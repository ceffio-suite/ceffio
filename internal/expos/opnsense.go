// Package expos publie une installation Ceffio derriere un pare-feu OPNsense.
//
// POURQUOI ce package existe : deployer Ceffio ne suffit pas a le rendre
// joignable. Dans l'infrastructure cible, le pare-feu (OPNsense) termine le TLS
// public et route vers la VM ; sans les domaines declares cote OPNsense, le DNS
// repond mais rien n'arrive au cluster. C'etait une etape manuelle — elle est
// desormais dans le CLI, parce qu'un deploiement qui laisse une etape manuelle
// n'est pas reproductible.
//
// Sequence complete d'une publication :
//  1. le DNS publique existe (cree par l'utilisateur : *.ceffio.mandem-it.com) ;
//  2. le certificat wildcard existe cote OPNsense (cree par l'utilisateur) ;
//  3. les domaines + handlers sont declares dans os-caddy  <- ce package ;
//  4. les hotes publics sont ajoutes aux Ingress Traefik <- internal/ingress.
//
// L'authentification se fait par cle API OPNsense, lue depuis un fichier
// (jamais en dur, jamais dans Git).
package expos

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config décrit comment joindre le pare-feu et quoi publier.
type Config struct {
	HoteAPI     string // ex. opn.datalock.mandem-it.com
	FichierCle  string // fichier contenant key= / secret=
	Domaine     string // domaine de base public, ex. ceffio.mandem-it.com
	IPInterne   string // cible : IP de la VM qui porte Traefik
	PortInterne string // ex. "80" (le TLS est termine cote pare-feu)
	// CertificatRef : refId du certificat wildcard cote OPNsense. Si vide, il
	// est cherche automatiquement par ses SAN.
	CertificatRef string
	SousDomaines  []string // ex. cloud, chat, matrix, keycloak, office, meet, admin
}

// Resultat rend compte de ce qui a été fait — et de ce qui existait déjà.
type Resultat struct {
	Certificat   string   `json:"certificat"`
	Creés        []string `json:"crees"`
	Existants    []string `json:"existants"`
	Applique     bool     `json:"applique"`
	Avertissemts []string `json:"avertissements,omitempty"`
}

// client minimal pour l'API OPNsense.
type client struct {
	hote string
	auth string
	http *http.Client
}

func newClient(cfg Config) (*client, error) {
	cle, err := lireCredential(cfg.FichierCle, "key")
	if err != nil {
		return nil, err
	}
	secret, err := lireCredential(cfg.FichierCle, "secret")
	if err != nil {
		return nil, err
	}
	// Le fichier peut utiliser « key= » ou « key: », avec espaces eventuels :
	// une extraction trop stricte retourne une chaine vide, et une cle vide ne
	// produit pas d'erreur — juste des reponses vides, tres couteuses a
	// diagnostiquer.
	if len(cle) < 20 || len(secret) < 20 {
		return nil, fmt.Errorf("identifiants OPNsense mal lus dans %s (key=%d car., secret=%d car.)",
			cfg.FichierCle, len(cle), len(secret))
	}
	return &client{
		hote: cfg.HoteAPI,
		auth: base64.StdEncoding.EncodeToString([]byte(cle + ":" + secret)),
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// Le pare-feu sert un certificat auto-signe : on ne peut pas
				// le valider sans embarquer sa CA.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}, nil
}

func lireCredential(fichier, nom string) (string, error) {
	b, err := os.ReadFile(fichier)
	if err != nil {
		return "", fmt.Errorf("lecture de %s : %w", fichier, err)
	}
	re := regexp.MustCompile(`(?im)^\s*` + nom + `\s*[:=]\s*(\S+)`)
	m := re.FindStringSubmatch(string(b))
	if m == nil {
		return "", fmt.Errorf("champ %q absent de %s", nom, fichier)
	}
	return strings.TrimSpace(m[1]), nil
}

func (c *client) appel(ctx context.Context, chemin, methode string, corps any) (string, error) {
	var body io.Reader
	if corps != nil {
		b, err := json.Marshal(corps)
		if err != nil {
			return "", err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, methode, "https://"+c.hote+"/api/"+chemin, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic "+c.auth)
	// Content-Type UNIQUEMENT s'il y a un corps : sur un GET, ce pare-feu
	// repond « Invalid JSON syntax » et l'erreur ressemble a une API morte.
	if corps != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

// Publier declare les domaines et leurs handlers, puis applique.
func Publier(ctx context.Context, cfg Config, progress func(string)) (*Resultat, error) {
	if progress == nil {
		progress = func(string) {}
	}
	res := &Resultat{}

	cli, err := newClient(cfg)
	if err != nil {
		return res, err
	}

	// 1. Verifier que le pare-feu repond — sur un point qui a TOUJOURS du
	//    contenu : une reponse vide sur tous les chemins signale un mauvais hote.
	out, err := cli.appel(ctx, "core/firmware/status", "GET", nil)
	if err != nil || len(out) < 10 {
		return res, fmt.Errorf("pare-feu injoignable sur %s (%v)", cfg.HoteAPI, err)
	}

	// 2. Trouver le certificat wildcard qui couvre le domaine.
	cert := cfg.CertificatRef
	if cert == "" {
		out, err := cli.appel(ctx, "acmeclient/certificates/search", "GET", nil)
		if err != nil {
			return res, fmt.Errorf("lecture des certificats : %w", err)
		}
		var d struct {
			Rows []struct {
				Name      string `json:"name"`
				AltNames  string `json:"altNames"`
				CertRefID string `json:"certRefId"`
			} `json:"rows"`
		}
		if json.Unmarshal([]byte(out), &d) != nil {
			return res, fmt.Errorf("reponse de certificats illisible")
		}
		for _, r := range d.Rows {
			if strings.Contains(r.AltNames, cfg.Domaine) {
				cert = r.CertRefID
				break
			}
		}
	}
	if cert == "" {
		return res, fmt.Errorf("aucun certificat couvrant %s cote pare-feu (creez-le d'abord)", cfg.Domaine)
	}
	res.Certificat = cert
	progress("certificat : " + cert)

	// 3. Lister les domaines deja declares, pour ne pas creer de doublon
	//    (un doublon FromDomain cree une entree conflictuelle).
	out, _ = cli.appel(ctx, "caddy/reverse_proxy/search_reverse_proxy", "GET", nil)
	existants := map[string]string{}
	var dr struct {
		Rows []struct {
			FromDomain string `json:"FromDomain"`
			UUID       string `json:"uuid"`
		} `json:"rows"`
	}
	if json.Unmarshal([]byte(out), &dr) == nil {
		for _, r := range dr.Rows {
			existants[r.FromDomain] = r.UUID
		}
	}
	progress(fmt.Sprintf("%d domaines déjà déclarés sur le pare-feu", len(existants)))

	// 4. Creer chaque domaine + son handler.
	for _, sub := range cfg.SousDomaines {
		hote := sub + "." + cfg.Domaine
		if _, ok := existants[hote]; ok {
			res.Existants = append(res.Existants, hote)
			continue
		}
		out, err := cli.appel(ctx, "caddy/reverse_proxy/add_reverse_proxy", "POST", map[string]any{
			"reverse": map[string]string{
				"enabled": "1", "FromDomain": hote, "CustomCertificate": cert,
				"DnsChallenge": "0", "DisableTls": "0",
				"description": "Ceffio - " + sub,
			},
		})
		if err != nil {
			return res, fmt.Errorf("création du domaine %s : %w", hote, err)
		}
		var rd struct {
			UUID string `json:"uuid"`
		}
		if json.Unmarshal([]byte(out), &rd) != nil || rd.UUID == "" {
			return res, fmt.Errorf("création du domaine %s refusée : %s", hote, tronque(out))
		}

		out, err = cli.appel(ctx, "caddy/reverse_proxy/add_handle", "POST", map[string]any{
			"handle": map[string]string{
				"enabled": "1", "reverse": rd.UUID, "HandleType": "handle",
				"HandleDirective": "reverse_proxy",
				"ToDomain":        cfg.IPInterne, "ToPort": cfg.PortInterne,
				// HttpTls "0" : la patte interne reste en HTTP, puisque le TLS
				// public est termine par le pare-feu. Evite toute question de
				// certificat auto-signe entre le pare-feu et la VM.
				"HttpTls": "0", "HttpTlsInsecureSkipVerify": "0",
			},
		})
		if err != nil {
			return res, fmt.Errorf("création du handler %s : %w", hote, err)
		}
		var rh struct {
			UUID string `json:"uuid"`
		}
		if json.Unmarshal([]byte(out), &rh) != nil || rh.UUID == "" {
			return res, fmt.Errorf("handler %s refusé : %s", hote, tronque(out))
		}
		progress("+ " + hote)
		res.Creés = append(res.Creés, hote)
	}

	// 5. Appliquer — sans le Content-Type, comme pour tout POST sans corps.
	if _, err := cli.appel(ctx, "caddy/service/reconfigure", "POST", nil); err != nil {
		return res, fmt.Errorf("application de la configuration : %w", err)
	}
	res.Applique = true
	progress("configuration appliquée")
	return res, nil
}

func tronque(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
