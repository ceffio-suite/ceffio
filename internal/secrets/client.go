package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// client encapsule les appels HTTP à OpenBao.
//
// On parle directement à l'API HTTP plutôt que d'embarquer le SDK : le besoin
// est réduit (lire et écrire un KV), et une dépendance de plus dans un produit
// qu'on veut auto-portant se paie à chaque mise à jour de sécurité.
type client struct {
	cfg  *Coffre
	http *http.Client
}

func nouveauClient(cfg *Coffre) *client {
	return &client{
		cfg: cfg,
		// Un délai court : si le coffre ne répond pas vite, on veut se rabattre
		// sur Kubernetes plutôt que de bloquer le déploiement.
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// entetes pose les entêtes communs à tous les appels.
func (c *client) entetes(req *http.Request) {
	req.Header.Set("X-Vault-Token", c.cfg.Jeton)
	// Le namespace se pose en entête, pas dans le chemin. Un jeton valide qui
	// ne voit pas le moteur attendu vient presque toujours de là.
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
}

// LireEntree rend TOUTES les clés d'une entrée du coffre.
//
// POURQUOI PAR ENTRÉE ET NON PAR CLÉ : la première version lisait une clé par
// chemin (« ceffio/nextcloud/password »). Un coffre rangé ainsi ne se parcourt
// pas — on y trouve « un mot de passe » sans savoir à quoi il ouvre, et chercher
// un compte ne donne rien. Une entrée par COMPTE porte ses clés ensemble, et se
// lit d'un coup d'œil.
//
// La lecture se fait sur le chemin `data/` (KV versionné) : c'est celui qui
// porte les VALEURS, alors que `metadata/` ne sert qu'à lister. Confondre les
// deux donne `data: null` et fait croire à une entrée vide.
func (c *client) LireEntree(ctx context.Context, composant, nom string) (map[string]string, error) {
	chemin := fmt.Sprintf("%s/v1/%s/data/%s",
		strings.TrimRight(c.cfg.Adresse, "/"), c.cfg.Moteur,
		c.cfg.Chemin(composant, nom))

	req, err := http.NewRequestWithContext(ctx, "GET", chemin, nil)
	if err != nil {
		return nil, err
	}
	c.entetes(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	brut, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("entrée absente du coffre : %s", c.cfg.Chemin(composant, nom))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("coffre a refusé (HTTP %d) : %.150s",
			resp.StatusCode, string(brut))
	}

	// Forme de la réponse KV v2 :
	// {"data":{"data":{"<clé>":"<valeur>"},"metadata":{...}}}
	var corps struct {
		Data struct {
			Data map[string]string `json:"data"`
			Meta struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(brut, &corps); err != nil {
		return nil, fmt.Errorf("réponse illisible du coffre : %w", err)
	}
	if len(corps.Data.Data) == 0 {
		return nil, fmt.Errorf("entrée vide dans le coffre : %s", c.cfg.Chemin(composant, nom))
	}
	return corps.Data.Data, nil
}

// Ecrire pose une valeur dans le coffre.
//
// Idempotent au sens utile : réécrire la même valeur crée une nouvelle version,
// ce qui est le comportement voulu — l'historique est conservé, et un secret
// écrasé par erreur reste récupérable.
func (c *client) EcrireEntree(ctx context.Context, composant, nom string, donnees map[string]string) error {
	chemin := fmt.Sprintf("%s/v1/%s/data/%s",
		strings.TrimRight(c.cfg.Adresse, "/"), c.cfg.Moteur,
		c.cfg.Chemin(composant, nom))

	poids, err := json.Marshal(map[string]any{"data": donnees})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", chemin, strings.NewReader(string(poids)))
	if err != nil {
		return err
	}
	c.entetes(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		brut, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("écriture refusée (HTTP %d) : %.150s",
			resp.StatusCode, string(brut))
	}
	return nil
}

// Lister rend les clés d'un préfixe. Sert au diagnostic (quels secrets sont
// dans le coffre), jamais au fonctionnement : un composant lit ce qu'il
// connaît, il n'explore pas.
//
// POURQUOI `metadata/` ET PAS LE CHEMIN DES VALEURS : sur un KV versionné,
// lister le chemin des valeurs échoue avec « Invalid path for a versioned K/V
// secrets engine ». C'est le chemin metadata qui liste.
func (c *client) Lister(ctx context.Context, composant string) ([]string, error) {
	chemin := fmt.Sprintf("%s/v1/%s/metadata/%s?list=true",
		strings.TrimRight(c.cfg.Adresse, "/"), c.cfg.Moteur,
		c.cfg.Chemin(composant, ""))

	req, err := http.NewRequestWithContext(ctx, "GET", chemin, nil)
	if err != nil {
		return nil, err
	}
	c.entetes(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	brut, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listage refusé (HTTP %d)", resp.StatusCode)
	}

	var corps struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(brut, &corps); err != nil {
		return nil, err
	}
	return corps.Data.Keys, nil
}

// ---------------------------------------------------------------------------
// Accès avec repli
// ---------------------------------------------------------------------------

// LireOuSecret rend un secret depuis le coffre s'il est configuré, sinon depuis
// le Secret Kubernetes.
//
// C'EST LE CŒUR DE LA RÈGLE « OpenBao OPTIONNEL » : l'appelant demande une
// valeur, sans savoir d'où elle vient. Si le coffre est absent ou injoignable,
// on se rabat sur Kubernetes avec un avertissement — jamais une erreur fatale.
// Un déploiement qui échoue parce qu'un coffre facultatif est en panne serait
// une régression, pas une sécurité.
//
// Ordre de priorité : coffre d'abord (c'est la source de vérité quand il est
// là), Kubernetes en repli. C'est ce qui permet de faire tourner un secret en
// l'écrivant dans le coffre, sans toucher au cluster.
func LireOuSecret(ctx context.Context, cfg *Coffre, composant, nom, cle, nsSecret, cleSecret string) (string, error) {
	if cfg.Dispo() {
		c := nouveauClient(cfg)
		entree, err := c.LireEntree(ctx, composant, nom)
		if err == nil {
			if v, ok := entree[cle]; ok && v != "" {
				return v, nil
			}
			// L'ENTRÉE EXISTE MAIS LA CLÉ MANQUE : on le dit, puis on se rabat.
			// Ce n'est pas la même chose qu'une entrée absente — confondre les
			// deux ferait passer un coffre incomplet pour un coffre vide, et la
			// cause disparaîtrait du compte rendu.
			fmt.Printf("  ∙ coffre : clé « %s » absente dans %s — repli sur le Secret Kubernetes\n",
				cle, cfg.Chemin(composant, nom))
		} else {
			// Un coffre configuré mais injoignable n'est pas une panne du
			// déploiement : on prévient et on continue.
			fmt.Printf("  ∙ coffre injoignable pour %s (%v) — repli sur le Secret Kubernetes\n",
				cfg.Chemin(composant, nom), err)
		}
	}
	return lireSecretK8s(ctx, nsSecret, cleSecret)
}

// EcrireDansCoffre pose un secret dans le coffre, si configuré.
//
// Si aucun coffre n'est configuré, on ne fait RIEN et on le dit : le secret
// reste dans Kubernetes, et c'est le comportement nominal d'une installation sans
// OpenBao.
func EcrireDansCoffre(ctx context.Context, cfg *Coffre, composant, nom string, donnees map[string]string) error {
	if !cfg.Dispo() {
		return nil
	}
	c := nouveauClient(cfg)
	if err := c.EcrireEntree(ctx, composant, nom, donnees); err != nil {
		return fmt.Errorf("écriture dans le coffre impossible (%s/%s) : %w",
			composant, nom, err)
	}
	// On n'affiche JAMAIS les valeurs — seulement le chemin et le nombre de clés.
	fmt.Printf("  ∙ coffre : %s écrit (%d clé(s))\n", cfg.Chemin(composant, nom), len(donnees))
	return nil
}

// lireSecretK8s lit un secret depuis un Secret Kubernetes (repli).
func lireSecretK8s(ctx context.Context, ns, cle string) (string, error) {
	out, err := kubeGet(ctx, "get", "secret", ns, "-o",
		fmt.Sprintf("jsonpath={.data.%s}", cle))
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("secret %s/%s introuvable", ns, cle)
	}
	return decoderBase64(out)
}

// kubeGet exécute kubectl et rend la sortie.
func kubeGet(ctx context.Context, args ...string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", args...)
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// decoderBase64 décode une valeur de Secret Kubernetes.
//
// Kubernetes stocke les valeurs en base64 : on décode ici, une seule fois, au
// lieu de laisser chaque appelant le faire — c'est la source classique d'un
// mot de passe qui « ne marche pas » parce qu'il est comparé encodé.
func decoderBase64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("valeur base64 illisible : %w", err)
	}
	return string(b), nil
}
