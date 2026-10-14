package console

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Représentation de la pile pour la console.
//
// Choix de conception : la console montre ce qu'un ADMINISTREUR veut voir —
// les SERVICES publics (avec leur rôle et leur état réel), pas la topologie
// interne (namespaces, pods). Les pods restent disponibles en détail dépliable
// pour le diagnostic, mais ne sont plus la vue principale.

// ServicePublic décrit un endpoint exposé via ingress.
type ServicePublic struct {
	Nom       string `json:"nom"`       // nom lisible ("Nextcloud")
	Hote      string `json:"hote"`      // cloud.ceffio.example.com
	Role      string `json:"role"`      // rôle en une phrase
	URL       string `json:"url"`       // https://…
	Technique bool   `json:"technique"` // true = pas un service utilisateur direct (office)
	SSO       bool   `json:"sso"`       // authentifié via Keycloak
	PodsReady int    `json:"podsReady"`
	PodsTotal int    `json:"podsTotal"`
	Sante     string `json:"sante"` // "ok" | "ko" | "inconnue"
	Pods      []Pod  `json:"pods"`
}

// Layer décrit l'état d'une couche interne de la pile (vue diagnostic).
type Layer struct {
	Name  string `json:"name"`
	Ready int    `json:"ready"`
	Total int    `json:"total"`
	Pods  []Pod  `json:"pods"`
}

type Pod struct {
	Name     string `json:"name"`
	Ready    bool   `json:"ready"`
	Restarts int    `json:"restarts"`
	Age      string `json:"age"`
}

type IngressInfo struct {
	Name string `json:"name"`
	Host string `json:"host"`
	NS   string `json:"ns"`
}

type CertInfo struct {
	Name      string `json:"name"`
	NS        string `json:"ns"`
	Condition string `json:"condition"`
	NotAfter  string `json:"notAfter"` // RFC3339 (vide si inconnu)
	Jours     int    `json:"jours"`    // jours avant expiration (-1 si inconnu)
	Hote      string `json:"hote"`     // domaine couvert (déduit du nom)
}

// catalogueServices : rôle de chaque exposition publique. Une seule source de
// vérité — la console et toute doc future lisent la même table.
//
// office est marqué « technique » : personne ne l'utilise directement, mais le
// NAVIGATEUR y charge l'éditeur ONLYOFFICE quand on ouvre un document dans
// Nextcloud (DocumentServerUrl). La retirer de l'exposition casserait
// l'édition de documents — elle reste donc publique, mais n'est plus présentée
// comme un service utilisateur.
var catalogueServices = []struct {
	sub       string
	nom       string
	role      string
	technique bool
	sso       bool
	pods      []string // préfixes de pods qui portent le service
}{
	{"cloud", "Nextcloud", "Fichiers, partage et collaboration", false, true,
		[]string{"nextcloud"}},
	{"talk", "Nextcloud Talk", "Messagerie et visioconférence (intégré à Nextcloud)", false, true,
		[]string{"nextcloud"}},
	{"keycloak", "Keycloak", "Authentification unique (SSO) de toutes les apps", false, false,
		[]string{"keycloak"}},
	{"office", "ONLYOFFICE", "Moteur d'édition des documents Nextcloud — chargé par le navigateur, pas d'accès direct utile", true, false,
		[]string{"onlyoffice"}},
	{"admin", "Console Ceffio", "Cette console d'administration", true, false,
		[]string{"ceffio-admin"}},
	{"spreed", "Talk — serveur de médias", "Transport vidéo des réunions (Janus + signaling)", true, false,
		[]string{"janus", "talk-signaling", "coturn", "nats"}},
}

// handleStatus renvoie l'état complet de la plateforme.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Tous les pods ceffio-* d'un coup (une seule requête API par namespace).
	podsParNS := map[string][]Pod{}
	for _, l := range []string{"data", "identity", "files", "office", "video", "system"} {
		ns := "ceffio-" + l
		pl, err := s.kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, p := range pl.Items {
			// Ignorer les pods en terminaison (ils faussent les totaux).
			if p.DeletionTimestamp != nil {
				continue
			}
			// Un pod Succeeded (job terminé) n'est pas « non prêt ».
			if p.Status.Phase == "Succeeded" {
				continue
			}
			ready := true
			restarts := 0
			for _, cs := range p.Status.ContainerStatuses {
				if !cs.Ready {
					ready = false
				}
				restarts += int(cs.RestartCount)
			}
			if len(p.Status.ContainerStatuses) == 0 {
				ready = false
			}
			podsParNS[ns] = append(podsParNS[ns], Pod{
				Name:     p.Name,
				Ready:    ready,
				Restarts: restarts,
				Age:      ageHumain(time.Since(p.CreationTimestamp.Time)),
			})
		}
	}

	// 2. Couches (vue diagnostic interne).
	var stack []Layer
	for _, l := range []string{"data", "identity", "files", "office", "video", "system"} {
		ly := Layer{Name: l}
		for _, p := range podsParNS["ceffio-"+l] {
			ly.Total++
			if p.Ready {
				ly.Ready++
			}
			ly.Pods = append(ly.Pods, p)
		}
		stack = append(stack, ly)
	}

	// 3. Services publics : état réel calculé depuis les pods qui les portent.
	var services []ServicePublic
	for _, c := range catalogueServices {
		svc := ServicePublic{
			Nom:       c.nom,
			Hote:      c.sub + "." + s.Domain,
			Role:      c.role,
			URL:       "https://" + c.sub + "." + s.Domain,
			Technique: c.technique,
			SSO:       c.sso,
			Sante:     "inconnue",
		}
		for _, ns := range []string{"ceffio-files", "ceffio-identity", "ceffio-office", "ceffio-video", "ceffio-system"} {
			for _, p := range podsParNS[ns] {
				if !porteService(p.Name, c.pods) {
					continue
				}
				svc.PodsTotal++
				if p.Ready {
					svc.PodsReady++
				}
				svc.Pods = append(svc.Pods, p)
			}
		}
		if svc.PodsTotal > 0 && svc.PodsReady == svc.PodsTotal {
			svc.Sante = "ok"
		} else if svc.PodsTotal > 0 {
			svc.Sante = "ko"
		}
		services = append(services, svc)
	}
	// Les services utilisateurs d'abord, techniques ensuite, ordre stable.
	sort.SliceStable(services, func(i, j int) bool {
		if services[i].Technique != services[j].Technique {
			return !services[i].Technique
		}
		return services[i].Nom < services[j].Nom
	})

	// 4. Ingress.
	var ing []IngressInfo
	il, err := s.kube.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, i := range il.Items {
			for _, ru := range i.Spec.Rules {
				if ru.Host != "" {
					ing = append(ing, IngressInfo{Name: i.Name, NS: i.Namespace, Host: ru.Host})
				}
			}
		}
		sort.Slice(ing, func(a, b int) bool { return ing[a].Host < ing[b].Host })
	}

	// 5. Certificats (avec expiration).
	certs := s.listCerts(ctx)

	// 6. Synthèse chiffrée pour l'en-tête du dashboard.
	podsReady, podsTotal := 0, 0
	for _, ps := range podsParNS {
		for _, p := range ps {
			podsTotal++
			if p.Ready {
				podsReady++
			}
		}
	}
	certsOK := 0
	for _, c := range certs {
		if c.Condition == "True" {
			certsOK++
		}
	}

	writeJSON(w, 200, map[string]any{
		"domain":    s.Domain,
		"stack":     stack,
		"services":  services,
		"ingress":   ing,
		"certs":     certs,
		"podsReady": podsReady,
		"podsTotal": podsTotal,
		"certsOK":   certsOK,
		"certsN":    len(certs),
		"serveur":   time.Now().Format(time.RFC3339),
	})
}

// porteService dit si un pod (par son nom) porte l'un des préfixes donnés.
// Les noms de pods k8s sont « <deploy>-<rs>-<hash> » : on compare le préfixe.
func porteService(podNom string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(podNom, p+"-") {
			return true
		}
	}
	return false
}

// ageHumain formate une durée en texte court lisible.
func ageHumain(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "quelques s"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + " min"
	case d < 48*time.Hour:
		return itoa(int(d.Hours())) + " h"
	default:
		return itoa(int(d.Hours()/24)) + " j"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b strings.Builder
	if n < 0 {
		b.WriteByte('-')
		n = -n
	}
	var chiffres []byte
	for n > 0 {
		chiffres = append([]byte{byte('0' + n%10)}, chiffres...)
		n /= 10
	}
	b.Write(chiffres)
	return b.String()
}

// listCerts lit les Certificate cert-manager (API non typée) : statut Ready
// ET date d'expiration — un certificat qui va expirer est une panne annoncée,
// la console doit le montrer avant.
func (s *Server) listCerts(ctx context.Context) []CertInfo {
	out := []CertInfo{}
	list, err := s.kube.Discovery().RESTClient().Get().AbsPath("/apis/cert-manager.io/v1", "certificates").DoRaw(ctx)
	if err != nil {
		return out
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				DNSNames []string `json:"dnsNames"`
			} `json:"spec"`
			Status struct {
				NotAfter   string `json:"notAfter"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(list, &doc); err != nil {
		return out
	}
	for _, it := range doc.Items {
		c := CertInfo{
			Name:  it.Metadata.Name,
			NS:    it.Metadata.Namespace,
			Jours: -1,
		}
		for _, cond := range it.Status.Conditions {
			if cond.Type == "Ready" {
				c.Condition = cond.Status
			}
		}
		if len(it.Spec.DNSNames) > 0 {
			c.Hote = it.Spec.DNSNames[0]
		}
		if it.Status.NotAfter != "" {
			c.NotAfter = it.Status.NotAfter
			if t, err := time.Parse(time.RFC3339, it.Status.NotAfter); err == nil {
				c.Jours = int(time.Until(t).Hours() / 24)
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}
