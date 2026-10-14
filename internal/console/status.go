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

// Representation of the stack for the console.
//
// Design choice: the console shows what an ADMINISTRATOR wants to see —
// the PUBLIC services (with their role and real state), not the internal
// topology (namespaces, pods). Pods remain available in expandable detail
// for diagnosis, but are no longer the main view.

// ServicePublic describes an endpoint exposed via ingress.
type ServicePublic struct {
	Nom       string `json:"nom"`       // readable name ("Nextcloud")
	Hote      string `json:"hote"`      // cloud.ceffio.example.com
	Role      string `json:"role"`      // role in one sentence
	URL       string `json:"url"`       // https://…
	Technique bool   `json:"technique"` // true = not a direct user service (office)
	SSO       bool   `json:"sso"`       // authenticated via Keycloak
	PodsReady int    `json:"podsReady"`
	PodsTotal int    `json:"podsTotal"`
	Sante     string `json:"sante"` // "ok" | "ko" | "unknown"
	Pods      []Pod  `json:"pods"`
}

// Layer describes the state of an internal stack layer (diagnostic view).
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
	NotAfter  string `json:"notAfter"` // RFC3339 (empty if unknown)
	Jours     int    `json:"jours"`    // days before expiry (-1 if unknown)
	Hote      string `json:"hote"`     // covered domain (deduced from the name)
}

// catalogueServices: role of each public exposure. A single source of
// truth — the console and any future doc read the same table.
//
// office is marked "technical": nobody uses it directly, but the BROWSER
// loads the ONLYOFFICE editor from it when a document is opened in Nextcloud
// (DocumentServerUrl). Removing it from the exposure would break document
// editing — so it stays public, but is no longer presented as a user service.
var catalogueServices = []struct {
	sub       string
	nom       string
	role      string
	technique bool
	sso       bool
	pods      []string // prefixes of pods that carry the service
}{
	{"cloud", "Nextcloud", "Files, sharing and collaboration", false, true,
		[]string{"nextcloud"}},
	{"talk", "Nextcloud Talk", "Messaging and video conferencing (built into Nextcloud)", false, true,
		[]string{"nextcloud"}},
	{"keycloak", "Keycloak", "Single sign-on (SSO) for all apps", false, false,
		[]string{"keycloak"}},
	{"office", "ONLYOFFICE", "Editing engine for Nextcloud documents — loaded by the browser, no useful direct access", true, false,
		[]string{"onlyoffice"}},
	{"admin", "Ceffio console", "This administration console", true, false,
		[]string{"ceffio-admin"}},
	{"spreed", "Talk — media server", "Video transport for meetings (Janus + signaling)", true, false,
		[]string{"janus", "talk-signaling", "coturn", "nats"}},
}

// handleStatus returns the full state of the platform.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. All ceffio-* pods at once (one API request per namespace).
	podsParNS := map[string][]Pod{}
	for _, l := range []string{"data", "identity", "files", "office", "video", "system"} {
		ns := "ceffio-" + l
		pl, err := s.kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, p := range pl.Items {
			// Ignore terminating pods (they skew the totals).
			if p.DeletionTimestamp != nil {
				continue
			}
			// A Succeeded pod (finished job) is not "not ready".
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

	// 2. Layers (internal diagnostic view).
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

	// 3. Public services: real state computed from the pods carrying them.
	var services []ServicePublic
	for _, c := range catalogueServices {
		svc := ServicePublic{
			Nom:       c.nom,
			Hote:      c.sub + "." + s.Domain,
			Role:      c.role,
			URL:       "https://" + c.sub + "." + s.Domain,
			Technique: c.technique,
			SSO:       c.sso,
			Sante:     "unknown",
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
	// User services first, technical ones next, stable order.
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

	// 5. Certificates (with expiry).
	certs := s.listCerts(ctx)

	// 6. Numeric summary for the dashboard header.
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

// porteService says whether a pod (by its name) carries one of the given prefixes.
// k8s pod names are "<deploy>-<rs>-<hash>": we compare the prefix.
func porteService(podNom string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(podNom, p+"-") {
			return true
		}
	}
	return false
}

// ageHumain formats a duration in short readable text.
func ageHumain(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "a few s"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + " min"
	case d < 48*time.Hour:
		return itoa(int(d.Hours())) + " h"
	default:
		return itoa(int(d.Hours()/24)) + " d"
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

// listCerts reads cert-manager Certificates (untyped API): Ready status
// AND expiry date — a certificate about to expire is an announced outage,
// the console must show it before it happens.
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
