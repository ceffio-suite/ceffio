// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/version"
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

	// ISSUER AND RENEWAL, which the expiry date alone does not tell.
	//
	// "88 days left" is reassuring and says nothing about the automation: a
	// certificate that will expire and never renew looks exactly like a healthy one
	// until the day it stops. Renews is when cert-manager PLANS to act, and its
	// absence is itself a finding.
	Issuer                   string `json:"issuer,omitempty"`
	Renews                   string `json:"renews,omitempty"`
	JoursAvantRenouvellement int    `json:"jours_avant_renouvellement"`
}

// registryNamespaces lists every namespace the registry declares, in
// module order, deduplicated.
//
// WHY the registry and not a hand-written list: the previous list
// ("data, identity, files, office, video, system") predated the mail, vault
// and exapps modules — their pods were simply invisible on the status page.
// Every module declares its Namespaces in Info(); walking the registry
// makes an omission impossible for any future module.
func registryNamespaces() []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range moduleAll() {
		for _, ns := range m.Info().Namespaces {
			if !seen[ns] {
				seen[ns] = true
				out = append(out, ns)
			}
		}
	}
	return out
}

// registryServices builds the catalogue of public exposures from the
// registry, replacing the old hand-written catalogueServices table: each
// module declares its Services (subdomain, role, SSO, pod prefixes) and the
// status page only assembles them. SSO comes straight from
// module.Service.SSO — the same flag ServicePublic already exposed.
func registryServices() []module.Service {
	var out []module.Service
	for _, m := range moduleAll() {
		out = append(out, m.Info().Services...)
	}
	return out
}

// handleStatus returns the full state of the platform.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespaces := registryNamespaces()

	// 1. All declared-namespace pods at once (one API request per namespace).
	podsParNS := map[string][]Pod{}
	for _, ns := range namespaces {
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

	// 2. Layers (internal diagnostic view): one row per declared namespace.
	var stack []Layer
	for _, ns := range namespaces {
		ly := Layer{Name: ns}
		for _, p := range podsParNS[ns] {
			ly.Total++
			if p.Ready {
				ly.Ready++
			}
			ly.Pods = append(ly.Pods, p)
		}
		stack = append(stack, ly)
	}

	// 3. Public services: real state computed from the pods carrying them.
	// The catalogue comes from the registry (module.Service), NOT from a
	// table maintained here — SSO included, which ServicePublic already
	// exposed and module.Service now carries.
	var services []ServicePublic
	for _, c := range registryServices() {
		svc := ServicePublic{
			Nom:       c.Name,
			Hote:      c.Sub + "." + s.Domain,
			Role:      c.Role,
			URL:       "https://" + c.Sub + "." + s.Domain,
			Technique: c.Technical,
			SSO:       c.SSO,
			Sante:     "unknown",
		}
		// Pod prefixes are matched in EVERY declared namespace: the old
		// code scanned a hard-coded subset of five namespaces, which is
		// how mail/vault/exapps pods ended up invisible.
		for _, ns := range namespaces {
			for _, p := range podsParNS[ns] {
				if !porteService(p.Name, c.PodPrefixes) {
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

		// THE VERSION OF THE RUNNING BINARY, and the reason it belongs here:
		// an operator updating a console has no other way to know WHICH build
		// answered. The version is injected at compile time by the release
		// workflow (`-X internal/version.Binary`), so it is empty on a local
		// build — hence the fallback below rather than a bare value.
		"version": versionCourante(),
		"commit":  version.Commit,
		"built":   version.Date,
	})
}

// versionCourante renvoie la version à afficher pour le binaire en cours.
//
// WHY NOT version.Binary DIRECTLY: on a local build the variable keeps its
// default "0.0.0-dev", which tells an operator nothing about WHAT is running.
// ImageTag() already solves that problem for the container image — it identifies
// a development build by the hash of its own content. Reusing it here means the
// console shows the SAME identifier the deployed image carries, so the two
// answers cannot disagree when someone cross-checks them from the cluster.
func versionCourante() string {
	if version.Binary != "" && version.Binary != "0.0.0-dev" {
		return version.Binary
	}
	// ImageTag() already prefixes a development build with "dev-" (the first
	// characters of the binary's hash). Repeating the word here would print
	// "dev (dev-05d49fa4)" — a duplication that reads like two different
	// identifiers rather than one.
	return version.ImageTag()
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
	// Guard: the fake clientset used in tests exposes a Discovery with no
	// REST client — dereferencing nil here would panic the whole status
	// response for a section (certificates) that is merely unavailable.
	rc := s.kube.Discovery().RESTClient()
	if rc == nil {
		return out
	}
	list, err := rc.Get().AbsPath("/apis/cert-manager.io/v1", "certificates").DoRaw(ctx)
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
				DNSNames  []string `json:"dnsNames"`
				IssuerRef struct {
					Name string `json:"name"`
				} `json:"issuerRef"`
			} `json:"spec"`
			Status struct {
				NotAfter    string `json:"notAfter"`
				RenewalTime string `json:"renewalTime"`
				Conditions  []struct {
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
			Name:                     it.Metadata.Name,
			NS:                       it.Metadata.Namespace,
			Jours:                    -1,
			JoursAvantRenouvellement: -1,
			Issuer:                   it.Spec.IssuerRef.Name,
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
		if it.Status.RenewalTime != "" {
			c.Renews = it.Status.RenewalTime
			if t, err := time.Parse(time.RFC3339, it.Status.RenewalTime); err == nil {
				c.JoursAvantRenouvellement = int(time.Until(t).Hours() / 24)
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}
