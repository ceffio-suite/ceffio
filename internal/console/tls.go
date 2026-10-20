// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package console — the TLS page: ACME challenge, DNS provider, certificates.
//
// WHY A PAGE AND NOT AN INSTALL FLAG: which challenge proves the ownership of
// the domain is an OPERATIONS setting, not a deployment one. It changes the day
// the operator moves their DNS, or the day they decide a wildcard is worth a
// provider token. Freezing it in the deployment would force a reinstall to
// change an address — and the argument that made the challenge parametrable in
// the first place would be lost behind a rebuild.
//
// THE SHAPE OF THE PAGE, AND WHY IT IS THIS ONE:
//
//	the CHALLENGE and the PROVIDER are read from the running configuration,
//	not typed in here: they come from the environment of the console pod, and
//	a value written twice is a value that diverges. The page SHOWS what is
//	active, so an operator never has to guess which path is in use.
//
//	the API TOKEN is the only thing this page writes, and it goes to OpenBao.
//	It is never read back to the browser: the page learns whether a credential
//	exists, never its value. Cert-manager's solver reads it through the
//	injector, so the console does not need any right in cert-manager — the
//	RBAC non-regression test would refuse that widening anyway.
//
//	the CERTIFICATES are observed, not computed: their state is cert-manager's
//	answer, which is the only authority on whether a challenge completed.
package console

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// nsCertManager mirrors the constant of internal/ingress: the namespace the
// certificates and the DNS solver live in.
//
// WHY DUPLICATED AND NOT IMPORTED: the console must not import the ingress
// layer, which would drag the whole deployment code into the administrative
// binary. The value is pinned by a test instead (see tls_test.go), so a change
// on one side fails the build rather than diverging in silence.
const nsCertManager = "cert-manager"

// EtatTLS is what the page displays.
//
// It deliberately carries the CHALLENGE AND THE PROVIDER as data rather than
// letting the page infer them: the page must be able to say "you are on HTTP-01,
// which cannot issue a wildcard" without recomputing anything.
type EtatTLS struct {
	// Challenge actif : "http01" ou "dns01".
	Challenge string `json:"challenge"`
	// Provider DNS (dns01 seulement), vide sinon.
	Provider string `json:"provider,omitempty"`
	// Zone mise à jour par le challenge.
	Zone string `json:"zone,omitempty"`
	// WebhookGroup : l'identité du solver (dns01 seulement).
	WebhookGroup string `json:"webhook_group,omitempty"`

	// IdentifiantDefini dit si une clé est stockée dans le coffre. LA VALEUR
	// N'EST JAMAIS RENVOYÉE : même règle que le mot de passe SMTP.
	IdentifiantDefini bool `json:"identifiant_defini"`

	// Le solver est-il déployé et disponible ?
	SolverDeploye bool `json:"solver_deploye"`

	// Certificats observés.
	Certificats []CertificatTLS `json:"certificats"`
}

// CertificatTLS is one certificate as cert-manager reports it.
type CertificatTLS struct {
	Nom       string   `json:"nom"`
	Namespace string   `json:"namespace"`
	Ready     bool     `json:"ready"`
	Raison    string   `json:"raison,omitempty"`
	Noms      []string `json:"noms,omitempty"`
	Expire    string   `json:"expire,omitempty"`
	// Jours : days left before expiry, -1 when unknown. A certificate about to
	// expire is an announced outage — that is why the console shows it BEFORE
	// it happens rather than after.
	Jours int `json:"jours"`
}

// handleTLS lit ou écrit la configuration TLS.
//
//	GET  /api/certificates → the state (challenge, provider, certificates)
//
// THE POST IS GONE, and it had to be: it wrote the DNS credential to
// kv/data/ceffio/tls/dns-provider, which is now the ingress module's settings. Two
// writers for one entry is a source of drift — the module reads back what it last
// wrote and would overwrite, with its own view, an identifier changed through this
// route, or the reverse. The credential has exactly ONE path now: the module
// declares it, the console draws it, the CLI applies it.
//
// REMOVED RATHER THAN RESTRICTED, because a read-only route that keeps its POST
// has not fixed anything: it is the same defect with a comment saying it should
// not be used. What remains is what the Certificates tab needs — observing.
func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		// 405, not 404: the path exists and the method does not. An operator
		// who tries to write here must be told the route is read-only, not sent
		// looking for a typo in the URL.
		w.Header().Set("Allow", http.MethodGet)
		apiErr(w, http.StatusMethodNotAllowed,
			"this route is read-only: the DNS credential is written through the "+
				"ingress module's settings (Settings → ingress → tls), which is the "+
				"single path to the vault entry")
		return
	}
	etat, err := s.etatTLS(r.Context())
	if err != nil {
		apiErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, etat)
}

// cheminCoffreDNS : le chemin OpenBao des identifiants DNS, en deux parties
// comme secrets.EcrireDansCoffre les attend (montage, chemin).
//
// IL DOIT CORRESPONDRE À CELUI DU SOLVER (internal/ingress/dnswebhook.go,
// cheminBaoIdentifiantsDNS = "kv/data/ceffio/tls/dns-provider"). L'écart entre
// les deux ne produirait aucune erreur : le pod du solver démarrerait avec un
// fichier vide, et chaque challenge échouerait sur une authentification. Un
// test les compare.
var cheminCoffreDNS = [2]string{"ceffio", "tls/dns-provider"}

// etatTLS observe la configuration et les certificats.
func (s *Server) etatTLS(ctx context.Context) (*EtatTLS, error) {
	etat := &EtatTLS{Challenge: string(s.acme.Challenge)}

	// Le challenge et le provider viennent de la configuration RÉSOLUE du
	// pod : la page ne les devine pas et ne les réécrit pas.
	if s.acme.DNS01() {
		etat.Provider = string(s.acme.Provider)
		etat.Zone = s.acme.Zone
		etat.WebhookGroup = s.acme.WebhookGroup
	}

	// L'identifiant est-il présent ? On lit l'entrée et on ne garde QUE ce
	// fait : la valeur ne quitte pas le serveur.
	if entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(),
		cheminCoffreDNS[0], cheminCoffreDNS[1]); err == nil && len(entree) > 0 {
		// Une entrée avec seulement le nom du provider n'est PAS un
		// identifiant : elle dirait « configuré » alors qu'aucun jeton n'est
		// utilisable, et l'opérateur chercherait l'erreur côté DNS.
		for k := range entree {
			if k != "provider" {
				etat.IdentifiantDefini = true
				break
			}
		}
	}

	if s.kube != nil {
		etat.SolverDeploye = s.solverDNSDeploye(ctx)
		etat.Certificats = s.certificats(ctx)
	}
	return etat, nil
}

// solverDNSDeploye dit si le pod du solver est en service.
//
// WHY IT MATTERS TO THE PAGE: with dns01 configured and no solver, every
// certificate stays Pending. Showing the challenge as active without saying the
// solver is missing would send the operator looking at their DNS provider for a
// problem that is in the cluster.
func (s *Server) solverDNSDeploye(ctx context.Context) bool {
	if !s.acme.DNS01() {
		return false
	}
	pods, err := s.kube.CoreV1().Pods(nsCertManager).List(ctx,
		metav1.ListOptions{LabelSelector: "app=ceffio-acme-dns-webhook"})
	if err != nil {
		return false
	}
	for _, p := range pods.Items {
		for _, c := range p.Status.ContainerStatuses {
			if c.Ready {
				return true
			}
		}
	}
	return false
}

// certificats lit les Certificate de cert-manager et leur état.
//
// WHY THROUGH THE UNTYPED REST CLIENT, like listCerts in status.go: Certificate
// is a cert-manager CRD, absent from client-go's typed clients. The console
// already holds a cluster-wide READ grant on certificates (deploy.go), so this
// is an observation, not a new privilege — and the RBAC non-regression test
// pins that the grant did not change.
func (s *Server) certificats(ctx context.Context) []CertificatTLS {
	out := []CertificatTLS{}
	rc := s.kube.Discovery().RESTClient()
	if rc == nil {
		// Guard: the fake clientset used in tests exposes a Discovery with no
		// REST client — dereferencing nil would panic the whole page for a
		// section that is merely unavailable.
		return out
	}
	brut, err := rc.Get().AbsPath("/apis/cert-manager.io/v1", "certificates").DoRaw(ctx)
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
					Type    string `json:"type"`
					Status  string `json:"status"`
					Reason  string `json:"reason"`
					Message string `json:"message"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(brut, &doc); err != nil {
		return out
	}
	for _, it := range doc.Items {
		c := CertificatTLS{
			Nom:       it.Metadata.Name,
			Namespace: it.Metadata.Namespace,
			Noms:      it.Spec.DNSNames,
			Jours:     -1,
		}
		for _, cond := range it.Status.Conditions {
			if cond.Type != "Ready" {
				continue
			}
			c.Ready = cond.Status == "True"
			if !c.Ready {
				// Le message de cert-manager est souvent la seule indication
				// exploitable — « le challenge n'a pas abouti » sans dire
				// pourquoi oblige à fouiller les logs. On le garde tel quel,
				// tronqué, plutôt que de le résumer en perdant la cause.
				c.Raison = strings.TrimSpace(cond.Message)
				if c.Raison == "" {
					c.Raison = cond.Reason
				}
				if len(c.Raison) > 300 {
					c.Raison = c.Raison[:300] + "…"
				}
			}
		}
		if it.Status.NotAfter != "" {
			c.Expire = it.Status.NotAfter
			if t, err := time.Parse(time.RFC3339, it.Status.NotAfter); err == nil {
				c.Jours = int(time.Until(t).Hours() / 24)
			}
		}
		out = append(out, c)
	}
	return out
}
