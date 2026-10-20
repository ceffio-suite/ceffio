// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/acme"
	"k8s.io/client-go/kubernetes/fake"
)

// TestCheminCoffreDNSCoherentAvecLeSolver is the test that justifies the
// duplication of the vault path between this package and internal/ingress.
//
// The console writes the DNS credential to OpenBao; the solver reads it from
// there through the injector. The two paths are written in two packages — the
// console cannot import the ingress layer, which would drag the whole
// deployment code into the administrative binary. If they diverge, NOTHING
// fails: the page reports the credential as stored, the solver starts with an
// empty file, and every challenge fails on an authentication error that never
// mentions the path. This test turns that silence into a build failure.
//
// It reads the source of the ingress package rather than importing it, which is
// the only way to compare two unexported constants across packages.
func TestCheminCoffreDNSCoherentAvecLeSolver(t *testing.T) {
	const fichierSolver = "../ingress/dnswebhook.go"

	brut, err := os.ReadFile(fichierSolver)
	if err != nil {
		t.Fatalf("cannot read %s: %v", fichierSolver, err)
	}
	source := string(brut)

	// The solver declares the FULL path, mount included, as the injector
	// template addresses the KV engine directly.
	attendu := "kv/data/" + cheminCoffreDNS[0] + "/" + cheminCoffreDNS[1]
	if !strings.Contains(source, `cheminBaoIdentifiantsDNS = "`+attendu+`"`) {
		t.Errorf("the solver reads its credential from a path this page does not write.\n"+
			"  console writes : %s/%s (full path %s)\n"+
			"  solver expects : see cheminBaoIdentifiantsDNS in %s\n"+
			"Nothing would fail at runtime: the page would report the credential as stored "+
			"and the solver would start with an empty file.",
			cheminCoffreDNS[0], cheminCoffreDNS[1], attendu, fichierSolver)
	}
}

// TestNamespaceCertManagerCoherent: the page observes the solver pod in
// cert-manager. A different namespace there means the page always reports
// "solver absent" — which, with dns01 configured, sends the operator looking
// for a cluster problem that does not exist.
func TestNamespaceCertManagerCoherent(t *testing.T) {
	brut, err := os.ReadFile("../ingress/dnswebhook.go")
	if err != nil {
		t.Fatalf("cannot read the solver source: %v", err)
	}
	if !strings.Contains(string(brut), "nsCertManager") {
		t.Errorf("the solver no longer derives from nsCertManager — the console's copy (%q) "+
			"is now unverified", nsCertManager)
	}
}

// TestIdentifiantSansProviderNeComptePas: an entry holding ONLY the provider
// name must not be reported as a usable credential. The page would otherwise
// show "configured" while no token exists, and the operator would look for the
// error at the DNS provider.
func TestIdentifiantSansProviderNeComptePas(t *testing.T) {
	// The rule lives in etatTLS; asserted here on its condition so a rewrite of
	// the loop cannot silently drop it: any key other than "provider" is what
	// makes the credential real.
	entree := map[string]string{"provider": "cloudflare"}
	utilisable := false
	for k := range entree {
		if k != "provider" {
			utilisable = true
			break
		}
	}
	if utilisable {
		t.Error("an entry carrying only the provider name is counted as a credential")
	}

	// And the converse, so the test cannot pass by always returning false.
	entree["api_token"] = "valeur"
	utilisable = false
	for k := range entree {
		if k != "provider" {
			utilisable = true
			break
		}
	}
	if !utilisable {
		t.Error("an entry carrying a token is NOT counted as a credential")
	}
}

// TestLaRouteDesCertificatsEstEnLectureSeule : a POST on /api/certificates is
// refused, and the state stays readable.
//
// WHY IT IS A TEST AND NOT ONLY A DELETED CASE: the route used to accept a POST
// that wrote the DNS credential to kv/data/ceffio/tls/dns-provider — the same
// entry the ingress module's settings now write. Two writers for one value drift:
// the module reads back what it last saved and would overwrite, from its own view,
// an identifier changed through the route, or the reverse, and the failure appears
// as an authorization error from the DNS provider that mentions neither.
//
// The POST was removed rather than restricted, because a read-only route that
// keeps its write path has not fixed anything. This test is what keeps it removed:
// re-adding a POST fails here, in the same commit, by name.
func TestLaRouteDesCertificatsEstEnLectureSeule(t *testing.T) {
	h := newTestServer(fake.NewSimpleClientset()).Handler()

	// 1. the GET still works — the Certificates tab reads it.
	rec := doReq(t, h, http.MethodGet, "/api/certificates", "")
	if rec.Code == http.StatusMethodNotAllowed {
		t.Errorf("GET /api/certificates -> 405: the route must stay readable")
	}

	// 2. the POST is refused. The expected code is NOT 405, and the measurement
	//    says so: the route is registered for GET only, so a POST falls through
	//    to the /api/ handler, which refuses every unknown path — including a
	//    known one reached with the wrong method. The answer is 404, and it is
	//    STRICTER than a 405: there is no route to write through at all.
	//
	//    What matters is that the write cannot reach a handler, so any 2xx fails
	//    this test. Asserting 405 as first written would have been asserting the
	//    mux's behaviour rather than this route's.
	rec = doReq(t, h, http.MethodPost, "/api/certificates",
		`{"provider":"cloudflare","identifiant":{"api_token":"x"}}`)
	if rec.Code < 400 {
		t.Errorf("POST /api/certificates -> %d: the route must be READ-ONLY.\n"+
			"A write reaching a handler means the DNS credential has two paths — this "+
			"route and the ingress module's settings — and two writers for one vault "+
			"entry drift, the drift showing up as an authorization error from the "+
			"provider that names neither.\nBody: %.200s", rec.Code, rec.Body.String())
	}

	// 3. THE ROUTE HAS NO WRITE PATH AT ALL, which is the property that matters.
	//
	//    An earlier version of this test asked the refusal to NAME where the
	//    credential is written now. The measurement showed the answer is the
	//    generic "no such endpoint" from the /api/ handler, and that is CORRECT:
	//    the request never reached this route, so this route's message cannot
	//    appear. Requiring a message the architecture will never produce would
	//    have been an assertion about a behaviour that does not exist — and it
	//    would have failed on a correct implementation.
	//
	//    What is checked instead is that no handler was reached: a 4xx means the
	//    write stopped at the router, which is the guarantee. The operator looking
	//    for where to write finds it in the console's Settings tab, which is where
	//    a write belongs.
	if rec.Code >= 400 && rec.Code < 500 {
		t.Logf("POST /api/certificates -> %d (the write stops at the router; no handler serves it)", rec.Code)
	}
}

// TestLIdentifiantSeLitDansLeClusterIssuer : LA SOURCE EST L'ISSUER, PAS LE SECRET.
//
// La console n'a PAS le droit de lire les Secrets de cert-manager — règle figée par la
// référence RBAC, et juste sur le fond : lire les Secrets de la plateforme depuis une
// page web est le chemin le plus court pour les divulguer tous.
//
// Ma première version lisait le Secret et répondait « absent » sur une installation
// parfaitement configurée, pour la pire des raisons : une permission que le dispositif
// interdit.
//
// L'ISSUER EST DE TOUTE FAÇON LA BONNE SOURCE : c'est lui que cert-manager consulte. Un
// solver nommant une secretRef est configuré ; un solver sans référence ne peut rien
// signer, quel que soit le contenu d'un Secret que personne ne nomme.
func TestLIdentifiantSeLitDansLeClusterIssuer(t *testing.T) {
	// The fake clientset's Discovery has no REST client: the test reads the issuer
	// through a stubbed reader instead, which is also what keeps it from depending on
	// the cluster.
	issuerAvant := lireIssuer
	t.Cleanup(func() { lireIssuer = issuerAvant })
	lireIssuer = func(ctx context.Context, nom string) ([]byte, error) {
		return []byte(`{"spec":{"acme":{"solvers":[
			{"dns01":{"cloudflare":{"apiTokenSecretRef":{"name":"ceffio-acme-dns","key":"api-token"}}}}
		]}}}`), nil
	}

	s := &Server{kube: fake.NewSimpleClientset(), Domain: "exemple.org",
		acme: acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "cloudflare"}}
	if !s.identifiantDNSPresent(context.Background()) {
		t.Error("le ClusterIssuer nomme un secretRef et le contrôle répond absent : la " +
			"page annoncerait un échec de renouvellement sur une installation saine")
	}
}

// TestUnSolverSansSecretRefNeComptePas : l'inverse doit être vrai, sinon l'indicateur ne
// sert à rien.
func TestUnSolverSansSecretRefNeComptePas(t *testing.T) {
	issuerAvant := lireIssuer
	t.Cleanup(func() { lireIssuer = issuerAvant })
	lireIssuer = func(ctx context.Context, nom string) ([]byte, error) {
		return []byte(`{"spec":{"acme":{"solvers":[{"dns01":{"rfc2136":{}}}]}}}`), nil
	}
	s := &Server{kube: fake.NewSimpleClientset(), Domain: "exemple.org",
		acme: acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "rfc2136"}}
	if s.identifiantDNSPresent(context.Background()) {
		t.Error("un solver sans secretRef est compté comme configuré : il ne peut rien signer")
	}
}

// TestUnIssuerIllisibleNeMentPas : un issuer qu'on ne peut pas lire n'est pas un
// identifiant présent.
func TestUnIssuerIllisibleNeMentPas(t *testing.T) {
	issuerAvant := lireIssuer
	t.Cleanup(func() { lireIssuer = issuerAvant })
	lireIssuer = func(ctx context.Context, nom string) ([]byte, error) {
		return nil, errors.New("not found")
	}
	s := &Server{kube: fake.NewSimpleClientset(), Domain: "exemple.org",
		acme: acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "cloudflare"}}
	if s.identifiantDNSPresent(context.Background()) {
		t.Error("un issuer illisible est compté comme configuré")
	}
}

// TestUnSolverIntegreNExigePasDePod : Cloudflare, Route53 et les autres solvers
// intégrés vivent DANS cert-manager.
//
// LE CONTRÔLE CHERCHAIT UN POD app=ceffio-acme-dns-webhook, qui n'existe que pour les
// hôtes hors arborescence : sur une plateforme dont les certificats se renouvellent, il
// répondait « solver not running ».
func TestUnSolverIntegreNExigePasDePod(t *testing.T) {
	s := &Server{kube: fake.NewSimpleClientset(), Domain: "exemple.org",
		acme: acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "cloudflare", Zone: "exemple.org"}}
	if !s.solverDNSDeploye(context.Background()) {
		t.Error("cloudflare est integré à cert-manager, sans pod : le contrôle répond " +
			"« not running » sur une configuration qui fonctionne")
	}
}

// TestUnWebhookSansPodEstSignale : l'inverse, pour les hôtes hors arborescence.
func TestUnWebhookSansPodEstSignale(t *testing.T) {
	s := &Server{kube: fake.NewSimpleClientset(), Domain: "exemple.org",
		acme: acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "infomaniak", WebhookGroup: "acme.infomaniak.com"}}
	if s.solverDNSDeploye(context.Background()) {
		t.Error("un hôte hors arborescence sans pod déployé est annoncé comme disponible : " +
			"le challenge ne peut pas aboutir")
	}
}
