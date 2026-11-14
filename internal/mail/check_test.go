// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Tests of the mail prerequisite checks.
//
// WHY THEY EXIST: each check turns several external facts — the public DNS, the
// cluster, the mail pod, the mail server's own view of its zone — into ONE
// verdict. Every one of those sources is replaced below by a seam that says
// "nothing answers here" by default, so a test that passes proves the verdict
// comes from the fact the test sets up, and not from something that happened to
// be reachable from the machine running it. No test here touches a network, a
// resolver or a cluster.
package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ceffio-suite/ceffio/internal/dnscheck"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/publicip"
)

// ipPubliee is the address the fake cluster publishes for the platform.
//
// IT IS FROM THE DOCUMENTATION RANGE (TEST-NET-3): if one of these tests ever
// reached a real resolver, the lookup would answer nothing instead of reaching a
// host that exists.
const ipPubliee = "203.0.113.10"

// ---------------------------------------------------------------------------
// The DNS resolver
// ---------------------------------------------------------------------------

// resolveurFactice answers the lookups of one test.
//
// AN EMPTY KEY AND A MISSING KEY BOTH MEAN "NOT PUBLISHED": `mx: {"ceffio.org":
// nil}` is the name with no MX record, which Go reports as NXDOMAIN just like a
// name that does not exist — the check treats both as "the zone publishes
// nothing here" (dnscheck.EstAbsent). To test the OTHER verdict, the resolver
// being unable to answer, a test puts an error in `erreurs`; only that one is
// allowed to read "not readable".
type resolveurFactice struct {
	hosts   map[string][]string
	mx      map[string][]*net.MX
	txt     map[string][]string
	cname   map[string]string
	srv     map[string][]*net.SRV
	ptr     map[string][]string
	erreurs map[string]error
}

func nouveauResolveurFactice() *resolveurFactice {
	return &resolveurFactice{
		hosts:   map[string][]string{},
		mx:      map[string][]*net.MX{},
		txt:     map[string][]string{},
		cname:   map[string]string{},
		srv:     map[string][]*net.SRV{},
		ptr:     map[string][]string{},
		erreurs: map[string]error{},
	}
}

// cle normalises a lookup key the way a resolver compares names.
func cle(nom string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(nom), "."))
}

// erreur returns the forced failure of one lookup, if any.
func (f *resolveurFactice) erreur(genre, nom string) error {
	return f.erreurs[genre+"|"+nom]
}

// echec is the error a resolver gives for a name that does not exist.
func echec(nom string) error {
	return &net.DNSError{Err: "no such host", Name: nom, IsNotFound: true}
}

func (f *resolveurFactice) LookupHost(_ context.Context, hote string) ([]string, error) {
	if err := f.erreur("host", cle(hote)); err != nil {
		return nil, err
	}
	if v, ok := f.hosts[cle(hote)]; ok {
		return v, nil
	}
	return nil, echec(hote)
}

func (f *resolveurFactice) LookupMX(_ context.Context, nom string) ([]*net.MX, error) {
	if err := f.erreur("mx", cle(nom)); err != nil {
		return nil, err
	}
	if v, ok := f.mx[cle(nom)]; ok {
		return v, nil
	}
	return nil, echec(nom)
}

func (f *resolveurFactice) LookupTXT(_ context.Context, nom string) ([]string, error) {
	if err := f.erreur("txt", cle(nom)); err != nil {
		return nil, err
	}
	if v, ok := f.txt[cle(nom)]; ok {
		return v, nil
	}
	return nil, echec(nom)
}

func (f *resolveurFactice) LookupCNAME(_ context.Context, hote string) (string, error) {
	if err := f.erreur("cname", cle(hote)); err != nil {
		return "", err
	}
	if v, ok := f.cname[cle(hote)]; ok {
		return v, nil
	}
	return "", echec(hote)
}

func (f *resolveurFactice) LookupSRV(_ context.Context, service, proto, nom string) (string, []*net.SRV, error) {
	k := cle(service) + "|" + cle(proto) + "|" + cle(nom)
	if err := f.erreur("srv", k); err != nil {
		return "", nil, err
	}
	if v, ok := f.srv[k]; ok {
		return "", v, nil
	}
	return "", nil, echec(nom)
}

func (f *resolveurFactice) LookupAddr(_ context.Context, adresse string) ([]string, error) {
	if err := f.erreur("ptr", cle(adresse)); err != nil {
		return nil, err
	}
	if v, ok := f.ptr[cle(adresse)]; ok {
		return v, nil
	}
	return nil, echec(adresse)
}

// ---------------------------------------------------------------------------
// The bench
// ---------------------------------------------------------------------------

// socle is one test's world: a fake cluster, a fake resolver, and one knob per
// external source the checks read.
//
// EVERY KNOB DEFAULTS TO "NOTHING ANSWERS" — an unreadable zone, an unreachable
// pod, a closed port, a silent resolver. A test then moves exactly the knob its
// check depends on, so the assertion cannot pass because a neighbouring source
// happened to answer.
type socle struct {
	resolveur *resolveurFactice
	zone      string
	zoneErr   error
	commande  func(context.Context, string) (string, error)
	cert      func(context.Context, string, string, bool) (*x509.Certificate, error)
	dial      func(context.Context, string) (net.Conn, error)
	systeme   func(context.Context, string) ([]string, error)
}

// installerSocle installs the bench for one test and restores every seam after
// it, whatever the test does.
func installerSocle(t *testing.T, objets ...runtime.Object) *socle {
	t.Helper()
	// The host name of the mail layer is derived from the domain; an operator
	// running the unit tests with CEFFIO_MAIL_DOMAIN exported must not change
	// what "mail.ceffio.org" means in these tests.
	t.Setenv("CEFFIO_MAIL_DOMAIN", "")
	installerCluster(t, objets...)

	s := &socle{
		resolveur: nouveauResolveurFactice(),
		zoneErr:   errors.New("the mail server is not reachable"),
		commande: func(context.Context, string) (string, error) {
			return "", errors.New("the mail pod is not reachable")
		},
		cert: func(context.Context, string, string, bool) (*x509.Certificate, error) {
			return nil, errors.New("no TLS listener")
		},
		dial: func(context.Context, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
		systeme: func(context.Context, string) ([]string, error) {
			return nil, echec("blocklist")
		},
	}

	remplacer(t, &nouvelleResolution, func() *dnscheck.Client {
		return dnscheck.PourTest(s.resolveur)
	})
	remplacer(t, &lireZoneDNS, func(context.Context, string) (string, error) {
		return s.zone, s.zoneErr
	})
	remplacer(t, &executerCommandePod, func(ctx context.Context, script string) (string, error) {
		return s.commande(ctx, script)
	})
	remplacer(t, &certificatServi, func(ctx context.Context, adresse, hote string, implicite bool) (*x509.Certificate, error) {
		return s.cert(ctx, adresse, hote, implicite)
	})
	remplacer(t, &dialTCP, func(ctx context.Context, adresse string) (net.Conn, error) {
		return s.dial(ctx, adresse)
	})
	remplacer(t, &resoudreNomSysteme, func(ctx context.Context, nom string) ([]string, error) {
		return s.systeme(ctx, nom)
	})
	remplacer(t, &transportJMAP, func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("the mail server is not reachable")
	})
	return s
}

// remplacer swaps a seam for the duration of the test.
func remplacer[T any](t *testing.T, cible *T, valeur T) {
	t.Helper()
	ancien := *cible
	*cible = valeur
	t.Cleanup(func() { *cible = ancien })
}

// contexte builds the shared context of the checks without going through Checks,
// so that a test about ONE check is not affected by the settings or the public
// address being readable.
func (s *socle) contexte(domaine string, reglages Reglages) *contexteChecks {
	return &contexteChecks{
		domaine:   domaine,
		hote:      "mail." + domaine,
		prive:     estDomainePrive(domaine),
		resolveur: dnscheck.PourTest(s.resolveur),
		reglages:  reglages,
		adresse:   publicip.Adresse{IPv4: ipPubliee},
		ipConnue:  true,
	}
}

// ---------------------------------------------------------------------------
// Cluster fixtures
// ---------------------------------------------------------------------------

// configMapAdressePublique is the ConfigMap the platform publishes its address in.
func configMapAdressePublique(ip string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: publicip.Nom, Namespace: publicip.Namespace},
		Data:       map[string]string{publicip.CleIPv4: ip},
	}
}

// configMapReglages is the ConfigMap the mail settings live in.
func configMapReglages(donnees map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "ceffio-settings", Namespace: nsReglages},
		Data:       donnees,
	}
}

// reglagesRelais are settings in relay mode, with a host, a port and a user: the
// password is deliberately absent, since it lives in the vault and these tests
// have no vault.
var reglagesRelais = map[string]string{
	CleServeur: `{"envoi":"relais"}`,
	CleRelais:  `{"hote":"relais.example.net","port":"587","utilisateur":"ceffio"}`,
}

// serviceMailFactice is the internal Service the TLS check resolves the mail host
// through.
func serviceMailFactice() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceMail, Namespace: ns},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.43.0.10"},
	}
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

// certificatTest builds a certificate with the given names and expiry.
//
// autoSigne chooses between the two faults the TLS check must tell apart: a
// certificate issued by itself (Stalwart's built-in one) and one issued by a CA
// but for the wrong name.
func certificatTest(t *testing.T, noms []string, expire time.Time, autoSigne bool) *x509.Certificate {
	t.Helper()
	commun := "mail.ceffio.org"
	if len(noms) > 0 {
		commun = noms[0]
	}
	cle, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the key: %v", err)
	}
	modele := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commun},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     expire,
		DNSNames:     noms,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signataire := modele, any(cle)
	if !autoSigne {
		cleCA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating the CA key: %v", err)
		}
		parent = &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		signataire = cleCA
	}
	der, err := x509.CreateCertificate(rand.Reader, modele, parent, &cle.PublicKey, signataire)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}

// ---------------------------------------------------------------------------
// SMTP sessions on a pipe
// ---------------------------------------------------------------------------

// dialogueSMTP is the server side of a fake SMTP session.
type dialogueSMTP func(br *bufio.Reader, c net.Conn) error

// dialogueAvecBanniere answers one connection with `lignes` and then waits for
// the client to hang up.
func dialogueAvecBanniere(lignes ...string) dialogueSMTP {
	return func(br *bufio.Reader, c net.Conn) error {
		for _, ligne := range lignes {
			if _, err := fmt.Fprint(c, ligne+"\r\n"); err != nil {
				return err
			}
			// A greeting does not wait for the client; an EHLO reply does.
			if br.Buffered() > 0 {
				if _, err := br.ReadString('\n'); err != nil {
					return err
				}
			}
		}
		_, err := br.ReadString('\n')
		return err
	}
}

// sansAuthentification greets the client and answers EHLO without offering AUTH.
func sansAuthentification(br *bufio.Reader, c net.Conn) error {
	if _, err := fmt.Fprint(c, "220 relais.example.net ESMTP\r\n"); err != nil {
		return err
	}
	if _, err := br.ReadString('\n'); err != nil {
		return err
	}
	if _, err := fmt.Fprint(c, "250 relais.example.net\r\n"); err != nil {
		return err
	}
	_, err := br.ReadString('\n')
	return err
}

// dialerFactice installs a dial seam that speaks `dialogue` on a pipe.
//
// THE PIPE IS WHAT MAKES THE SMTP DIALOGUE TESTABLE WITHOUT A NETWORK: the
// client and the fake server each hold one end, and the dialogue is exactly the
// one a real relay would have.
func dialerFactice(t *testing.T, dialogue dialogueSMTP) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	return func(context.Context, string) (net.Conn, error) {
		client, serveur := net.Pipe()
		go func() {
			defer serveur.Close()
			_ = dialogue(bufio.NewReader(serveur), serveur)
		}()
		return client, nil
	}
}

// ---------------------------------------------------------------------------
// Small assertions
// ---------------------------------------------------------------------------

// verifierParID runs one check and returns its verdict.
func verdictParID(t *testing.T, checks []module.Check, id string) module.Check {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	ids := make([]string, 0, len(checks))
	for _, check := range checks {
		ids = append(ids, check.ID)
	}
	t.Fatalf("no check with id %q; the checks were %s", id, strings.Join(ids, ", "))
	return module.Check{}
}

// attendreNiveau fails the test when a verdict is not the expected level, and
// prints the Detail it got — a level alone never says what went wrong.
func attendreNiveau(t *testing.T, check module.Check, niveau module.CheckLevel) {
	t.Helper()
	if check.Level != niveau {
		t.Fatalf("check %q: level = %q, want %q (detail: %s)", check.ID, check.Level, niveau, check.Detail)
	}
}

// attendreContient fails the test when a string does not appear in the verdict.
func attendreContient(t *testing.T, check module.Check, champ, motif string) {
	t.Helper()
	valeur := check.Detail
	if champ == "fix" {
		valeur = check.Fix
	}
	if !strings.Contains(valeur, motif) {
		t.Fatalf("check %q: %s does not contain %q: %s", check.ID, champ, motif, valeur)
	}
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func TestChecksSansDomaine(t *testing.T) {
	installerSocle(t)

	attendus := []string{
		"mx", "a-mail", "ptr", "port25-out", "relay", "tls", "records",
		"inbound-25", "inbound-test", "dnsbl", "volume",
	}
	checks := Checks(context.Background(), "   ")
	if len(checks) != len(attendus) {
		t.Fatalf("got %d checks, want %d", len(checks), len(attendus))
	}
	for i, id := range attendus {
		if checks[i].ID != id {
			t.Fatalf("check %d: id = %q, want %q", i, checks[i].ID, id)
		}
		attendreNiveau(t, checks[i], module.CheckNotApplicable)
		if checks[i].Label == "" || checks[i].Detail == "" {
			t.Fatalf("check %q: an empty label or detail is an absence, not a diagnosis", id)
		}
		attendreContient(t, checks[i], "detail", "no platform domain")
	}
}

func TestChecksDomainePrive(t *testing.T) {
	installerSocle(t,
		configMapAdressePublique(ipPubliee),
		configMapReglages(reglagesRelais),
	)

	checks := Checks(context.Background(), "ceffio.local")

	// The Internet checks answer "internal delivery only"; the local ones (the
	// relay settings, the certificate, the volume) are still evaluated, because
	// they are about this installation and not about the outside world.
	for _, id := range []string{"mx", "a-mail", "ptr", "port25-out", "records", "inbound-25", "inbound-test", "dnsbl"} {
		check := verdictParID(t, checks, id)
		attendreNiveau(t, check, module.CheckNotApplicable)
		attendreContient(t, check, "detail", "private domain")
	}

	// The relay is configured but its password is in the vault, which the bench
	// has no access to: the check must say so and block.
	relais := verdictParID(t, checks, "relay")
	attendreNiveau(t, relais, module.CheckBlocking)
	attendreContient(t, relais, "detail", "relay password is empty")

	attendreNiveau(t, verdictParID(t, checks, "tls"), module.CheckWarning)
	attendreNiveau(t, verdictParID(t, checks, "volume"), module.CheckWarning)
}

func TestChecksAucunePanique(t *testing.T) {
	installerSocle(t, configMapAdressePublique(ipPubliee))

	// Nothing answers anywhere: every check must still return a verdict with a
	// level it recognises and a detail that says what it could not read.
	checks := Checks(context.Background(), "ceffio.org")
	if len(checks) != 11 {
		t.Fatalf("got %d checks, want 11 (the record families collapse into one group verdict when the zone is unreadable)", len(checks))
	}
	vus := map[string]bool{}
	valides := map[module.CheckLevel]bool{
		module.CheckOK:            true,
		module.CheckWarning:       true,
		module.CheckBlocking:      true,
		module.CheckNotApplicable: true,
	}
	for _, check := range checks {
		if vus[check.ID] {
			t.Fatalf("check id %q returned twice", check.ID)
		}
		vus[check.ID] = true
		if check.Label == "" || check.Detail == "" {
			t.Fatalf("check %q: an empty label or detail is an absence, not a diagnosis", check.ID)
		}
		if !valides[check.Level] {
			t.Fatalf("check %q: unknown level %q", check.ID, check.Level)
		}
	}
}

// ---------------------------------------------------------------------------
// mx, a-mail, ptr
// ---------------------------------------------------------------------------

func TestVerifierMX(t *testing.T) {
	t.Run("aucun enregistrement", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.mx["ceffio.org"] = nil
		check := verifierMX(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "no MX record")
		attendreContient(t, check, "fix", "ceffio.org. MX 10 mail.ceffio.org.")
	})

	t.Run("MX non publié (NXDOMAIN)", func(t *testing.T) {
		s := installerSocle(t)
		// Go reports a domain without MX as `no such host`, exactly like a
		// domain that does not exist. Reading that as an unreadable lookup
		// would turn the most ordinary gap into a broken verification.
		s.resolveur.erreurs["mx|ceffio.org"] = &net.DNSError{Err: "no such host", Name: "ceffio.org", IsNotFound: true}
		check := verifierMX(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "no MX record")
		attendreContient(t, check, "fix", "ceffio.org. MX 10 mail.ceffio.org.")
	})

	t.Run("MX illisible", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.erreurs["mx|ceffio.org"] = &net.DNSError{Err: "timeout", Name: "ceffio.org", IsTimeout: true}
		check := verifierMX(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "could not be read")
	})

	t.Run("autre service de messagerie", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.mx["ceffio.org"] = []*net.MX{{Host: "mx.autre.example.net.", Pref: 5}}
		check := verifierMX(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "another mail service")
	})

	t.Run("routé vers le serveur de la plateforme", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.mx["ceffio.org"] = []*net.MX{{Host: "mail.ceffio.org.", Pref: 10}}
		check := verifierMX(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
		attendreContient(t, check, "detail", "routed to the mail server")
	})

	t.Run("null MX", func(t *testing.T) {
		s := installerSocle(t)
		// RFC 7505: a single record whose host is "." says "this domain accepts
		// no mail". It must not be read as a foreign MX.
		s.resolveur.mx["ceffio.org"] = []*net.MX{{Host: ".", Pref: 0}}
		check := verifierMX(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "null MX")
		attendreContient(t, check, "fix", "ceffio.org. MX 10 mail.ceffio.org.")
	})

	t.Run("domaine privé", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierMX(context.Background(), s.contexte("ceffio.local", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckNotApplicable)
	})
}

func TestVerifierAMail(t *testing.T) {
	t.Run("mauvais A", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.hosts["mail.ceffio.org"] = []string{"198.51.100.7"}
		check := verifierAMail(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "not to the platform's public address")
	})

	t.Run("A absent", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierAMail(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "fix", "mail.ceffio.org. A "+ipPubliee)
	})

	t.Run("AAAA inattendu", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.hosts["mail.ceffio.org"] = []string{ipPubliee, "2001:db8::1"}
		check := verifierAMail(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "2001:db8::1")
	})

	t.Run("correct", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.hosts["mail.ceffio.org"] = []string{ipPubliee}
		check := verifierAMail(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
	})
}

func TestVerifierPTR(t *testing.T) {
	t.Run("PTR illisible en direct bloque", func(t *testing.T) {
		s := installerSocle(t)
		// A RESOLVER THAT CANNOT ANSWER IS NOT A MISSING PTR: only this case may
		// read "could not be read", and it must still block in direct mode.
		s.resolveur.erreurs["ptr|"+ipPubliee] = &net.DNSError{Err: "timeout", Name: ipPubliee, IsTimeout: true}
		check := verifierPTR(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "could not be read")
		attendreContient(t, check, "fix", "reverse DNS (PTR)")
	})

	t.Run("PTR non publié en direct bloque", func(t *testing.T) {
		s := installerSocle(t)
		// NXDOMAIN on the reverse name: the absence is the finding, so it must
		// read as a missing reverse DNS, not as a failed lookup.
		check := verifierPTR(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "has no reverse DNS")
		attendreContient(t, check, "fix", "reverse DNS (PTR)")
	})

	t.Run("aucun PTR déclaré", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.ptr[ipPubliee] = []string{}
		check := verifierPTR(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "has no reverse DNS")
	})

	t.Run("PTR vers un autre nom", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.ptr[ipPubliee] = []string{"autre.example.net"}
		check := verifierPTR(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "not mail.ceffio.org")
	})

	t.Run("PTR vers un autre nom en relais avertit", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.ptr[ipPubliee] = []string{"autre.example.net"}
		reglages := ReglagesParDefaut()
		reglages.Envoi = Envoi{Mode: ModeRelais, Hote: "relais.example.net", Port: 587}
		check := verifierPTR(context.Background(), s.contexte("ceffio.org", reglages))
		attendreNiveau(t, check, module.CheckWarning)
	})

	t.Run("aller-retour confirmé", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.ptr[ipPubliee] = []string{"mail.ceffio.org"}
		s.resolveur.hosts["mail.ceffio.org"] = []string{ipPubliee}
		check := verifierPTR(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
	})

	t.Run("PTR juste mais A absent", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.ptr[ipPubliee] = []string{"mail.ceffio.org"}
		check := verifierPTR(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "does not resolve back")
	})
}

// ---------------------------------------------------------------------------
// port25-out, relay
// ---------------------------------------------------------------------------

func TestVerifierPort25Sortant(t *testing.T) {
	sonde := func(t *testing.T, s *socle) {
		t.Helper()
		s.resolveur.mx[sondeSortie] = []*net.MX{{Host: "gmail-smtp-in.l.google.com.", Pref: 5}}
	}

	t.Run("sonde qui ne peut pas tourner", func(t *testing.T) {
		s := installerSocle(t)
		sonde(t, s)
		check := verifierPort25Sortant(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "the probe could not run")
	})

	t.Run("port fermé", func(t *testing.T) {
		s := installerSocle(t)
		sonde(t, s)
		var script string
		s.commande = func(_ context.Context, s string) (string, error) {
			script = s
			return "FERME", nil
		}
		check := verifierPort25Sortant(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "fix", "relay")
		if !strings.Contains(script, "/dev/tcp/gmail-smtp-in.l.google.com/25") {
			t.Fatalf("the probe does not target the resolved MX: %s", script)
		}
	})

	t.Run("port ouvert", func(t *testing.T) {
		s := installerSocle(t)
		sonde(t, s)
		s.commande = func(context.Context, string) (string, error) { return "OUVERT", nil }
		check := verifierPort25Sortant(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
	})

	t.Run("cible introuvable", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierPort25Sortant(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "could not be resolved")
	})

	t.Run("relais configuré", func(t *testing.T) {
		s := installerSocle(t)
		reglages := ReglagesParDefaut()
		reglages.Envoi = Envoi{Mode: ModeRelais, Hote: "relais.example.net", Port: 587}
		check := verifierPort25Sortant(context.Background(), s.contexte("ceffio.org", reglages))
		attendreNiveau(t, check, module.CheckNotApplicable)
	})
}

func TestVerifierRelais(t *testing.T) {
	relaisComplet := func() Reglages {
		reglages := ReglagesParDefaut()
		reglages.Envoi = Envoi{
			Mode: ModeRelais, Hote: "relais.example.net", Port: 587,
			Utilisateur: "ceffio", MotDePasse: "secret",
		}
		return reglages
	}

	t.Run("envoi direct", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierRelais(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckNotApplicable)
	})

	t.Run("réglages incomplets", func(t *testing.T) {
		s := installerSocle(t)
		reglages := relaisComplet()
		reglages.Envoi.MotDePasse = ""
		check := verifierRelais(context.Background(), s.contexte("ceffio.org", reglages))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "incomplete")
	})

	t.Run("relais injoignable", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierRelais(context.Background(), s.contexte("ceffio.org", relaisComplet()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "cannot reach")
	})

	t.Run("relais sans authentification", func(t *testing.T) {
		s := installerSocle(t)
		s.dial = dialerFactice(t, sansAuthentification)
		check := verifierRelais(context.Background(), s.contexte("ceffio.org", relaisComplet()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "no authentication")
	})

	t.Run("relais sans utilisateur", func(t *testing.T) {
		s := installerSocle(t)
		s.dial = dialerFactice(t, sansAuthentification)
		ok, detail := verifierRelaisSMTP(context.Background(), Envoi{Hote: "relais.example.net", Port: 587})
		if !ok {
			t.Fatalf("the relay answered, so the session should be usable: %s", detail)
		}
		if !strings.Contains(detail, "no username") {
			t.Fatalf("detail = %q, want a mention that no username was given", detail)
		}
	})
}

// ---------------------------------------------------------------------------
// tls
// ---------------------------------------------------------------------------

func TestVerifierTLS(t *testing.T) {
	installer := func(t *testing.T) *socle {
		t.Helper()
		return installerSocle(t, serviceMailFactice())
	}

	t.Run("certificat auto-signé", func(t *testing.T) {
		s := installer(t)
		cert := certificatTest(t, []string{"localhost"}, time.Now().Add(90*24*time.Hour), true)
		s.cert = func(context.Context, string, string, bool) (*x509.Certificate, error) { return cert, nil }
		check := verifierTLS(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "self-signed certificate")
		attendreContient(t, check, "fix", "ceffio mail --domain ceffio.org")
	})

	t.Run("certificat valide pour l'hôte", func(t *testing.T) {
		s := installer(t)
		cert := certificatTest(t, []string{"mail.ceffio.org"}, time.Now().Add(90*24*time.Hour), false)
		s.cert = func(context.Context, string, string, bool) (*x509.Certificate, error) { return cert, nil }
		check := verifierTLS(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
	})

	t.Run("certificat d'un autre hôte", func(t *testing.T) {
		s := installer(t)
		cert := certificatTest(t, []string{"console.example.net"}, time.Now().Add(90*24*time.Hour), false)
		s.cert = func(context.Context, string, string, bool) (*x509.Certificate, error) { return cert, nil }
		check := verifierTLS(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "not mail.ceffio.org")
	})

	t.Run("renouvellement en retard", func(t *testing.T) {
		s := installer(t)
		cert := certificatTest(t, []string{"mail.ceffio.org"}, time.Now().Add(5*24*time.Hour), false)
		s.cert = func(context.Context, string, string, bool) (*x509.Certificate, error) { return cert, nil }
		check := verifierTLS(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "less than two weeks")
	})

	t.Run("certificat expiré", func(t *testing.T) {
		s := installer(t)
		cert := certificatTest(t, []string{"mail.ceffio.org"}, time.Now().Add(-time.Hour), false)
		s.cert = func(context.Context, string, string, bool) (*x509.Certificate, error) { return cert, nil }
		check := verifierTLS(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckBlocking)
		attendreContient(t, check, "detail", "expired")
	})

	t.Run("service illisible", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierTLS(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "Service")
	})
}

// ---------------------------------------------------------------------------
// records
// ---------------------------------------------------------------------------

// zoneComplete is the zone file a fully configured mail server generates.
const zoneComplete = `$ORIGIN ceffio.org.
$TTL 3600
@                IN MX 10 mail.ceffio.org.
mail             IN A 203.0.113.10
@                IN TXT "v=spf1 mx -all"
ceffio._domainkey IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
_dmarc           IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@ceffio.org"
_mta-sts         IN TXT "v=STSv1; id=20260101"
mta-sts          IN CNAME mail.ceffio.org.
_smtp._tls       IN TXT "v=TLSRPTv1; rua=mailto:tls@ceffio.org"
autoconfig       IN CNAME mail.ceffio.org.
_imaps._tcp      IN SRV 0 1 993 mail.ceffio.org.
_submissions._tcp IN SRV 0 1 465 mail.ceffio.org.
`

// publierZone makes the fake resolver answer exactly what zoneComplete declares.
func publierZone(t *testing.T, s *socle) {
	t.Helper()
	s.zone, s.zoneErr = zoneComplete, nil
	r := s.resolveur
	r.mx["ceffio.org"] = []*net.MX{{Host: "mail.ceffio.org.", Pref: 10}}
	r.hosts["mail.ceffio.org"] = []string{ipPubliee}
	r.txt["ceffio.org"] = []string{"v=spf1 mx -all"}
	r.txt["ceffio._domainkey.ceffio.org"] = []string{"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"}
	r.txt["_dmarc.ceffio.org"] = []string{"v=DMARC1; p=quarantine; rua=mailto:dmarc@ceffio.org"}
	r.txt["_mta-sts.ceffio.org"] = []string{"v=STSv1; id=20260101"}
	r.cname["mta-sts.ceffio.org"] = "mail.ceffio.org."
	r.txt["_smtp._tls.ceffio.org"] = []string{"v=TLSRPTv1; rua=mailto:tls@ceffio.org"}
	r.cname["autoconfig.ceffio.org"] = "mail.ceffio.org."
	r.srv["imaps|tcp|ceffio.org"] = []*net.SRV{{Target: "mail.ceffio.org.", Port: 993, Priority: 0, Weight: 1}}
	r.srv["submissions|tcp|ceffio.org"] = []*net.SRV{{Target: "mail.ceffio.org.", Port: 465, Priority: 0, Weight: 1}}
}

func TestVerifierRecordsSansZone(t *testing.T) {
	t.Run("zone illisible", func(t *testing.T) {
		s := installerSocle(t)
		checks := verifierRecords(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		if len(checks) != 1 {
			t.Fatalf("got %d checks, want the single group verdict", len(checks))
		}
		attendreNiveau(t, checks[0], module.CheckWarning)
		attendreContient(t, checks[0], "detail", "zone file")
	})

	t.Run("zone vide", func(t *testing.T) {
		s := installerSocle(t)
		s.zone, s.zoneErr = "   \n", nil
		checks := verifierRecords(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		if len(checks) != 1 {
			t.Fatalf("got %d checks, want the single group verdict", len(checks))
		}
		attendreNiveau(t, checks[0], module.CheckWarning)
		attendreContient(t, checks[0], "detail", "no zone file")
	})

	t.Run("domaine privé", func(t *testing.T) {
		s := installerSocle(t)
		checks := verifierRecords(context.Background(), s.contexte("ceffio.local", ReglagesParDefaut()))
		if len(checks) != 1 {
			t.Fatalf("got %d checks, want the single group verdict", len(checks))
		}
		attendreNiveau(t, checks[0], module.CheckNotApplicable)
	})
}

func TestVerifierRecordsComplets(t *testing.T) {
	s := installerSocle(t)
	publierZone(t, s)

	checks := verifierRecords(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
	attendus := []string{
		"records", "records-spf", "records-dkim", "records-dmarc", "records-mta-sts",
		"records-tls-rpt", "records-autoconfig", "records-srv",
	}
	if len(checks) != len(attendus) {
		t.Fatalf("got %d checks, want %d", len(checks), len(attendus))
	}
	for i, id := range attendus {
		if checks[i].ID != id {
			t.Fatalf("check %d: id = %q, want %q", i, checks[i].ID, id)
		}
		attendreNiveau(t, checks[i], module.CheckOK)
	}
	attendreContient(t, checks[0], "detail", "11 records are published")
}

func TestVerifierRecordsManquants(t *testing.T) {
	t.Run("famille absente de la zone", func(t *testing.T) {
		s := installerSocle(t)
		publierZone(t, s)
		// The server declares no DMARC record at all: that is its own fault and
		// the operator must hear about it, because mail is then unauthenticated
		// on that axis without any DNS mistake.
		s.zone = strings.Replace(zoneComplete,
			"_dmarc           IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@ceffio.org\"\n", "", 1)
		delete(s.resolveur.txt, "_dmarc.ceffio.org")

		checks := verifierRecords(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, verdictParID(t, checks, "records"), module.CheckWarning)
		attendreNiveau(t, verdictParID(t, checks, "records-dmarc"), module.CheckWarning)
		attendreContient(t, verdictParID(t, checks, "records-dmarc"), "detail", "declares no")
	})

	t.Run("zone d'accord mais DNS muet", func(t *testing.T) {
		s := installerSocle(t)
		publierZone(t, s)
		delete(s.resolveur.txt, "ceffio.org")

		checks := verifierRecords(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		resume := verdictParID(t, checks, "records")
		attendreNiveau(t, resume, module.CheckWarning)
		attendreContient(t, resume, "detail", "does not match the zone file")
		attendreContient(t, resume, "fix", "records-*")

		s.resolveur.txt["ceffio.org"] = []string{}
		checks = verifierRecords(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		spf := verdictParID(t, checks, "records-spf")
		attendreNiveau(t, spf, module.CheckWarning)
		attendreContient(t, spf, "detail", "no TXT record")
		attendreContient(t, spf, "fix", `ceffio.org. IN TXT "v=spf1 mx -all"`)
	})

	t.Run("relay: the SPF fix names the relay's include", func(t *testing.T) {
		s := installerSocle(t)
		publierZone(t, s)
		// The record is missing, and outgoing mail leaves through a relay: the
		// zone file's own SPF line would be a correct direct-delivery record
		// only. An operator who copies it verbatim still fails SPF at the
		// relay's addresses, so the fix must say so.
		delete(s.resolveur.txt, "ceffio.org")
		reglages := ReglagesParDefaut()
		reglages.Envoi = Envoi{Mode: ModeRelais, Hote: "relais.example.net", Port: 587}

		checks := verifierRecords(context.Background(), s.contexte("ceffio.org", reglages))
		spf := verdictParID(t, checks, "records-spf")
		attendreNiveau(t, spf, module.CheckWarning)
		attendreContient(t, spf, "fix", "include:")
	})
}

// ---------------------------------------------------------------------------
// inbound-25, inbound-test
// ---------------------------------------------------------------------------

func TestVerifierEntrant25(t *testing.T) {
	t.Run("connexion refusée", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierEntrant25(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "no connection to")
		attendreContient(t, check, "fix", "inbound port 25")
	})

	t.Run("bannière SMTP", func(t *testing.T) {
		s := installerSocle(t)
		s.dial = dialerFactice(t, dialogueAvecBanniere("220 mail.ceffio.org ESMTP Stalwart"))
		check := verifierEntrant25(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
		attendreContient(t, check, "detail", "the world can reach the mail server")
	})

	t.Run("bannière inattendue", func(t *testing.T) {
		s := installerSocle(t)
		s.dial = dialerFactice(t, dialogueAvecBanniere("554 go away"))
		check := verifierEntrant25(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "instead of an SMTP banner")
	})
}

// jmapEntrant answers the JMAP calls the inbound test makes.
func jmapEntrant(t *testing.T, expediteur, entetes string) {
	t.Helper()
	fauxTransportJMAP(t, map[string]any{
		// THE ADDRESS IS NOT THE ACCOUNT NAME: the server lists accounts by
		// login ("adminceffio"), and postmaster@ is an alias carried by that
		// account. The fixture reproduces that shape, because a name-based
		// match would pass with a name-shaped fixture and fail in production.
		"x:Account/get": map[string]any{
			"list": []any{map[string]any{
				"id": "a1", "name": "adminceffio", "emailAddress": "adminceffio@ceffio.org",
				"aliases": map[string]any{"0": map[string]any{
					"@type": "EmailAlias", "name": "postmaster", "domainId": "d1",
				}},
			}},
		},
		"x:Domain/get": map[string]any{
			"list": []any{map[string]any{"id": "d1", "name": "ceffio.org"}},
		},
		"x:Mailbox/get": map[string]any{
			"list": []any{map[string]any{"id": "m1", "name": "INBOX", "role": "inbox"}},
		},
		"Email/query": map[string]any{"ids": []any{"e1"}},
		"Email/get": map[string]any{
			"list": []any{map[string]any{
				"from":                                 []any{map[string]any{"email": expediteur}},
				"receivedAt":                           "2026-01-02T03:04:05Z",
				"header:Authentication-Results:asText": entetes,
			}},
		},
	})
}

func TestVerifierTestEntrant(t *testing.T) {
	t.Run("message authentifié", func(t *testing.T) {
		s := installerSocle(t)
		jmapEntrant(t, "alice@example.net", "mx.example.net; spf=pass dkim=pass dmarc=pass")
		check := verifierTestEntrant(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
		attendreContient(t, check, "detail", "is authenticated")
	})

	t.Run("messages illisibles", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierTestEntrant(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "could not be listed")
	})

	t.Run("aucun message extérieur", func(t *testing.T) {
		s := installerSocle(t)
		// A bounce proves the OUTBOUND path: it must not be taken for an
		// inbound delivery (§9.F).
		jmapEntrant(t, "MAILER-DAEMON@ceffio.org", "mx.example.net; spf=pass dkim=pass dmarc=pass")
		check := verifierTestEntrant(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "no message from an outside domain")
	})

	t.Run("authentification non évaluée", func(t *testing.T) {
		s := installerSocle(t)
		jmapEntrant(t, "alice@example.net", "")
		check := verifierTestEntrant(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "no Authentication-Results")
	})
}

// ---------------------------------------------------------------------------
// dnsbl
// ---------------------------------------------------------------------------

func TestVerifierListesNoires(t *testing.T) {
	t.Run("adresse listée", func(t *testing.T) {
		s := installerSocle(t)
		s.systeme = func(_ context.Context, nom string) ([]string, error) {
			if strings.HasSuffix(nom, "zen.spamhaus.org") {
				return []string{"127.0.0.2"}, nil
			}
			return nil, echec(nom)
		}
		check := verifierListesNoires(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "is listed by zen.spamhaus.org")
		attendreContient(t, check, "fix", "delisting")
	})

	t.Run("adresse absente des listes", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierListesNoires(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
		attendreContient(t, check, "detail", "is not listed")
	})

	t.Run("aucune liste joignable", func(t *testing.T) {
		s := installerSocle(t)
		s.systeme = func(context.Context, string) ([]string, error) {
			return []string{"127.255.255.254"}, nil
		}
		check := verifierListesNoires(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckNotApplicable)
		attendreContient(t, check, "detail", "query refused")
	})

	t.Run("adresse publique inconnue", func(t *testing.T) {
		s := installerSocle(t)
		c := s.contexte("ceffio.org", ReglagesParDefaut())
		c.ipConnue = false
		check := verifierListesNoires(context.Background(), c)
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "no public address")
	})
}

// ---------------------------------------------------------------------------
// volume
// ---------------------------------------------------------------------------

// jmapQuotas answers the accounts call with one account holding `octets`.
func jmapQuotas(t *testing.T, octets int64) {
	t.Helper()
	fauxTransportJMAP(t, map[string]any{
		"x:Account/get": map[string]any{
			"list": []any{map[string]any{
				"id":     "a1",
				"name":   "postmaster@ceffio.org",
				"quotas": map[string]any{"maxDiskQuota": float64(octets)},
			}},
		},
	})
}

// dfRend is the `df -Pk` output for a volume with `libreGo` free.
func dfRend(libreGo int64) string {
	return fmt.Sprintf("Filesystem 1024-blocks Used Available Capacity Mounted on\n"+
		"/dev/sda1 20971520 0 %d 50%% %s\n", libreGo*1024*1024, cheminVolume)
}

func TestVerifierVolume(t *testing.T) {
	t.Run("volume absent", func(t *testing.T) {
		s := installerSocle(t)
		check := verifierVolume(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "volume")
	})

	t.Run("quotas au-delà de la capacité", func(t *testing.T) {
		s := installerSocle(t, claim(20, "local-path"))
		jmapQuotas(t, 25<<30)
		check := verifierVolume(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "delivery stops when the volume fills")
	})

	t.Run("moins de dix pour cent libre", func(t *testing.T) {
		s := installerSocle(t, claim(20, "local-path"))
		jmapQuotas(t, 5<<30)
		s.commande = func(context.Context, string) (string, error) { return dfRend(1), nil }
		check := verifierVolume(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckWarning)
		attendreContient(t, check, "detail", "less than 10 %")
	})

	t.Run("volume sain", func(t *testing.T) {
		s := installerSocle(t, claim(20, "local-path"))
		jmapQuotas(t, 5<<30)
		s.commande = func(context.Context, string) (string, error) { return dfRend(10), nil }
		check := verifierVolume(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()))
		attendreNiveau(t, check, module.CheckOK)
		attendreContient(t, check, "detail", "free")
	})
}

// ---------------------------------------------------------------------------
// the record lookups themselves
// ---------------------------------------------------------------------------

func TestManqueDistingueAbsentDeCNAME(t *testing.T) {
	t.Run("CNAME absent", func(t *testing.T) {
		s := installerSocle(t)
		// net.LookupCNAME ANSWERS WITH THE NAME ITSELF when there is no alias.
		// Reading that as "points to itself" told the operator to fix a record
		// that does not exist.
		s.resolveur.cname["autoconfig.ceffio.org"] = "autoconfig.ceffio.org."
		motif := manque(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()), valeurAttendue{
			Genre: "CNAME", Nom: "autoconfig.ceffio.org", Valeur: "mail.ceffio.org",
		})
		if !strings.Contains(motif, "no CNAME record pointing to mail.ceffio.org") {
			t.Fatalf("motif = %q, want the absence, not a self-alias", motif)
		}
	})

	t.Run("CNAME vers un autre nom", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.cname["autoconfig.ceffio.org"] = "console.example.net."
		motif := manque(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()), valeurAttendue{
			Genre: "CNAME", Nom: "autoconfig.ceffio.org", Valeur: "mail.ceffio.org",
		})
		if !strings.Contains(motif, "points to console.example.net, expected mail.ceffio.org") {
			t.Fatalf("motif = %q, want the wrong target named", motif)
		}
	})

	t.Run("SRV: une seule barre de soulignement", func(t *testing.T) {
		s := installerSocle(t)
		// Go prepends `_` to the service, so the lookup must receive `imaps`
		// even though the record is written `_imaps._tcp`. The fake is keyed on
		// what the client asks for: a key here proves the argument is right.
		s.resolveur.srv["imaps|tcp|ceffio.org"] = []*net.SRV{{Target: "mail.ceffio.org.", Port: 993, Priority: 0, Weight: 1}}
		motif := manque(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()), valeurAttendue{
			Genre: "SRV", Service: "_imaps", Proto: "tcp", Nom: "ceffio.org",
			Prio: 0, Poids: 1, Port: 993, Cible: "mail.ceffio.org",
		})
		if motif != "" {
			t.Fatalf("motif = %q, want the record found", motif)
		}
	})

	t.Run("TXT absent", func(t *testing.T) {
		s := installerSocle(t)
		s.resolveur.erreurs["txt|ceffio.org"] = &net.DNSError{Err: "no such host", Name: "ceffio.org", IsNotFound: true}
		motif := manque(context.Background(), s.contexte("ceffio.org", ReglagesParDefaut()), valeurAttendue{
			Genre: "TXT", Nom: "ceffio.org", Valeur: "v=spf1 mx -all",
		})
		if !strings.Contains(motif, "no TXT record") || strings.Contains(motif, "not readable") {
			t.Fatalf("motif = %q, want the missing record, not a failed lookup", motif)
		}
	})
}

// ---------------------------------------------------------------------------
// the account lookup
// ---------------------------------------------------------------------------

func TestTrouverCompte(t *testing.T) {
	comptes := func(t *testing.T, compte map[string]any) {
		t.Helper()
		fauxTransportJMAP(t, map[string]any{
			"x:Account/get": map[string]any{"list": []any{compte}},
			"x:Domain/get": map[string]any{
				"list": []any{map[string]any{"id": "d1", "name": "ceffio.org"}},
			},
		})
	}

	t.Run("adresse de l'account", func(t *testing.T) {
		comptes(t, map[string]any{
			"id": "a1", "name": "adminceffio", "emailAddress": "adminceffio@ceffio.org",
		})
		id, err := trouverCompte(context.Background(), "adminceffio@ceffio.org")
		if err != nil || id != "a1" {
			t.Fatalf("id = %q, err = %v, want a1", id, err)
		}
	})

	t.Run("alias de l'account", func(t *testing.T) {
		// The alias carries a domain IDENTIFIER ("d1"), not a name: without the
		// domain table the address cannot be spelled out at all.
		comptes(t, map[string]any{
			"id": "a1", "name": "adminceffio", "emailAddress": "adminceffio@ceffio.org",
			"aliases": map[string]any{"0": map[string]any{
				"@type": "EmailAlias", "name": "postmaster", "domainId": "d1",
			}},
		})
		id, err := trouverCompte(context.Background(), "postmaster@ceffio.org")
		if err != nil || id != "a1" {
			t.Fatalf("id = %q, err = %v, want a1", id, err)
		}
	})

	t.Run("adresse absente", func(t *testing.T) {
		comptes(t, map[string]any{
			"id": "a1", "name": "adminceffio", "emailAddress": "adminceffio@ceffio.org",
		})
		id, err := trouverCompte(context.Background(), "postmaster@ceffio.org")
		if err != nil || id != "" {
			t.Fatalf("id = %q, err = %v, want no account", id, err)
		}
	})
}

// ---------------------------------------------------------------------------
// the STARTTLS greeting
// ---------------------------------------------------------------------------

func TestNegocierStartTLSEnvoieUnFQDN(t *testing.T) {
	client, serveur := net.Pipe()
	defer client.Close()
	obtenu := make(chan string, 1)
	go func() {
		defer serveur.Close()
		br := bufio.NewReader(serveur)
		if _, err := fmt.Fprint(serveur, "220 mail.ceffio.org ESMTP\r\n"); err != nil {
			obtenu <- "banner: " + err.Error()
			return
		}
		ligne, err := br.ReadString('\n')
		if err != nil {
			obtenu <- "ehlo: " + err.Error()
			return
		}
		obtenu <- ligne
		// The probe returns after STARTTLS is accepted; the TLS handshake is
		// the caller's, so the fake server stops here.
		fmt.Fprint(serveur, "250-mail.ceffio.org\r\n250 STARTTLS\r\n")
		br.ReadString('\n')
		fmt.Fprint(serveur, "220 2.0.0 Ready to start TLS\r\n")
	}()

	if _, err := negocierStartTLS(client, "mail.ceffio.org"); err != nil {
		t.Fatalf("negotiation: %v", err)
	}
	// STALWART REFUSES A BARE LABEL: `EHLO ceffio-checks` was answered with
	// `550 5.5.0 Invalid EHLO domain`, which made every STARTTLS probe fail at
	// the greeting on a working server.
	if ligne := <-obtenu; ligne != "EHLO mail.ceffio.org\r\n" {
		t.Fatalf("greeting = %q, want the probed host as a FQDN", ligne)
	}
}
