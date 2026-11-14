// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The mail prerequisites checks (docs/plan-mail.md §4.4).
//
// WHY THEY EXIST: a mail layer can be installed, its Deployment Ready and its
// certificate issued, and still receive nothing — the MX points elsewhere, port
// 25 is filtered by the hosting provider, the public DNS carries no SPF record.
// None of that is visible to a Kubernetes read, so State cannot answer it.
// State says "the workload is there"; this file says "mail can actually flow",
// one verdict per prerequisite, with the record or the command that fixes it.
//
// THEY ARE READ-ONLY AND IDEMPOTENT — the `module.Checker` contract. The
// console calls them when the Modules page opens and `ceffio dns status` calls
// them on every run; a check that wrote something would make a diagnostic
// change the system it was asked to observe. Every probe below reads.
//
// ONE CHECK NEVER HIDES ANOTHER. Each probe is attempted even when the previous
// one failed, and a probe that cannot run (no cluster, no published address, no
// JMAP answer) is reported as what it is — the check's own truth — never as a
// panic, and never as a failure of the check beside it.
//
// THE DOMAIN THAT COMES IN IS THE ADDRESS DOMAIN (ceffio.org); the host the MX
// points at is derived through `domaineMail`, the single rule this package
// already uses everywhere.
package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"regexp"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/dnscheck"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/publicip"
)

// sondeSortie is the recipient domain the outbound probe dials. A LARGE
// provider on purpose: the case that matters is "can we reach Google", it has
// several MX records, and it is stable over years — unlike a domain the
// operator controls, which might accept port 25 on a non-standard setup.
// Resolved at run time, never frozen into the binary: an address that moved
// would make the check lie.
const sondeSortie = "gmail.com"

// listesNoires are the DNSBL zones queried, in order. The query name is
// `<reversed-ip>.<zone>`. Three independent lists rather than one, because a
// single list's verdict is a single operator's opinion (§4.4) and the check
// must not declare the platform clean on that basis.
var listesNoires = []string{"zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"}

// serviceMail is the name of the internal Service of the mail layer. It is the
// address the `tls` check dials: the internal Service publishes 25/465/993
// whatever the exposure setting of the public one, which is exactly what a
// certificate check needs.
const serviceMail = "stalwart"

// cheminVolume is where the mailbox store is mounted in the pod; `df` is read
// there for the `volume` check.
const cheminVolume = "/var/lib/stalwart"

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

// The five seams below are variables so a test can answer without a network, a
// cluster or a certificate authority. Each defaults to the real implementation;
// a test replaces one and restores it with t.Cleanup.
var (
	// nouvelleResolution builds the resolver the DNS checks read through. The
	// default client queries PUBLIC resolvers, never CoreDNS: a split-horizon
	// zone that answers correctly from inside the cluster is exactly the false
	// "everything is published" this check must not produce.
	nouvelleResolution = dnscheck.Nouveau

	// dialTCP opens a TCP connection; a test substitutes net.Pipe.
	dialTCP = func(ctx context.Context, adresse string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", adresse)
	}

	// executerCommandePod runs a shell command in the Stalwart pod. The outbound
	// port 25 probe and the free-space read run from there on purpose: the
	// question is what THE SERVER can reach, not what the operator's laptop can.
	executerCommandePod = executerDansPod

	// certificatServi returns the leaf certificate a TLS port presents.
	certificatServi = certificatServiReel

	// appelServeurJMAP is the JMAP call the read-only checks make.
	appelServeurJMAP = appelJMAP

	// lireZoneDNS reads the zone file Stalwart generates for the domain: the
	// records it expects the operator to publish. It is the truth the `records`
	// family is compared against — see the block comment above the parser.
	lireZoneDNS = lireZoneDNSServeur

	// resoudreNomSysteme is the SYSTEM resolver, used by the blocklist check
	// only. A public recursive resolver is the wrong client there: Spamhaus
	// answers 127.255.255.x to queries from services it has not registered, so
	// the check must see the answer the SERVER's resolver gives, and that
	// answer is only meaningful from the host that sends the mail.
	resoudreNomSysteme = func(ctx context.Context, nom string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, nom)
	}
)

// borner gives a connection a deadline for its reads and writes.
//
// WHY IT IS NEEDED: `State` calls `Checks`, and the console reads `State` when
// the page loads. A peer that accepts the connection then says nothing — a
// port filtered by a firewall that lets the SYN through, a saturated server —
// would block that read for ever, because `DialContext` only bounds the
// establishment. A context deadline takes precedence when it is closer: the
// outermost caller decides.
func borner(ctx context.Context, conn net.Conn) {
	delai := 10 * time.Second
	if echeance, ok := ctx.Deadline(); ok {
		if reste := time.Until(echeance); reste < delai {
			delai = reste
		}
	}
	_ = conn.SetDeadline(time.Now().Add(delai))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// Checks returns the eleven prerequisite checks of the mail layer.
//
// IT RETURNS A VERDICT FOR EVERY CHECK, ALWAYS, in the order of the plan: the
// console renders them as a list, and a list that changes length with the
// environment makes an operator wonder which check disappeared. When a whole
// group cannot be evaluated (no domain, no zone file), the group keeps its id
// and says why — that is a diagnosis, an empty list is an absence.
func Checks(ctx context.Context, domaine string) []module.Check {
	domaine = normaliserDomaine(domaine)
	if domaine == "" {
		return checksSansDomaine("no platform domain is configured: the mail prerequisites cannot be checked without one")
	}
	c := &contexteChecks{
		domaine:   domaine,
		hote:      domaineMail(domaine),
		prive:     estDomainePrive(domaine),
		resolveur: nouvelleResolution(),
	}
	// THE SETTINGS AND THE PUBLIC ADDRESS ARE READ ONCE. Eleven checks
	// re-reading them would repeat the same failure once per check, and "the
	// public address is unreadable" eleven times is not a better diagnosis than
	// one — it buries the checks that did work.
	if reglages, err := LireReglages(ctx); err != nil {
		c.errReglages = err
		c.reglages = ReglagesParDefaut()
	} else {
		c.reglages = reglages
	}
	c.adresse, c.ipConnue, c.errIP = lireAdressePubliee(ctx)

	checks := make([]module.Check, 0, 18)
	checks = append(checks,
		verifierMX(ctx, c),
		verifierAMail(ctx, c),
		verifierPTR(ctx, c),
		verifierPort25Sortant(ctx, c),
		verifierRelais(ctx, c),
		verifierTLS(ctx, c),
	)
	checks = append(checks, verifierRecords(ctx, c)...)
	checks = append(checks,
		verifierEntrant25(ctx, c),
		verifierTestEntrant(ctx, c),
		verifierListesNoires(ctx, c),
		verifierVolume(ctx, c),
	)
	return checks
}

// contexteChecks carries what the eleven checks share.
type contexteChecks struct {
	domaine string // the address domain: ceffio.org
	hote    string // the mail host: mail.ceffio.org
	prive   bool   // a private domain (`.local`): internal delivery only

	resolveur *dnscheck.Client

	reglages    Reglages
	errReglages error

	adresse  publicip.Adresse
	ipConnue bool
	errIP    error
}

// res builds one check. A tiny helper, but it keeps every call site to one line
// and makes the four fields impossible to mix up.
func res(id, label string, niveau module.CheckLevel, detail, fix string) module.Check {
	return module.Check{ID: id, Label: label, Level: niveau, Detail: detail, Fix: fix}
}

// resultat is res for a check built from the shared context.
func (c *contexteChecks) resultat(id, label string, niveau module.CheckLevel, detail, fix string) module.Check {
	return res(id, label, niveau, detail, fix)
}

// normaliserDomaine trims what an operator can paste and lower-cases the rest.
func normaliserDomaine(domaine string) string {
	domaine = strings.ToLower(strings.TrimSpace(domaine))
	return strings.TrimSuffix(domaine, ".")
}

// estDomainePrive reports whether the domain is the internal one.
//
// WHY A COPY OF internal/ingress's rule AND NOT AN IMPORT: the ingress package
// imports this one's eventual module, and a mail check that depended on the
// ingress would tie the prerequisites of the mail to the implementation of the
// proxy. The rule is one line and is asserted by a test here; if the ingress
// changes its definition of "private", the two must be changed together, and
// the test in internal/mail says so.
func estDomainePrive(domaine string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(domaine)), ".local")
}

// lireAdressePubliee reads the address other hosts see for this platform.
func lireAdressePubliee(ctx context.Context) (publicip.Adresse, bool, error) {
	client, err := clientK8s()
	if err != nil {
		return publicip.Adresse{}, false, fmt.Errorf("cluster access: %w", err)
	}
	return publicip.Lire(ctx, client.Kubernetes())
}

// adressePublique returns the published IPv4 address, or why it is unknown.
func (c *contexteChecks) adressePublique() (string, bool, string) {
	switch {
	case c.errIP != nil:
		return "", false, fmt.Sprintf("the platform's public address could not be read: %v", c.errIP)
	case !c.ipConnue || strings.TrimSpace(c.adresse.IPv4) == "":
		return "", false, "no public address is published for the platform yet"
	}
	return strings.TrimSpace(c.adresse.IPv4), true, ""
}

// mentionRelais explains the lighter consequence of a reputation fault when
// outgoing mail leaves through the relay: the server is not the sender.
func (c *contexteChecks) mentionRelais() string {
	if c.reglages.Envoi.Mode == ModeRelais {
		return " (outgoing mail leaves through the relay, so this degrades the server's reputation rather than blocking delivery)"
	}
	return ""
}

// checksSansDomaine answers "there is nothing to check" without pretending the
// checks do not exist.
func checksSansDomaine(motif string) []module.Check {
	identites := []struct{ id, label string }{
		{"mx", "MX record of the domain"},
		{"a-mail", "Address of the mail host"},
		{"ptr", "Reverse DNS of the public address"},
		{"port25-out", "Outgoing port 25"},
		{"relay", "Outbound relay"},
		{"tls", "TLS certificate of the mail host"},
		{"records", "DNS records of the domain"},
		{"inbound-25", "Inbound port 25 on the public address"},
		{"inbound-test", "End-to-end inbound test"},
		{"dnsbl", "Blocklist presence of the public address"},
		{"volume", "Mailbox volume"},
	}
	checks := make([]module.Check, 0, len(identites))
	for _, i := range identites {
		checks = append(checks, res(i.id, i.label, module.CheckNotApplicable, motif, ""))
	}
	return checks
}

// ---------------------------------------------------------------------------
// mx, a-mail, ptr: is the domain routed here, and can the outside find it?
// ---------------------------------------------------------------------------

func verifierMX(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "mx", "MX record of the domain"
	if c.prive {
		return c.resultat(id, label, module.CheckNotApplicable, "private domain: internal delivery only", "")
	}
	mxs, err := c.resolveur.MX(ctx, c.domaine)
	// AN EMPTY MX ANSWER COMES BACK AS NXDOMAIN: Go reports `no such host` both
	// for a domain that does not exist and for a domain that exists with no MX
	// record, so reading the error as "the check could not look" would turn the
	// most ordinary finding — a domain that accepts no mail yet — into a broken
	// verification. Only a real resolver failure keeps the unreadable wording.
	if err != nil && !dnscheck.EstAbsent(err) {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the MX record of %s could not be read: %v", c.domaine, err), "")
	}
	if len(mxs) == 0 {
		return c.resultat(id, label, module.CheckWarning,
			"no MX record: the domain accepts no mail, so the mail server will never receive any",
			fmt.Sprintf("%s. MX 10 %s.", c.domaine, c.hote))
	}
	autres := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		hote := strings.TrimSuffix(mx.Host, ".")
		if strings.EqualFold(hote, c.hote) {
			return c.resultat(id, label, module.CheckOK,
				fmt.Sprintf("%s is routed to the mail server (%s, priority %d)", c.domaine, c.hote, mx.Pref), "")
		}
		// A NULL MX (RFC 7505) is a host of ".": the domain publishes one record
		// to say it accepts NO mail. It is the opposite of "another mail service
		// receives this domain's mail", so it must not be reported as a foreign
		// MX — an operator would go looking for a provider that does not exist.
		if hote == "" || hote == "." {
			continue
		}
		autres = append(autres, fmt.Sprintf("%s (priority %d)", hote, mx.Pref))
	}
	if len(autres) == 0 {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("a null MX record (RFC 7505) tells every sender that %s accepts no mail: the mail server will never receive any", c.domaine),
			fmt.Sprintf("remove the null MX record (0 .) and publish %s. MX 10 %s.", c.domaine, c.hote))
	}
	return c.resultat(id, label, module.CheckBlocking,
		fmt.Sprintf("%s is routed to %s, not to %s: another mail service receives this domain's mail", c.domaine, strings.Join(autres, ", "), c.hote),
		fmt.Sprintf("publish %s. MX 10 %s. (or uninstall the mail module if the domain is handled elsewhere)", c.domaine, c.hote))
}

func verifierAMail(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "a-mail", "Address of the mail host"
	if c.prive {
		return c.resultat(id, label, module.CheckNotApplicable, "private domain: internal delivery only", "")
	}
	ip, connue, motif := c.adressePublique()
	if !connue {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s: the address of %s cannot be compared", motif, c.hote), "")
	}
	fix := fmt.Sprintf("%s. A %s", c.hote, ip)
	adresses, err := c.resolveur.A(ctx, c.hote)
	if err != nil || len(adresses) == 0 {
		detail := fmt.Sprintf("%s has no A record: the outside cannot reach the mail server", c.hote)
		if err != nil && !dnscheck.EstAbsent(err) {
			detail = fmt.Sprintf("%s does not resolve (%v): the outside cannot reach the mail server", c.hote, err)
		}
		return c.resultat(id, label, module.CheckBlocking, detail, fix)
	}
	if !contientAdresse(adresses, ip) {
		return c.resultat(id, label, module.CheckBlocking,
			fmt.Sprintf("%s resolves to %s, not to the platform's public address %s: the mail for this domain goes elsewhere", c.hote, strings.Join(adresses, ", "), ip), fix)
	}
	// AN AAAA RECORD THE PLATFORM DOES NOT SERVE IS A REAL FAILURE MODE: a
	// client that prefers IPv6 tries it first and gives up before IPv4, so mail
	// "works" from some networks and not from others.
	if v6, err := c.resolveur.AAAA(ctx, c.hote); err == nil && len(v6) > 0 {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s resolves to %s, and also to the IPv6 address %s, which the platform does not serve: clients preferring IPv6 will fail to connect", c.hote, ip, strings.Join(v6, ", ")),
			fmt.Sprintf("remove the AAAA record of %s, or make the platform answer on it", c.hote))
	}
	return c.resultat(id, label, module.CheckOK,
		fmt.Sprintf("%s resolves to the platform's public address %s", c.hote, ip), "")
}

func verifierPTR(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "ptr", "Reverse DNS of the public address"
	if c.prive {
		return c.resultat(id, label, module.CheckNotApplicable, "private domain: internal delivery only", "")
	}
	ip, connue, motif := c.adressePublique()
	if !connue {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s: the reverse DNS of the mail host cannot be checked", motif), "")
	}
	// DIRECT DELIVERY MAKES THE PTR A BLOCKING PREREQUISITE: Google and Microsoft
	// refuse mail from an address without one. In relay mode the relay's address
	// is the one being judged, so a missing PTR degrades reputation but does not
	// stop delivery.
	niveau := module.CheckBlocking
	if c.reglages.Envoi.Mode == ModeRelais {
		niveau = module.CheckWarning
	}
	fix := fmt.Sprintf("ask your hosting provider to set the reverse DNS (PTR) of %s to %s", ip, c.hote)
	ptrs, confirme, err := c.resolveur.FCrDNS(ctx, c.hote, ip)
	switch {
	case err != nil && dnscheck.EstAbsent(err) && len(ptrs) == 0:
		// NO REVERSE ZONE ENTRY AT ALL: the resolver answered that the name does
		// not exist, which is the finding, not a reason to report the lookup as
		// unreadable. The `len(ptrs) == 0` guard matters: FCrDNS also fails here
		// when the FORWARD lookup of a matching PTR fails, and that is a missing
		// A record, not a missing PTR.
		return c.resultat(id, label, niveau,
			fmt.Sprintf("the address %s has no reverse DNS: the large receivers refuse mail from an address without one%s", ip, c.mentionRelais()), fix)
	case err != nil && !contientNom(ptrs, c.hote):
		return c.resultat(id, label, niveau,
			fmt.Sprintf("the reverse DNS of %s could not be read (%v): mail servers that require it will refuse the platform's mail%s", ip, err, c.mentionRelais()), fix)
	case err != nil:
		return c.resultat(id, label, niveau,
			fmt.Sprintf("the reverse DNS of %s is %s, but %s does not resolve back to that address (%v)%s", ip, strings.Join(ptrs, ", "), c.hote, err, c.mentionRelais()), fix)
	case confirme:
		return c.resultat(id, label, module.CheckOK,
			fmt.Sprintf("the reverse DNS of %s is %s, and %s resolves back to that address", ip, c.hote, c.hote), "")
	case len(ptrs) == 0:
		return c.resultat(id, label, niveau,
			fmt.Sprintf("the address %s has no reverse DNS: the large receivers refuse mail from an address without one%s", ip, c.mentionRelais()), fix)
	case contientNom(ptrs, c.hote):
		return c.resultat(id, label, niveau,
			fmt.Sprintf("the reverse DNS of %s is %s, but %s does not resolve back to that address: the A record of the mail host is missing or lagging%s", ip, strings.Join(ptrs, ", "), c.hote, c.mentionRelais()), fix)
	default:
		return c.resultat(id, label, niveau,
			fmt.Sprintf("the reverse DNS of %s is %s, not %s: receivers compare the two and refuse the mismatch%s", ip, strings.Join(ptrs, ", "), c.hote, c.mentionRelais()), fix)
	}
}

// ---------------------------------------------------------------------------
// port25-out, relay: can the server send at all?
// ---------------------------------------------------------------------------

func verifierPort25Sortant(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "port25-out", "Outgoing port 25"
	if c.prive {
		return c.resultat(id, label, module.CheckNotApplicable, "private domain: internal delivery only", "")
	}
	if c.reglages.Envoi.Mode == ModeRelais {
		return c.resultat(id, label, module.CheckNotApplicable,
			"outgoing mail leaves through the relay: the server does not connect to port 25 itself", "")
	}
	mxs, err := c.resolveur.MX(ctx, sondeSortie)
	if err != nil || len(mxs) == 0 {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the probe target %s could not be resolved (%s): the outbound path cannot be tested", sondeSortie, motifErreur(err, "no MX record")), "")
	}
	cible := strings.TrimSuffix(mxs[0].Host, ".")
	if !nomHoteValide(cible) {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the probe target resolves to %q, which is not a host name: the outbound path cannot be tested", cible), "")
	}
	sortie, err := executerCommandePod(ctx, scriptPort25Sortant(cible))
	if err != nil {
		// A PROBE THAT CANNOT RUN IS NOT A VERDICT ON THE PORT: reporting it as
		// blocking would tell the operator to open a port that may already be
		// open, and hide the real fault (the pod cannot exec).
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the probe could not run in the mail pod: %v: the outbound path is unknown", err), "")
	}
	if strings.Contains(sortie, "OUVERT") {
		return c.resultat(id, label, module.CheckOK,
			fmt.Sprintf("the mail server reaches %s on port 25: direct delivery can work", cible), "")
	}
	return c.resultat(id, label, module.CheckBlocking,
		fmt.Sprintf("the mail server cannot reach %s on port 25: most hosting providers filter it, and direct delivery then fails silently", cible),
		"open outbound port 25 at your hosting provider, or configure a relay in the mail module settings and switch the send mode to relais")
}

// scriptPort25Sortant is the pod-side probe. There is no `nc` in the image, and
// bash's /dev/tcp is the one client that needs nothing installed. The exit status
// is turned into a WORD so the caller reads one line; `timeout` bounds a
// connection that hangs, which is the common shape of a filtered port.
func scriptPort25Sortant(hote string) string {
	return fmt.Sprintf("timeout 10 bash -c 'exec 3<>/dev/tcp/%s/25' 2>/dev/null && echo OUVERT || echo FERME", hote)
}

func verifierRelais(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "relay", "Outbound relay"
	if c.reglages.Envoi.Mode != ModeRelais {
		return c.resultat(id, label, module.CheckNotApplicable,
			"outgoing mail is delivered directly: there is no relay to check", "")
	}
	if err := c.reglages.Envoi.Valider(); err != nil {
		return c.resultat(id, label, module.CheckBlocking,
			fmt.Sprintf("the relay settings are incomplete: %v", err), "")
	}
	ok, detail := verifierRelaisSMTP(ctx, c.reglages.Envoi)
	if ok {
		return c.resultat(id, label, module.CheckOK,
			fmt.Sprintf("the relay %s:%d accepted the session: %s", c.reglages.Envoi.Hote, c.reglages.Envoi.Port, detail), "")
	}
	return c.resultat(id, label, module.CheckBlocking,
		fmt.Sprintf("the relay %s:%d refused: %s", c.reglages.Envoi.Hote, c.reglages.Envoi.Port, detail),
		"check the relay host, port, username and password in the mail module settings")
}

// verifierRelaisSMTP opens an SMTP session on the relay and authenticates when
// a username is set.
//
// WHY IT IS COPIED FROM internal/modules/mail: that package imports this one, so
// importing its helper back would be an import cycle. The dialogue is the same
// one the module uses before writing the route, and the two must be changed
// together — the test here asserts the strings the module's operator already
// sees.
func verifierRelaisSMTP(ctx context.Context, e Envoi) (bool, string) {
	if e.Hote == "" {
		return false, "no relay host given"
	}
	client, arret := ouvrirSessionSMTP(ctx, e.Hote, e.Port)
	if arret != "" {
		return false, arret
	}
	defer client.Close()
	if e.Utilisateur == "" {
		return true, "the relay answered and no username was given"
	}
	if ok, _ := client.Extension("AUTH"); !ok {
		return false, "the relay offers no authentication while a username was given"
	}
	if err := client.Auth(smtp.PlainAuth("", e.Utilisateur, e.MotDePasse, e.Hote)); err != nil {
		return false, "authentication refused by " + e.Hote + ": " + err.Error()
	}
	return true, "authenticated as " + e.Utilisateur
}

// ouvrirSessionSMTP connects, speaks EHLO, and upgrades with STARTTLS when the
// relay offers it. The returned string is the reason when the session cannot be
// opened; the client must be closed by the caller.
func ouvrirSessionSMTP(ctx context.Context, hote string, port int) (*smtp.Client, string) {
	adresse := net.JoinHostPort(hote, strconv.Itoa(port))
	conn, err := dialTCP(ctx, adresse)
	if err != nil {
		return nil, "cannot reach " + adresse + ": " + err.Error()
	}
	borner(ctx, conn)
	client, err := smtp.NewClient(conn, hote)
	if err != nil {
		conn.Close()
		return nil, "SMTP handshake with " + hote + " failed: " + err.Error()
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: hote}); err != nil {
			client.Close()
			return nil, "STARTTLS with " + hote + " failed: " + err.Error()
		}
	}
	return client, ""
}

// ---------------------------------------------------------------------------
// tls: the certificate the mail host presents
// ---------------------------------------------------------------------------

// portPostal is one TLS port of the mail layer.
type portPostal struct {
	Port      int
	Implicite bool // implicit TLS (SMTPS/IMAPS) rather than STARTTLS
	Libelle   string
}

// portsTLS lists the ports the check probes.
//
// THE INTERNAL SERVICE PUBLISHES ALL THREE, whatever the exposure setting of
// the public one (portsService does not depend on `clients_externes`): the
// certificate can therefore be verified without depending on a setting the
// operator has not touched yet, which is what makes the check useful BEFORE
// mail clients are opened to the outside.
var portsTLS = []portPostal{
	{Port: 25, Implicite: false, Libelle: "STARTTLS on port 25"},
	{Port: 465, Implicite: true, Libelle: "implicit TLS on port 465"},
	{Port: 993, Implicite: true, Libelle: "implicit TLS on port 993"},
}

// adresseServiceMail returns the cluster address of the mail Service.
func adresseServiceMail(ctx context.Context) (string, error) {
	client, err := clientK8s()
	if err != nil {
		return "", fmt.Errorf("cluster access: %w", err)
	}
	svc, err := client.Kubernetes().CoreV1().Services(ns).Get(ctx, serviceMail, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("reading the mail Service %s/%s: %w", ns, serviceMail, err)
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return "", fmt.Errorf("the mail Service %s/%s has no cluster address", ns, serviceMail)
	}
	return svc.Spec.ClusterIP, nil
}

func verifierTLS(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "tls", "TLS certificate of the mail host"
	adresse, err := adresseServiceMail(ctx)
	if err != nil {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the mail Service cannot be reached to read its certificate: %v", err), "")
	}
	utilisables := make([]string, 0, len(portsTLS))
	problemes := make([]string, 0, len(portsTLS))
	for _, p := range portsTLS {
		detail, probleme := controlerTLS(ctx, c.hote, adresse, p)
		if probleme != "" {
			problemes = append(problemes, probleme)
			continue
		}
		utilisables = append(utilisables, detail)
	}
	if len(problemes) > 0 {
		return c.resultat(id, label, module.CheckBlocking,
			fmt.Sprintf("the certificate presented for %s is not usable: %s", c.hote, strings.Join(problemes, "; ")),
			fmt.Sprintf("serve the platform certificate on the mail host, then re-run the mail deployment: ceffio mail --domain %s", c.domaine))
	}
	return c.resultat(id, label, module.CheckOK,
		fmt.Sprintf("the certificate presented for %s covers it on every port and is valid (%s)", c.hote, strings.Join(utilisables, ", ")), "")
}

// controlerTLS reads the certificate of one port and judges it against the host
// name the MX points at. It returns the human detail, or the problem.
func controlerTLS(ctx context.Context, hote, adresse string, p portPostal) (string, string) {
	cert, err := certificatServi(ctx, net.JoinHostPort(adresse, strconv.Itoa(p.Port)), hote, p.Implicite)
	if err != nil {
		return "", fmt.Sprintf("%s: %v", p.Libelle, err)
	}
	if cert == nil {
		return "", fmt.Sprintf("%s: no certificate was presented", p.Libelle)
	}
	noms := nomsCertificat(cert)
	expire := cert.NotAfter.UTC().Format("2006-01-02")
	switch {
	case estAutoSigne(cert) && !couvreHote(noms, hote):
		// THE SELF-SIGNED CASE IS NAMED, not reported as "invalid": Stalwart ships
		// exactly this certificate (`CN=rcgen self signed cert`, SAN localhost)
		// when the `mail-tls` Secret has not been installed into its store, and
		// the operator's action is specific — not "renew the certificate".
		return "", fmt.Sprintf("%s: the server still presents its built-in self-signed certificate (%s), which does not cover %s", p.Libelle, nomsAffichables(noms), hote)
	case !couvreHote(noms, hote):
		return "", fmt.Sprintf("%s: the certificate covers %s, not %s", p.Libelle, nomsAffichables(noms), hote)
	case time.Now().After(cert.NotAfter):
		return "", fmt.Sprintf("%s: the certificate expired on %s", p.Libelle, expire)
	case cert.NotAfter.Sub(time.Now()) < 14*24*time.Hour:
		// cert-manager renews 30 days before expiry; under two weeks left means the
		// renewal itself is failing, which is a blocking condition in sight.
		return "", fmt.Sprintf("%s: the certificate expires on %s, less than two weeks away: its renewal is failing", p.Libelle, expire)
	}
	return fmt.Sprintf("%s (until %s)", p.Libelle, expire), ""
}

// certificatServiReel opens a session on one port and returns the leaf
// certificate, WITHOUT validating it: the check does its own validation so it
// can report WHY the certificate is wrong (self-signed, wrong name, expiring)
// instead of Go's single generic verification error.
func certificatServiReel(ctx context.Context, adresse, hote string, implicite bool) (*x509.Certificate, error) {
	conn, err := dialTCP(ctx, adresse)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	borner(ctx, conn)
	if implicite {
		client := tls.Client(conn, &tls.Config{ServerName: hote, InsecureSkipVerify: true})
		if err := client.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return premierCertificat(client.ConnectionState()), nil
	}
	client, err := negocierStartTLS(conn, hote)
	if err != nil {
		return nil, err
	}
	if err := client.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return premierCertificat(client.ConnectionState()), nil
}

// negocierStartTLS reads the banner, negotiates EHLO and STARTTLS by hand.
//
// WHY NOT net/smtp: smtp.Client exposes no TLS connection state, so the
// certificate it validated cannot be inspected — and the whole point of this
// check is to say what the certificate IS. The dialogue is the minimum: a
// conforming server sends nothing after the `220` that accepts STARTTLS, so the
// buffered reader is left with nothing before the handshake starts (asserted).
func negocierStartTLS(conn net.Conn, hote string) (*tls.Conn, error) {
	br := bufio.NewReader(conn)
	lire := func() (string, error) {
		ligne, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimRight(ligne, "\r\n"), nil
	}
	banniere, err := lire()
	if err != nil {
		return nil, fmt.Errorf("no SMTP banner: %v", err)
	}
	if !strings.HasPrefix(banniere, "220") {
		return nil, fmt.Errorf("unexpected SMTP banner: %s", banniere)
	}
	// THE EHLO ARGUMENT MUST BE A DOMAIN, NOT A LABEL: Stalwart (like Postfix)
	// rejects `EHLO ceffio-checks` with `550 5.5.0 Invalid EHLO domain`, so a
	// fixed placeholder made every STARTTLS probe fail at the greeting. The
	// host being probed is a real FQDN, and it is the name the certificate will
	// be judged against anyway.
	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", hote); err != nil {
		return nil, err
	}
	offre := false
	for {
		ligne, err := lire()
		if err != nil {
			return nil, fmt.Errorf("EHLO negotiation: %v", err)
		}
		if !strings.HasPrefix(ligne, "250") {
			return nil, fmt.Errorf("EHLO refused: %s", ligne)
		}
		if len(ligne) > 4 && strings.EqualFold(strings.TrimSpace(ligne[4:]), "STARTTLS") {
			offre = true
		}
		if len(ligne) == 3 || ligne[3] == ' ' {
			break
		}
	}
	if !offre {
		return nil, errors.New("the server does not offer STARTTLS")
	}
	if _, err := fmt.Fprint(conn, "STARTTLS\r\n"); err != nil {
		return nil, err
	}
	reponse, err := lire()
	if err != nil {
		return nil, fmt.Errorf("STARTTLS: %v", err)
	}
	if !strings.HasPrefix(reponse, "220") {
		return nil, fmt.Errorf("STARTTLS refused: %s", reponse)
	}
	if br.Buffered() > 0 {
		return nil, errors.New("the server sent data before the TLS handshake")
	}
	return tls.Client(conn, &tls.Config{ServerName: hote, InsecureSkipVerify: true}), nil
}

// premierCertificat returns the leaf of a TLS connection, or nil.
func premierCertificat(etat tls.ConnectionState) *x509.Certificate {
	if len(etat.PeerCertificates) == 0 {
		return nil
	}
	return etat.PeerCertificates[0]
}

// nomsCertificat lists the names a certificate claims. A certificate with SANs
// is judged on its SANs only — the CN is ignored by every current validator, and
// reporting it would say "covered" for a certificate browsers refuse.
func nomsCertificat(cert *x509.Certificate) []string {
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames
	}
	if cert.Subject.CommonName != "" {
		return []string{cert.Subject.CommonName}
	}
	return nil
}

// nomsAffichables renders the names of a certificate for a Detail.
func nomsAffichables(noms []string) string {
	if len(noms) == 0 {
		return "no DNS name"
	}
	return strings.Join(noms, ", ")
}

// estAutoSigne reports whether the certificate was issued by itself.
func estAutoSigne(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// ---------------------------------------------------------------------------
// records: is what the server expects actually published?
// ---------------------------------------------------------------------------

// WHY THE ZONE FILE AND NOT A HARDCODED LIST OF RECORDS: Stalwart generates the
// records it expects in its own zone file (`x:Domain/get`, field `dnsZoneFile`),
// including one DKIM key per active selector. Hardcoding "v=spf1 …", one
// selector and one MTA-STS policy would drift the day a selector is rotated: the
// check would then demand a record the server does not use, and the operator
// would publish a key no message is signed with. Comparing the public DNS with
// the server's own view also answers the question the operator actually has —
// "is what the server expects published?" — instead of a neighbouring one.
//
// The parser below is deliberately tolerant. No sample of the generated file
// exists in this repository (the POC never captured one), so it accepts what
// BIND accepts: $ORIGIN/$TTL, relative and absolute owners, `@`, blank owners
// continuing the previous name, parentheses, `;` comments and quoted TXT split
// in several character-strings.

// enregistrementZone is one record of the zone file.
type enregistrementZone struct {
	Nom    string   // absolute owner, lower-case, no trailing dot
	Type   string   // upper-case record type
	Champs []string // rdata; TXT chunks are decoded, names are absolute with a dot
}

// Valeur is the TXT content a resolver returns for this record: Go's LookupTXT
// concatenates the character-strings of one record, so the expected value must
// be the concatenation too.
func (e enregistrementZone) Valeur() string { return strings.Join(e.Champs, "") }

// ligneZone renders the record as a line ready to paste in a zone file.
func (e enregistrementZone) ligneZone() string {
	if e.Type != "TXT" {
		return e.Nom + ". IN " + e.Type + " " + strings.Join(e.Champs, " ")
	}
	citations := make([]string, 0, len(e.Champs))
	for _, morceau := range e.Champs {
		citations = append(citations, `"`+morceau+`"`)
	}
	return e.Nom + ". IN TXT " + strings.Join(citations, " ")
}

// typesZone are the record types the parser keeps. An unknown token is skipped
// rather than taken for a type: the zone file is external input.
var typesZone = map[string]bool{
	"A": true, "AAAA": true, "CAA": true, "CNAME": true, "DNAME": true,
	"MX": true, "NS": true, "PTR": true, "SOA": true, "SRV": true,
	"SSHFP": true, "TLSA": true, "TXT": true,
}

// classesZone are the class names a zone file can carry.
var classesZone = map[string]bool{"IN": true, "CH": true, "HS": true, "CS": true}

// lireZone parses a zone file for `domaine` and returns its records.
func lireZone(zone, domaine string) []enregistrementZone {
	racine := normaliserDomaine(domaine) + "."
	origine := racine
	proprietaire := "" // last owner, absolute with its trailing dot
	sortie := make([]enregistrementZone, 0, 32)

	var courant strings.Builder
	profondeur := 0
	sansProprietaire := false
	lignes := strings.Split(strings.ReplaceAll(zone, "\r\n", "\n"), "\n")
	for _, ligne := range lignes {
		if profondeur == 0 {
			courant.Reset()
			sansProprietaire = len(ligne) > 0 && (ligne[0] == ' ' || ligne[0] == '\t')
		}
		morceau, delta := nettoyerLigne(ligne)
		if profondeur > 0 {
			courant.WriteByte(' ')
		}
		courant.WriteString(morceau)
		profondeur += delta
		if profondeur > 0 {
			continue
		}
		jetons := decouper(strings.TrimSpace(courant.String()))
		if len(jetons) == 0 {
			continue
		}
		if strings.HasPrefix(jetons[0], "$") {
			if strings.EqualFold(jetons[0], "$ORIGIN") && len(jetons) > 1 {
				origine = absolutiser(jetons[1], racine)
			}
			continue
		}
		i := 0
		if sansProprietaire {
			// A line starting with white space belongs to the previous owner.
			if proprietaire == "" {
				continue
			}
		} else {
			proprietaire = absolutiser(jetons[0], origine)
			i = 1
		}
		for i < len(jetons) && (estTTL(jetons[i]) || classesZone[strings.ToUpper(jetons[i])]) {
			i++
		}
		if i >= len(jetons) {
			continue
		}
		genre := strings.ToUpper(jetons[i])
		if !typesZone[genre] {
			continue
		}
		rdata := append([]string(nil), jetons[i+1:]...)
		enr := enregistrementZone{Nom: strings.TrimSuffix(strings.ToLower(proprietaire), "."), Type: genre}
		switch genre {
		case "TXT":
			enr.Champs = rdata
		case "CNAME", "NS", "DNAME", "PTR":
			if len(rdata) == 1 {
				enr.Champs = []string{absolutiser(rdata[0], origine)}
			}
		case "MX":
			if len(rdata) == 2 {
				enr.Champs = []string{rdata[0], absolutiser(rdata[1], origine)}
			}
		case "SRV":
			if len(rdata) == 4 {
				enr.Champs = []string{rdata[0], rdata[1], rdata[2], absolutiser(rdata[3], origine)}
			}
		default:
			enr.Champs = rdata
		}
		sortie = append(sortie, enr)
	}
	return sortie
}

// nettoyerLigne strips a `;` comment (outside quotes) and reports the net
// parenthesis nesting of what remains.
func nettoyerLigne(ligne string) (string, int) {
	var b strings.Builder
	dansGuillemets, echappe := false, false
	delta := 0
	for _, r := range ligne {
		switch {
		case echappe:
			echappe = false
			b.WriteRune(r)
		case dansGuillemets && r == '\\':
			echappe = true
			b.WriteRune(r)
		case r == '"':
			dansGuillemets = !dansGuillemets
			b.WriteRune(r)
		case !dansGuillemets && r == ';':
			return b.String(), delta
		case !dansGuillemets && r == '(':
			delta++
			b.WriteRune(' ')
		case !dansGuillemets && r == ')':
			delta--
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), delta
}

// decouper splits one logical line into tokens, decoding quoted strings so a TXT
// chunk reaches the comparison as the resolver will return it.
func decouper(texte string) []string {
	jetons := make([]string, 0, 8)
	var courant strings.Builder
	dansGuillemets, echappe, ouvert := false, false, false

	terminer := func() {
		if ouvert {
			jetons = append(jetons, courant.String())
			courant.Reset()
			ouvert = false
		}
	}
	for _, r := range texte {
		switch {
		case echappe:
			echappe = false
			courant.WriteRune(r)
			ouvert = true
		case r == '\\':
			echappe = true
			ouvert = true
		case r == '"':
			dansGuillemets = !dansGuillemets
			ouvert = true
		case !dansGuillemets && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			terminer()
		default:
			courant.WriteRune(r)
			ouvert = true
		}
	}
	terminer()
	return jetons
}

// absolutiser resolves a zone name against the current origin.
func absolutiser(nom, origine string) string {
	nom = strings.ToLower(strings.TrimSpace(nom))
	if nom == "@" {
		return origine
	}
	if strings.HasSuffix(nom, ".") {
		return nom
	}
	racine := strings.TrimSuffix(origine, ".")
	if nom == racine || strings.HasSuffix(nom, "."+racine) {
		return nom + "."
	}
	if origine == "" || origine == "." {
		return nom + "."
	}
	return nom + "." + origine
}

// estTTL reports whether a token is a TTL: digits, optionally suffixed with a
// unit (600, 1h, 2d…).
func estTTL(jeton string) bool {
	if jeton == "" {
		return false
	}
	dernier := jeton[len(jeton)-1]
	if dernier >= '0' && dernier <= '9' {
		for i := 0; i < len(jeton); i++ {
			if jeton[i] < '0' || jeton[i] > '9' {
				return false
			}
		}
		return true
	}
	switch dernier {
	case 's', 'S', 'm', 'M', 'h', 'H', 'd', 'D', 'w', 'W':
	default:
		return false
	}
	if len(jeton) < 2 {
		return false
	}
	for i := 0; i < len(jeton)-1; i++ {
		if jeton[i] < '0' || jeton[i] > '9' {
			return false
		}
	}
	return true
}

// valeurAttendue is one record the zone file declares: what must be published.
type valeurAttendue struct {
	Genre   string // TXT, CNAME, A or SRV
	Nom     string // the name to look up (absolute, no trailing dot)
	Valeur  string // TXT content, CNAME target or address
	Service string // SRV only: _imaps, _jmap…
	Proto   string // SRV only
	Cible   string // SRV only: target host, no trailing dot
	Port    int    // SRV only
	Prio    int    // SRV only
	Poids   int    // SRV only
	Ligne   string // the zone-file line offered as the Fix
}

// famille is one `records-<x>` check: a group of records sharing a purpose.
type famille struct {
	ID       string
	Label    string
	Requise  bool // the server itself creates this family: absent = warning
	Attendus []valeurAttendue
}

func verifierRecords(ctx context.Context, c *contexteChecks) []module.Check {
	const id, label = "records", "DNS records of the domain"
	if c.prive {
		return []module.Check{c.resultat(id, label, module.CheckNotApplicable, "private domain: internal delivery only", "")}
	}
	zone, err := lireZoneDNS(ctx, c.domaine)
	switch {
	case err != nil:
		return []module.Check{c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the mail server's zone file for %s could not be read (%v): the expected records are unknown", c.domaine, err), "")}
	case strings.TrimSpace(zone) == "":
		return []module.Check{c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the mail server generated no zone file for %s: no record can be compared", c.domaine), "")}
	}
	records := lireZone(zone, c.domaine)
	if len(records) == 0 {
		return []module.Check{c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the zone file of %s parsed to no record: no expected record is known", c.domaine), "")}
	}
	familles := famillesPour(records, c)
	checks := make([]module.Check, 0, len(familles)+1)
	var problemes []string
	for _, f := range familles {
		check := verifierFamille(ctx, c, f)
		if check.Level == module.CheckWarning {
			problemes = append(problemes, f.Label)
		}
		checks = append(checks, check)
	}
	resume := res(id, label, module.CheckOK,
		fmt.Sprintf("%d records are published as the mail server expects them", len(records)), "")
	if len(problemes) > 0 {
		resume = res(id, label, module.CheckWarning,
			fmt.Sprintf("the public DNS does not match the zone file of %s: %s", c.domaine, strings.Join(problemes, ", ")),
			"publish the records given by the `records-*` checks below")
	}
	return append([]module.Check{resume}, checks...)
}

// famillesPour groups the zone file's records by purpose, in the order of the
// plan.
func famillesPour(records []enregistrementZone, c *contexteChecks) []famille {
	domaine := c.domaine
	var familles []famille

	// SPF: the v=spf1 record of the domain itself.
	var spf []enregistrementZone
	for _, r := range records {
		if r.Type != "TXT" || r.Nom != domaine {
			continue
		}
		if strings.HasPrefix(strings.ToLower(r.Valeur()), "v=spf1") {
			spf = append(spf, r)
		}
	}
	familles = append(familles, famille{ID: "records-spf", Label: "SPF record", Requise: true,
		Attendus: attendusTXT(spf)})

	// DKIM: one key per ACTIVE selector — the zone declares exactly those.
	suffixeDKIM := "._domainkey." + domaine
	var dkim []enregistrementZone
	for _, r := range records {
		if r.Type == "TXT" && strings.HasSuffix(r.Nom, suffixeDKIM) {
			dkim = append(dkim, r)
		}
	}
	familles = append(familles, famille{ID: "records-dkim", Label: "DKIM records", Requise: true,
		Attendus: attendusTXT(dkim)})

	// DMARC.
	familles = append(familles, famille{ID: "records-dmarc", Label: "DMARC record", Requise: true,
		Attendus: attendusTXT(avecNom(records, "_dmarc."+domaine, "TXT"))})

	// MTA-STS: a TXT policy pointer and, when declared, the CNAME that serves
	// the policy file.
	familles = append(familles, famille{ID: "records-mta-sts", Label: "MTA-STS records",
		Attendus: append(
			attendusTXT(avecNom(records, "_mta-sts."+domaine, "TXT")),
			attendusCNAME(avecNom(records, "mta-sts."+domaine, "CNAME"))...,
		)})

	// TLS-RPT.
	familles = append(familles, famille{ID: "records-tls-rpt", Label: "TLS-RPT record",
		Attendus: attendusTXT(avecNom(records, "_smtp._tls."+domaine, "TXT"))})

	// Autoconfiguration: whatever the zone declares at the two well-known names.
	var autoconfig []enregistrementZone
	for _, r := range records {
		if r.Nom == "autoconfig."+domaine || r.Nom == "autodiscover."+domaine {
			autoconfig = append(autoconfig, r)
		}
	}
	familles = append(familles, famille{ID: "records-autoconfig", Label: "Autoconfiguration records",
		Attendus: attendusSimples(autoconfig)})

	// SRV: the discovery records. The IMAP/SMTP ones only make sense when mail
	// clients are opened to the outside, so they are skipped otherwise — a record
	// pointing at a port the public Service does not expose would send a client
	// to a closed door.
	familles = append(familles, famille{ID: "records-srv", Label: "SRV records",
		Attendus: attendusSRV(records, domaine, c.reglages.ClientsExternes)})

	return familles
}

// avecNom filters the records of one exact name and type.
func avecNom(records []enregistrementZone, nom, genre string) []enregistrementZone {
	var out []enregistrementZone
	for _, r := range records {
		if r.Type == genre && strings.EqualFold(r.Nom, nom) {
			out = append(out, r)
		}
	}
	return out
}

// attendusTXT turns TXT records into expected values.
func attendusTXT(records []enregistrementZone) []valeurAttendue {
	out := make([]valeurAttendue, 0, len(records))
	for _, r := range records {
		out = append(out, valeurAttendue{Genre: "TXT", Nom: r.Nom, Valeur: r.Valeur(), Ligne: r.ligneZone()})
	}
	return out
}

// attendusCNAME turns CNAME records into expected values.
func attendusCNAME(records []enregistrementZone) []valeurAttendue {
	out := make([]valeurAttendue, 0, len(records))
	for _, r := range records {
		if len(r.Champs) != 1 {
			continue
		}
		out = append(out, valeurAttendue{Genre: "CNAME", Nom: r.Nom, Valeur: strings.TrimSuffix(r.Champs[0], "."), Ligne: r.ligneZone()})
	}
	return out
}

// attendusSimples turns TXT/CNAME/A records into expected values.
func attendusSimples(records []enregistrementZone) []valeurAttendue {
	var out []valeurAttendue
	for _, r := range records {
		switch r.Type {
		case "TXT":
			out = append(out, valeurAttendue{Genre: "TXT", Nom: r.Nom, Valeur: r.Valeur(), Ligne: r.ligneZone()})
		case "CNAME":
			out = append(out, attendusCNAME([]enregistrementZone{r})...)
		case "A":
			if len(r.Champs) == 1 {
				out = append(out, valeurAttendue{Genre: "A", Nom: r.Nom, Valeur: r.Champs[0], Ligne: r.ligneZone()})
			}
		}
	}
	return out
}

// attendusSRV turns the SRV records of the discovery names into expected values.
func attendusSRV(records []enregistrementZone, domaine string, clientsExternes bool) []valeurAttendue {
	autorises := []string{"_caldavs", "_carddavs", "_jmap"}
	if clientsExternes {
		autorises = append(autorises, "_imaps", "_submissions")
	}
	out := make([]valeurAttendue, 0, 4)
	for _, r := range records {
		if r.Type != "SRV" || len(r.Champs) != 4 {
			continue
		}
		service, proto, ok := decouperProprietaireSRV(r.Nom, domaine)
		if !ok || !contientMot(autorises, service) {
			continue
		}
		prio, err1 := strconv.Atoi(r.Champs[0])
		poids, err2 := strconv.Atoi(r.Champs[1])
		port, err3 := strconv.Atoi(r.Champs[2])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out = append(out, valeurAttendue{
			Genre: "SRV", Service: service, Proto: proto, Nom: domaine,
			Prio: prio, Poids: poids, Port: port,
			Cible: strings.TrimSuffix(r.Champs[3], "."), Ligne: r.ligneZone(),
		})
	}
	return out
}

// decouperProprietaireSRV turns `_imaps._tcp.example.com` into `_imaps`, `tcp`.
func decouperProprietaireSRV(nom, domaine string) (string, string, bool) {
	suffixe := "." + domaine
	if !strings.HasSuffix(nom, suffixe) {
		return "", "", false
	}
	morceaux := strings.Split(strings.TrimSuffix(nom, suffixe), ".")
	if len(morceaux) != 2 {
		return "", "", false
	}
	return strings.ToLower(morceaux[0]), strings.ToLower(strings.TrimPrefix(morceaux[1], "_")), true
}

// verifierFamille compares one family of expected records with the public DNS.
func verifierFamille(ctx context.Context, c *contexteChecks, f famille) module.Check {
	if len(f.Attendus) == 0 {
		if f.Requise {
			return c.resultat(f.ID, f.Label, module.CheckWarning,
				fmt.Sprintf("the mail server's zone file declares no %s record: mail from %s is not authenticated on this axis", f.Label, c.domaine),
				"")
		}
		return c.resultat(f.ID, f.Label, module.CheckOK,
			fmt.Sprintf("the mail server declares no %s: nothing to publish", f.Label), "")
	}
	manquants := make([]string, 0, len(f.Attendus))
	fixes := make([]string, 0, len(f.Attendus))
	for _, a := range f.Attendus {
		fixes = append(fixes, a.Ligne)
		if motif := manque(ctx, c, a); motif != "" {
			manquants = append(manquants, motif)
		}
	}
	// IN RELAY MODE THE SPF RECORD IS INCOMPLETE EVEN WHEN IT MATCHES THE ZONE:
	// the zone file describes the server's own delivery, while the outside world
	// receives the mail from the relay's addresses. The include: mechanism is
	// the provider's, so it cannot be guessed here: the Fix says it is missing
	// and where to find it.
	if f.ID == "records-spf" && c.reglages.Envoi.Mode == ModeRelais {
		fixes = append(fixes, "in relay mode, also append the relay provider's include: mechanism to the SPF record (the zone file only describes direct delivery)")
	}
	if len(manquants) > 0 {
		return c.resultat(f.ID, f.Label, module.CheckWarning,
			fmt.Sprintf("%d of the %d record(s) the mail server expects are not published: %s", len(manquants), len(f.Attendus), strings.Join(manquants, "; ")),
			strings.Join(fixes, "\n"))
	}
	return c.resultat(f.ID, f.Label, module.CheckOK,
		fmt.Sprintf("the %d %s record(s) are published as the mail server expects", len(f.Attendus), f.Label), "")
}

// manque returns why one expected record is not published, or "" when it is.
//
// AN ABSENT NAME IS A FINDING, NOT A FAILURE TO LOOK: `dnscheck.EstAbsent`
// separates "the zone publishes nothing for this name" from "the resolver did
// not answer". Both used to read "not readable (…no such host)", which told the
// operator to check the network when the zone was simply missing the record.
// Only a genuine lookup failure keeps that wording.
func manque(ctx context.Context, c *contexteChecks, a valeurAttendue) string {
	switch a.Genre {
	case "TXT":
		valeurs, err := c.resolveur.TXT(ctx, a.Nom)
		if err != nil && !dnscheck.EstAbsent(err) {
			return fmt.Sprintf("%s: not readable (%v)", a.Nom, err)
		}
		for _, v := range valeurs {
			if strings.TrimSpace(v) == strings.TrimSpace(a.Valeur) {
				return ""
			}
		}
		return fmt.Sprintf("%s: no TXT record %q", a.Nom, a.Valeur)
	case "CNAME":
		actuel, err := c.resolveur.CNAME(ctx, a.Nom)
		if err != nil && !dnscheck.EstAbsent(err) {
			return fmt.Sprintf("%s: not readable (%v)", a.Nom, err)
		}
		// THE GO RESOLVER ANSWERS WITH THE NAME ITSELF when the name is not an
		// alias, and with an empty string does it never answer: a name that
		// CNAMEs to itself is indistinguishable from a name without a CNAME.
		// Comparing the two is what tells "no alias" from "the wrong alias".
		actuel = strings.TrimSuffix(actuel, ".")
		if actuel != "" && !strings.EqualFold(actuel, a.Nom) && strings.EqualFold(actuel, a.Valeur) {
			return ""
		}
		if actuel == "" || strings.EqualFold(actuel, a.Nom) {
			return fmt.Sprintf("%s: no CNAME record pointing to %s", a.Nom, a.Valeur)
		}
		return fmt.Sprintf("%s: points to %s, expected %s", a.Nom, actuel, a.Valeur)
	case "A":
		adresses, err := c.resolveur.A(ctx, a.Nom)
		if err != nil || !contientAdresse(adresses, a.Valeur) {
			return fmt.Sprintf("%s: no A record %s", a.Nom, a.Valeur)
		}
		return ""
	case "SRV":
		// THE LEADING UNDERSCORE BELONGS TO THE DISPLAY NAME ONLY: Go prepends
		// `_` to the service itself, so passing `_imaps` here made every query
		// ask for `__imaps._tcp.<domain>` — a name no zone ever publishes.
		enregistrements, err := c.resolveur.SRV(ctx, strings.TrimPrefix(a.Service, "_"), a.Proto, a.Nom)
		if err != nil && !dnscheck.EstAbsent(err) {
			return fmt.Sprintf("%s._%s.%s: not readable (%v)", a.Service, a.Proto, a.Nom, err)
		}
		for _, enr := range enregistrements {
			if enr.Priority == uint16(a.Prio) && enr.Weight == uint16(a.Poids) && enr.Port == uint16(a.Port) &&
				strings.EqualFold(strings.TrimSuffix(enr.Target, "."), a.Cible) {
				return ""
			}
		}
		return fmt.Sprintf("%s._%s.%s: no SRV record to %s:%d", a.Service, a.Proto, a.Nom, a.Cible, a.Port)
	}
	return ""
}

// lireZoneDNSServeur reads the zone file Stalwart generates for one domain.
func lireZoneDNSServeur(ctx context.Context, domaine string) (string, error) {
	corps, err := appelServeurJMAP(ctx, "x:Domain/get", map[string]any{
		"ids":        nil,
		"properties": []string{"name", "dnsZoneFile"},
	})
	if err != nil {
		return "", err
	}
	for _, e := range listeDe(corps, "list") {
		entree, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(normaliserDomaine(valeurChaine(entree["name"])), domaine) {
			return valeurChaine(entree["dnsZoneFile"]), nil
		}
	}
	return "", fmt.Errorf("the mail server declares no domain %q", domaine)
}

// ---------------------------------------------------------------------------
// inbound-25, inbound-test: does mail actually arrive?
// ---------------------------------------------------------------------------

func verifierEntrant25(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "inbound-25", "Inbound port 25 on the public address"
	if c.prive {
		return c.resultat(id, label, module.CheckNotApplicable, "private domain: internal delivery only", "")
	}
	ip, connue, motif := c.adressePublique()
	if !connue {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s: inbound port 25 cannot be tested", motif), "")
	}
	// THE CONNECTION IS MADE FROM HERE, NOT FROM THE POD: a pod that dials the
	// platform's public address goes out through the node, and many clusters
	// then hit a NAT loopback that refuses the connection — a false negative on
	// a port that works from every real sender. The checking process is outside
	// that path.
	adresse := net.JoinHostPort(ip, "25")
	conn, err := dialTCP(ctx, adresse)
	if err != nil {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("no connection to %s: the port is filtered or nothing listens there (%v)", adresse, err),
			"open inbound port 25 (hosting firewall, router NAT) and re-run this check")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ligne, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s accepted the connection but sent no SMTP banner (%v)", adresse, err),
			"check that the mail server's SMTP listener answers on port 25")
	}
	if !strings.HasPrefix(strings.TrimSpace(ligne), "220") {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s answered %q instead of an SMTP banner", adresse, strings.TrimSpace(ligne)),
			"check that port 25 reaches the mail server and not another service")
	}
	return c.resultat(id, label, module.CheckOK,
		fmt.Sprintf("%s answers the SMTP banner: the world can reach the mail server", adresse), "")
}

func verifierTestEntrant(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "inbound-test", "End-to-end inbound test"
	if c.prive {
		return c.resultat(id, label, module.CheckNotApplicable, "private domain: internal delivery only", "")
	}
	guide := fmt.Sprintf("send a message to postmaster@%s from an outside mailbox (a phone, a webmail), then re-run this check", c.domaine)
	// THE RECIPIENT IS AN ALIAS, SO "MISSING" HAS ITS OWN FIX: the installation
	// creates postmaster@ as an alias of the admin account (§4.8 step 7), so an
	// operator reading "send a message" as the fix would send mail into a void.
	creer := fmt.Sprintf("create postmaster@%s: the mail module's installation creates it as an alias of the admin account (`ceffio module install mail`), then send a message to it from an outside mailbox and re-run this check", c.domaine)
	compte, err := trouverCompte(ctx, "postmaster@"+c.domaine)
	if err != nil {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the mailboxes could not be listed: %v: the inbound path cannot be verified", err), guide)
	}
	if compte == "" {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("postmaster@%s does not exist on the mail server: the check has no predictable recipient", c.domaine), creer)
	}
	message, err := dernierMessageExterne(ctx, compte, c.domaine)
	if err != nil {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the messages of postmaster@%s could not be read: %v", c.domaine, err), guide)
	}
	if message == nil {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("no message from an outside domain has reached postmaster@%s yet: the inbound path has not been demonstrated", c.domaine), guide)
	}
	expediteur := expediteurDe(message)
	recu := valeurChaine(message["receivedAt"])
	entetes := valeurChaine(message["header:Authentication-Results:asText"])
	verdicts := verdictsAuthentification(entetes)
	if verdicts.vide() {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("a message from %s reached postmaster@%s (%s), but the server reported no Authentication-Results: SPF, DKIM and DMARC are not evaluated", expediteur, c.domaine, recu),
			"check that the domain is declared in the mail server and that the records-* checks pass, then send the test again")
	}
	resume := fmt.Sprintf("SPF %s, DKIM %s, DMARC %s", verdicts.spf(), verdicts.dkim(), verdicts.dmarc())
	if verdicts.authReussie() {
		return c.resultat(id, label, module.CheckOK,
			fmt.Sprintf("the message from %s received on %s is authenticated (%s)", expediteur, recu, resume), "")
	}
	return c.resultat(id, label, module.CheckWarning,
		fmt.Sprintf("the message from %s received on %s is NOT fully authenticated (%s): receivers will mark the platform's mail as suspicious", expediteur, recu, resume),
		"publish the SPF, DKIM and DMARC records (see the records-* checks), then send the test again")
}

// trouverCompte returns the id of the account that receives `adresse`.
//
// AN ADDRESS IS NOT A NAME: `x:Account/get` lists accounts by their login name
// ("adminceffio"), and the mail addresses an account receives are either its
// `emailAddress` or entries of its `aliases` map. Comparing the address with
// the account NAME — as this did — finds nothing even on a correct install,
// because postmaster@<domain> is an alias of the admin account (§4.8 step 7).
// An alias carries a domain IDENTIFIER, not a name, so the domain table is
// required to spell the address out.
func trouverCompte(ctx context.Context, adresse string) (string, error) {
	domaines, err := lireNomsDeDomaines(ctx)
	if err != nil {
		return "", err
	}
	comptes, err := clientJMAP().Get(ctx, "x:Account/get", nil,
		[]string{"id", "name", "emailAddress", "aliases"})
	if err != nil {
		return "", fmt.Errorf("reading the mail accounts: %w", err)
	}
	for _, compte := range comptes {
		id, _ := compte["id"].(string)
		if id == "" {
			continue
		}
		if strings.EqualFold(valeurChaine(compte["emailAddress"]), adresse) {
			return id, nil
		}
		for _, valeur := range aliasParIndex(compte["aliases"]) {
			alias, ok := valeur.(map[string]any)
			if !ok {
				continue
			}
			nom := valeurChaine(alias["name"])
			domaine := domaines[valeurChaine(alias["domainId"])]
			if nom != "" && domaine != "" && strings.EqualFold(nom+"@"+domaine, adresse) {
				return id, nil
			}
		}
	}
	return "", nil
}

// dernierMessageExterne returns the most recent message of the account that came
// from another domain, INBOX or Junk Mail first.
//
// TWO EXCLUSIONS, BOTH MEASURED (§9.F):
//   - a bounce (MAILER-DAEMON) proves the OUTBOUND path, not the inbound one;
//   - a message sent from the domain itself proves nothing either, since it is
//     delivered locally. Neither may be reported as "an outside message arrived".
func dernierMessageExterne(ctx context.Context, compte, domaine string) (map[string]any, error) {
	boites, err := boitesEntrantes(ctx, compte)
	if err != nil {
		return nil, err
	}
	var meilleur map[string]any
	meilleurDate := ""
	for _, boite := range boites {
		ids, err := idsRecents(ctx, compte, boite)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			continue
		}
		messages, err := messagesDe(ctx, compte, ids)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if !vientDeExterieur(message, domaine) {
				continue
			}
			date := valeurChaine(message["receivedAt"])
			if meilleur == nil || date > meilleurDate {
				meilleur, meilleurDate = message, date
			}
		}
	}
	return meilleur, nil
}

// boitesEntrantes lists the mailboxes a delivered message can land in.
func boitesEntrantes(ctx context.Context, compte string) ([]string, error) {
	corps, err := appelServeurJMAP(ctx, "x:Mailbox/get", map[string]any{
		"accountId":  compte,
		"ids":        nil,
		"properties": []string{"id", "name", "role"},
	})
	if err != nil {
		return nil, err
	}
	var entrantes, indesirables []string
	for _, e := range listeDe(corps, "list") {
		boite, ok := e.(map[string]any)
		if !ok {
			continue
		}
		id := valeurChaine(boite["id"])
		if id == "" {
			continue
		}
		role := strings.ToLower(valeurChaine(boite["role"]))
		nom := strings.ToLower(valeurChaine(boite["name"]))
		switch {
		case role == "inbox":
			entrantes = append(entrantes, id)
		case role == "junk", strings.Contains(nom, "junk"), strings.Contains(nom, "spam"),
			strings.Contains(nom, "indésirable"), strings.Contains(nom, "indesirable"):
			indesirables = append(indesirables, id)
		}
	}
	return append(entrantes, indesirables...), nil
}

// idsRecents returns the most recent message ids of one mailbox.
func idsRecents(ctx context.Context, compte, boite string) ([]string, error) {
	corps, err := appelServeurJMAP(ctx, "Email/query", map[string]any{
		"accountId": compte,
		"filter":    map[string]any{"inMailbox": boite},
		"sort":      []any{map[string]any{"property": "receivedAt", "isAscending": false}},
		"limit":     20,
	})
	if err != nil {
		return nil, err
	}
	liste := listeDe(corps, "ids")
	ids := make([]string, 0, len(liste))
	for _, e := range liste {
		if id := valeurChaine(e); id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// messagesDe reads the fields the check needs from a list of message ids.
func messagesDe(ctx context.Context, compte string, ids []string) ([]map[string]any, error) {
	corps, err := appelServeurJMAP(ctx, "Email/get", map[string]any{
		"accountId": compte,
		"ids":       ids,
		"properties": []string{
			"from", "subject", "receivedAt",
			"header:Authentication-Results:asText",
		},
	})
	if err != nil {
		return nil, err
	}
	liste, _ := corps["list"].([]any)
	messages := make([]map[string]any, 0, len(liste))
	for _, e := range liste {
		if message, ok := e.(map[string]any); ok {
			messages = append(messages, message)
		}
	}
	return messages, nil
}

// vientDeExterieur reports whether a message was sent from another domain by a
// real sender.
func vientDeExterieur(message map[string]any, domaine string) bool {
	expediteur := expediteurDe(message)
	a, _, ok := strings.Cut(expediteur, "@")
	if !ok || a == "" {
		return false
	}
	if strings.EqualFold(a, "mailer-daemon") || strings.EqualFold(a, "postmaster") {
		return false
	}
	_, domaineExpediteur, _ := strings.Cut(strings.ToLower(expediteur), "@")
	return domaineExpediteur != "" && domaineExpediteur != domaine
}

// expediteurDe renders the first From address of a message.
func expediteurDe(message map[string]any) string {
	adresses, _ := message["from"].([]any)
	for _, a := range adresses {
		adresse, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if email := valeurChaine(adresse["email"]); email != "" {
			return email
		}
	}
	return ""
}

// verdictsAuthentification extracts the SPF/DKIM/DMARC verdicts of the
// Authentication-Results header(s).
var (
	motifSPF   = regexp.MustCompile(`(?i)\bspf=(\w+)`)
	motifDKIM  = regexp.MustCompile(`(?i)\bdkim=(\w+)`)
	motifDMARC = regexp.MustCompile(`(?i)\bdmarc=(\w+)`)
)

// authentification holds the three verdicts, "absent" when not reported.
type authentification struct{ SPF, DKIM, DMARC string }

func verdictsAuthentification(entetes string) authentification {
	if strings.TrimSpace(entetes) == "" {
		// A message with no Authentication-Results header is the case the caller
		// must report as "the server evaluated nothing": returning zero values
		// would render as "SPF , DKIM , DMARC " and read as three verdicts.
		return authentification{SPF: "absent", DKIM: "absent", DMARC: "absent"}
	}
	v := authentification{SPF: "absent", DKIM: "absent", DMARC: "absent"}
	if m := motifSPF.FindStringSubmatch(entetes); m != nil {
		v.SPF = strings.ToLower(m[1])
	}
	if m := motifDKIM.FindStringSubmatch(entetes); m != nil {
		v.DKIM = strings.ToLower(m[1])
	}
	if m := motifDMARC.FindStringSubmatch(entetes); m != nil {
		v.DMARC = strings.ToLower(m[1])
	}
	return v
}

// vide reports whether the server reported no verdict at all.
func (v authentification) vide() bool {
	return v.SPF == "absent" && v.DKIM == "absent" && v.DMARC == "absent"
}

func (v authentification) spf() string   { return v.SPF }
func (v authentification) dkim() string  { return v.DKIM }
func (v authentification) dmarc() string { return v.DMARC }

// authReussie is the plan's criterion: the message is authenticated when DMARC
// passes, or when SPF and DKIM both pass (DMARC is then satisfied by alignment
// one way or the other).
func (v authentification) authReussie() bool {
	if v.DMARC == "pass" {
		return true
	}
	return v.SPF == "pass" && v.DKIM == "pass"
}

// ---------------------------------------------------------------------------
// dnsbl
// ---------------------------------------------------------------------------

func verifierListesNoires(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "dnsbl", "Blocklist presence of the public address"
	if c.prive {
		return c.resultat(id, label, module.CheckNotApplicable, "private domain: internal delivery only", "")
	}
	ip, connue, motif := c.adressePublique()
	if !connue {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s: the blocklists cannot be queried", motif), "")
	}
	var listes, injoignables []string
	for _, zone := range listesNoires {
		requete := requeteListeNoire(ip, zone)
		if requete == "" {
			injoignables = append(injoignables, fmt.Sprintf("%s (unreadable address %q)", zone, ip))
			continue
		}
		reponses, err := resoudreNomSysteme(ctx, requete)
		switch {
		case err != nil && estAbsent(err):
			// NXDOMAIN: the address is not in this list. That is the normal,
			// expected answer and it is not an error.
		case err != nil:
			injoignables = append(injoignables, fmt.Sprintf("%s (%v)", zone, err))
			continue
		}
		classified, joignable := classerReponseListe(reponses)
		if !joignable {
			// 127.255.255.x means "cannot answer your query" (Spamhaus answers
			// this to unregistered resolvers): treating it as a listing would
			// accuse the platform on no evidence.
			injoignables = append(injoignables, fmt.Sprintf("%s (answered %s: query refused)", zone, strings.Join(reponses, ", ")))
			continue
		}
		if classified != "" {
			listes = append(listes, fmt.Sprintf("%s (%s)", zone, classified))
		}
	}
	if len(listes) > 0 {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the public address %s is listed by %s: receivers that use these lists will reject or quarantine the platform's mail", ip, strings.Join(listes, ", ")),
			"request a delisting from the list(s), then re-run this check")
	}
	if len(injoignables) == len(listesNoires) {
		return c.resultat(id, label, module.CheckNotApplicable,
			fmt.Sprintf("none of the blocklists could be queried for %s: %s", ip, strings.Join(injoignables, "; ")), "")
	}
	detail := fmt.Sprintf("the public address %s is not listed by %s", ip, strings.Join(restantes(listesNoires, injoignables), ", "))
	if len(injoignables) > 0 {
		detail = fmt.Sprintf("%s; %s could not be queried", detail, strings.Join(injoignables, ", "))
	}
	return c.resultat(id, label, module.CheckOK, detail, "")
}

// requeteListeNoire builds the DNSBL query name of an IPv4 address.
func requeteListeNoire(ip, zone string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.%s", parsed[3], parsed[2], parsed[1], parsed[0], zone)
}

// classerReponseListe reads a DNSBL answer. It returns the reason when the
// address is listed, or "" when it is not; joignable is false when the answer
// means "cannot answer".
func classerReponseListe(reponses []string) (raison string, joignable bool) {
	if len(reponses) == 0 {
		return "", true
	}
	for _, reponse := range reponses {
		parsed := net.ParseIP(strings.TrimSpace(reponse))
		if parsed == nil || parsed.To4() == nil {
			continue
		}
		quatre := parsed.To4()
		if quatre[0] != 127 {
			continue
		}
		if quatre[1] == 255 && quatre[2] == 255 {
			return "", false
		}
		return strings.TrimSpace(reponse), true
	}
	return "", true
}

// restantes lists the zones that did not fail to answer.
func restantes(zones []string, injoignables []string) []string {
	out := make([]string, 0, len(zones))
	for _, zone := range zones {
		if !contientPrefixe(injoignables, zone) {
			out = append(out, zone)
		}
	}
	return out
}

func contientPrefixe(textes []string, prefixe string) bool {
	for _, texte := range textes {
		if strings.HasPrefix(texte, prefixe) {
			return true
		}
	}
	return false
}

// estAbsent reports whether an error is a DNS "name does not exist".
func estAbsent(err error) bool {
	var dnserr *net.DNSError
	if errors.As(err, &dnserr) {
		return dnserr.IsNotFound
	}
	return false
}

// ---------------------------------------------------------------------------
// volume
// ---------------------------------------------------------------------------

func verifierVolume(ctx context.Context, c *contexteChecks) module.Check {
	const id, label = "volume", "Mailbox volume"
	pvc, err := lirePVC(ctx)
	switch {
	case err != nil:
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the mail volume cannot be read: %v", err), "")
	case pvc == nil:
		return c.resultat(id, label, module.CheckWarning,
			"the mail volume does not exist: the mail server has no store yet",
			fmt.Sprintf("deploy the mail layer: ceffio mail --domain %s", c.domaine))
	}
	capacite := capaciteVolume(pvc)
	engages, comptes, err := quotasEngages(ctx)
	if err != nil {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("the mailboxes' quotas cannot be read: %v", err), "")
	}
	encombre := fmt.Sprintf("the mailboxes can claim %s", gio(engages))
	if comptes > 0 {
		encombre = fmt.Sprintf("%d mailbox(es) can claim %s", comptes, gio(engages))
	}
	if capacite <= 0 {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s, but the volume reports no capacity: the two cannot be compared", encombre), "")
	}
	if engages > capacite {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s of the %s volume: delivery stops when the volume fills, before the quotas do", encombre, gio(capacite)),
			"enlarge the volume (mail module settings) or lower the default quota")
	}
	libre, libreConnue := espaceLibre(ctx)
	detail := fmt.Sprintf("%s of the %s volume", encombre, gio(capacite))
	if !libreConnue {
		return c.resultat(id, label, module.CheckOK,
			fmt.Sprintf("%s; free space unknown (the mail pod could not be queried)", detail), "")
	}
	detail = fmt.Sprintf("%s, %s free (%d %%)", detail, gio(libre), pourcentage(libre, capacite))
	if libre*10 < capacite {
		return c.resultat(id, label, module.CheckWarning,
			fmt.Sprintf("%s: less than 10 %% of the volume is free, delivery stops when it is full", detail),
			"free space (delete messages, purge a mailbox) or enlarge the volume")
	}
	return c.resultat(id, label, module.CheckOK, detail, "")
}

// capaciteVolume is the size of the claim: what the volume actually reports,
// falling back to what was requested before the volume is bound.
func capaciteVolume(pvc *corev1.PersistentVolumeClaim) int64 {
	if quantite, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok && quantite.Value() > 0 {
		return quantite.Value()
	}
	if quantite, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
		return quantite.Value()
	}
	return 0
}

// quotasEngages sums the disk quotas of the mail accounts.
//
// THE NUMBER THAT MATTERS IS THE SUM OF THE QUOTAS, not the used space: Stalwart
// accepts a message per mailbox until that mailbox's quota is full, so the volume
// is over-committed the day the quotas exceed its size — the failure arrives
// then, days after the setting that caused it.
func quotasEngages(ctx context.Context) (int64, int, error) {
	corps, err := appelServeurJMAP(ctx, "x:Account/get", map[string]any{
		"ids":        nil,
		"properties": []string{"name", "quotas"},
	})
	if err != nil {
		return 0, 0, err
	}
	var total int64
	comptes := 0
	for _, e := range listeDe(corps, "list") {
		compte, ok := e.(map[string]any)
		if !ok {
			continue
		}
		quotas, _ := compte["quotas"].(map[string]any)
		valeur, ok := nombre(quotas["maxDiskQuota"])
		if !ok || valeur <= 0 {
			continue
		}
		total += int64(valeur)
		comptes++
	}
	return total, comptes, nil
}

// espaceLibre reads the free space of the mailbox store from inside the pod.
func espaceLibre(ctx context.Context) (int64, bool) {
	sortie, err := executerCommandePod(ctx, "df -Pk "+cheminVolume)
	if err != nil {
		return 0, false
	}
	lignes := strings.Split(strings.TrimSpace(sortie), "\n")
	if len(lignes) < 2 {
		return 0, false
	}
	champs := strings.Fields(lignes[len(lignes)-1])
	if len(champs) < 4 {
		return 0, false
	}
	ko, err := strconv.ParseInt(champs[3], 10, 64)
	if err != nil {
		return 0, false
	}
	return ko * 1024, true
}

// gio renders a byte count the way an operator reads a volume.
func gio(octets int64) string {
	return fmt.Sprintf("%.1f GiB", float64(octets)/(1<<30))
}

// pourcentage renders a ratio, clamped to 0..100.
func pourcentage(partie, total int64) int {
	if total <= 0 {
		return 0
	}
	p := partie * 100 / total
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return int(p)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// motifErreur renders an error, or a fallback when there is none.
func motifErreur(err error, defaut string) string {
	if err == nil {
		return defaut
	}
	return err.Error()
}

// nomHoteValide reports whether a value is safe to put in a shell command as a
// host name.
func nomHoteValide(hote string) bool {
	if hote == "" || len(hote) > 253 {
		return false
	}
	return motifNomHote.MatchString(hote)
}

var motifNomHote = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)

// contientAdresse reports whether one of the addresses is `voulue`, comparing
// parsed IPs so two spellings of the same IPv6 address match.
func contientAdresse(adresses []string, voulue string) bool {
	cible := net.ParseIP(strings.TrimSpace(voulue))
	for _, adresse := range adresses {
		if cible != nil {
			if actuelle := net.ParseIP(strings.TrimSpace(adresse)); actuelle != nil && actuelle.Equal(cible) {
				return true
			}
			continue
		}
		if strings.EqualFold(strings.TrimSpace(adresse), strings.TrimSpace(voulue)) {
			return true
		}
	}
	return false
}

// contientNom reports whether one of the names is `voulu`, ignoring case and a
// trailing dot.
func contientNom(noms []string, voulu string) bool {
	voulu = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(voulu)), ".")
	for _, nom := range noms {
		if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(nom)), ".") == voulu {
			return true
		}
	}
	return false
}

// contientMot reports whether `mot` is in `mots`.
func contientMot(mots []string, mot string) bool {
	for _, m := range mots {
		if strings.EqualFold(m, mot) {
			return true
		}
	}
	return false
}

// listeDe reads a JSON array out of a JMAP response body.
func listeDe(corps map[string]any, cle string) []any {
	liste, _ := corps[cle].([]any)
	return liste
}

// nombre reads a JSON number out of a decoded body.
func nombre(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	}
	return 0, false
}
