// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// This file tests every lookup on a fixture that answers, and on a fixture that
// fails.
//
// WHY NO REAL DNS QUERY: a unit test that contacts 1.1.1.1 fails when the
// network, the resolver or the test runner's firewall does, and then it says
// nothing about the code. Worse, it cannot make a name fail on demand, so the
// failure path — the one the operator sees when a record is missing — would go
// untested. The fake below answers exactly what each test needs.

// fauxResolveur answers from fields, and records what it was asked.
type fauxResolveur struct {
	noms    map[string][]string
	mx      map[string][]*net.MX
	txt     map[string][]string
	cname   map[string]string
	srv     map[string][]*net.SRV
	ptr     map[string][]string
	erreurs map[string]error // keyed by the name asked for

	// bloque, when set, ignores the arguments and waits for the context, which
	// is how the bound is tested without waiting for a real timeout.
	bloque bool
}

func (f *fauxResolveur) LookupHost(ctx context.Context, host string) ([]string, error) {
	if f.bloque {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err, ok := f.erreurs[host]; ok {
		return nil, err
	}
	return f.noms[host], nil
}

func (f *fauxResolveur) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err, ok := f.erreurs[name]; ok {
		return nil, err
	}
	return f.mx[name], nil
}

func (f *fauxResolveur) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err, ok := f.erreurs[name]; ok {
		return nil, err
	}
	return f.txt[name], nil
}

func (f *fauxResolveur) LookupCNAME(ctx context.Context, host string) (string, error) {
	if err, ok := f.erreurs[host]; ok {
		return "", err
	}
	if c, ok := f.cname[host]; ok {
		return c, nil
	}
	return host + ".", nil
}

func (f *fauxResolveur) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	if err, ok := f.erreurs[name]; ok {
		return "", nil, err
	}
	return "", f.srv[name], nil
}

func (f *fauxResolveur) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err, ok := f.erreurs[addr]; ok {
		return nil, err
	}
	return f.ptr[addr], nil
}

// TestServeursParDefautEtSurcharge : the two defaults, and the environment
// variable that replaces them.
//
// THE OVERRIDE IS THE AIR-GAPPED ESCAPE HATCH: without it, every check in a
// network with no outbound 53 fails with a timeout, and the operator cannot
// point the checks at their own recursive resolver.
func TestServeursParDefautEtSurcharge(t *testing.T) {
	t.Setenv(EnvServeurs, "")
	if got := Serveurs(); len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "9.9.9.9:53" {
		t.Fatalf("default resolvers are %v, expected the two public ones", got)
	}

	t.Setenv(EnvServeurs, " 10.0.0.2:53 , 10.0.0.3:53 ,")
	got := Serveurs()
	if len(got) != 2 || got[0] != "10.0.0.2:53" || got[1] != "10.0.0.3:53" {
		t.Fatalf("CEFFIO_DNS_SERVERS gave %v, expected the two overridden servers "+
			"without blanks", got)
	}

	// An accident in a shell must not disable every check.
	t.Setenv(EnvServeurs, "   ")
	if got := Serveurs(); len(got) != 2 {
		t.Fatalf("a blank CEFFIO_DNS_SERVERS gave %v, expected the defaults: an empty "+
			"value must not turn every check into a failure with no visible cause", got)
	}
}

// TestLeResolveurPublicEssaieLesServeursDansLOrdre : every configured resolver
// is tried, and a list that answers nowhere is reported with the servers it
// tried.
//
// WHY IT MATTERS: with one resolver dead, a client that stopped at the first
// failure would report a working network as broken. The message names the
// servers so the operator can tell "my resolver list is wrong" from "port 53 is
// filtered".
func TestLeResolveurPublicEssaieLesServeursDansLOrdre(t *testing.T) {
	// .invalid is reserved and never resolves: the dial fails on every entry,
	// which is the case the loop exists for.
	r := resolveurPublic([]string{"serveur-un.invalid:53", "serveur-deux.invalid:53"})
	ctx, annuler := context.WithTimeout(context.Background(), 2*time.Second)
	defer annuler()

	c, err := r.Dial(ctx, "udp", "1.1.1.1:53")
	if err == nil {
		c.Close()
		t.Fatal("dialing two dead resolvers succeeded: the failure is not reported, so " +
			"the operator would see a timeout instead of \"no resolver answered\"")
	}
	if !strings.Contains(err.Error(), "no public resolver answered") ||
		!strings.Contains(err.Error(), "serveur-un.invalid:53") ||
		!strings.Contains(err.Error(), "serveur-deux.invalid:53") {
		t.Errorf("the error does not say what went wrong: %v", err)
	}
}

// TestAETAAAALitLesBonnesFamilles : one lookup returns both families, and each
// accessor returns its own.
//
// A REGRESSION HERE WOULD BE SILENT: a check comparing the A record with the
// public IPv4 of the machine would compare it with an IPv6 address, conclude
// "wrong address" and send the operator to edit a correct zone.
func TestAETAAAALitLesBonnesFamilles(t *testing.T) {
	r := &fauxResolveur{noms: map[string][]string{
		"mail.example.com": {"192.0.2.10", "2001:db8::10", "192.0.2.11"},
	}}
	c := PourTest(r)

	v4, err := c.A(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	if len(v4) != 2 || v4[0] != "192.0.2.10" || v4[1] != "192.0.2.11" {
		t.Errorf("A returned %v, expected the two IPv4 addresses in order", v4)
	}

	v6, err := c.AAAA(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatalf("AAAA: %v", err)
	}
	if len(v6) != 1 || v6[0] != "2001:db8::10" {
		t.Errorf("AAAA returned %v, expected the one IPv6 address", v6)
	}

	// The combined list is what a caller wanting "does this name point to us"
	// uses; it must keep the families apart from the accessors and be sorted.
	toutes, err := c.Adresses(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatalf("Adresses: %v", err)
	}
	if len(toutes) != 3 {
		t.Errorf("Adresses returned %v, expected all three addresses", toutes)
	}
}

// TestUneAdresseIPv4MappeeResteIPv4 : the same address written as ::ffff:a.b.c.d
// is IPv4, and must not end up in the AAAA answer.
func TestUneAdresseIPv4MappeeResteIPv4(t *testing.T) {
	r := &fauxResolveur{noms: map[string][]string{
		"mail.example.com": {"::ffff:192.0.2.10"},
	}}
	c := PourTest(r)

	v4, err := c.A(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	if len(v4) != 1 || v4[0] != "192.0.2.10" {
		t.Errorf("a mapped IPv4 address gave %v, expected 192.0.2.10 in the A answer; "+
			"otherwise the check sees no A record and reports a correct zone as wrong", v4)
	}
	if v6, err := c.AAAA(context.Background(), "mail.example.com"); err != nil || len(v6) != 0 {
		t.Errorf("AAAA returned %v (%v): a mapped IPv4 address is not an IPv6 one", v6, err)
	}
}

// TestAEnEchecRemonteLErreur : a name that does not exist must be an error, not
// an empty answer.
//
// THE TWO ARE DIFFERENT FOR THE CALLER: "no A record" means the zone is wrong,
// while "the lookup failed" means the check could not measure anything. The
// console must not report "the record is missing" when the resolver refused to
// answer — that sends the operator to edit a zone that may be fine.
func TestAEnEchecRemonteLErreur(t *testing.T) {
	r := &fauxResolveur{erreurs: map[string]error{"mail.example.com": errors.New("no such host")}}
	c := PourTest(r)

	if addrs, err := c.A(context.Background(), "mail.example.com"); err == nil {
		t.Errorf("A returned %v and no error: a failed lookup must be visible to the caller",
			addrs)
	}
}

// TestMXEstTrieEtSansPointFinal : the order is by preference, and the trailing
// dot is removed for display.
func TestMXEstTrieEtSansPointFinal(t *testing.T) {
	r := &fauxResolveur{mx: map[string][]*net.MX{
		"example.com": {
			{Host: "second.example.com.", Pref: 20},
			{Host: "first.example.com.", Pref: 10},
		},
	}}
	c := PourTest(r)

	mx, err := c.MX(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("MX: %v", err)
	}
	if len(mx) != 2 {
		t.Fatalf("MX returned %d records, expected 2", len(mx))
	}
	if mx[0].Pref != 10 || mx[0].Host != "first.example.com" {
		t.Errorf("first MX record is %+v: expected the lowest preference with no trailing dot",
			mx[0])
	}
	if mx[1].Pref != 20 {
		t.Errorf("second MX record is %+v: expected preference 20", mx[1])
	}
}

// TestTXTEstTrie : TXT order from DNS is not meaningful, so the output is
// sorted — otherwise two runs of the same check differ and a report diff is
// noise.
func TestTXTEstTrie(t *testing.T) {
	r := &fauxResolveur{txt: map[string][]string{
		"example.com": {"v=spf1 -all", "google-site-verification=abc"},
	}}
	c := PourTest(r)

	txt, err := c.TXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("TXT: %v", err)
	}
	if len(txt) != 2 || txt[0] != "google-site-verification=abc" {
		t.Errorf("TXT returned %v, expected a sorted list", txt)
	}
}

// TestCNAME : a host with no alias answers with itself, without the dot.
//
// THE CALLER MUST COMPARE WITH ITS INPUT: the Go resolver does not error on a
// name that is not an alias, so "is this a CNAME?" can only be answered by
// comparing the two names. This test pins that behaviour because a check that
// assumed an error would silently never detect an alias.
func TestCNAME(t *testing.T) {
	r := &fauxResolveur{cname: map[string]string{
		"mail.example.com": "target.example.net.",
	}}
	c := PourTest(r)

	got, err := c.CNAME(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatalf("CNAME: %v", err)
	}
	if got != "target.example.net" {
		t.Errorf("CNAME returned %q, expected the target without the trailing dot", got)
	}

	// No entry in the fixture: the fake returns the input plus a dot, which is
	// what the real resolver does.
	got, err = c.CNAME(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("CNAME without an alias: %v", err)
	}
	if got != "www.example.com" {
		t.Errorf("CNAME without an alias returned %q, expected the host itself", got)
	}
}

// TestSRVEstTrieEtSansPointFinal : SRV records carry a target with a trailing
// dot, and the order in a zone file is not the order of the answer.
func TestSRVEstTrieEtSansPointFinal(t *testing.T) {
	r := &fauxResolveur{srv: map[string][]*net.SRV{
		"example.com": {
			{Target: "mail.example.com.", Port: 993, Priority: 10, Weight: 5},
			{Target: "other.example.com.", Port: 993, Priority: 5, Weight: 0},
		},
	}}
	c := PourTest(r)

	srv, err := c.SRV(context.Background(), "imaps", "tcp", "example.com")
	if err != nil {
		t.Fatalf("SRV: %v", err)
	}
	if len(srv) != 2 {
		t.Fatalf("SRV returned %d records, expected 2", len(srv))
	}
	if srv[0].Priority != 5 || srv[0].Target != "other.example.com" {
		t.Errorf("first SRV record is %+v, expected the lowest priority without the dot", srv[0])
	}
}

// TestPTREstTrieEtSansPointFinal : the reverse answer is displayed to the
// operator, so the dot goes and the order is stable.
func TestPTREstTrieEtSansPointFinal(t *testing.T) {
	r := &fauxResolveur{ptr: map[string][]string{
		"192.0.2.10": {"mail.example.com.", "smtp.example.com."},
	}}
	c := PourTest(r)

	ptr, err := c.PTR(context.Background(), "192.0.2.10")
	if err != nil {
		t.Fatalf("PTR: %v", err)
	}
	if len(ptr) != 2 || ptr[0] != "mail.example.com" || ptr[1] != "smtp.example.com" {
		t.Errorf("PTR returned %v, expected both names sorted and without dots", ptr)
	}
}

// TestPTREnEchecRemonteLErreur : the forward-confirmed check must be able to say
// "I could not measure" instead of "the PTR is wrong".
func TestPTREnEchecRemonteLErreur(t *testing.T) {
	r := &fauxResolveur{erreurs: map[string]error{"192.0.2.10": errors.New("no PTR")}}
	c := PourTest(r)

	if _, err := c.PTR(context.Background(), "192.0.2.10"); err == nil {
		t.Error("PTR returned no error for a failed lookup: the operator would be told the " +
			"reverse DNS is wrong when it could not be read")
	}
}

// TestFCrDNSConfirme : the happy path — the PTR names the host, and the host
// resolves back to the IP.
func TestFCrDNSConfirme(t *testing.T) {
	r := &fauxResolveur{
		ptr:  map[string][]string{"192.0.2.10": {"mail.example.com."}},
		noms: map[string][]string{"mail.example.com": {"192.0.2.10", "2001:db8::10"}},
	}
	c := PourTest(r)

	ptr, confirme, err := c.FCrDNS(context.Background(), "mail.example.com", "192.0.2.10")
	if err != nil {
		t.Fatalf("FCrDNS: %v", err)
	}
	if !confirme {
		t.Errorf("FCrDNS did not confirm a matching pair (PTR %v): the outbound mail check "+
			"would report a correct configuration as broken", ptr)
	}
}

// TestFCrDNSRefuseUnPTRQuiNeRevientPas : a PTR that names the host, but whose
// forward lookup does NOT return the IP, is not confirmed.
//
// THIS IS THE CASE THE CHECK EXISTS FOR: whoever controls a reverse zone can
// write any name in it. Only the forward-confirmed pair proves the two records
// belong together, and reporting the match without it would advise the operator
// to stop looking while their mail is still refused.
func TestFCrDNSRefuseUnPTRQuiNeRevientPas(t *testing.T) {
	r := &fauxResolveur{
		ptr:  map[string][]string{"192.0.2.10": {"mail.example.com."}},
		noms: map[string][]string{"mail.example.com": {"192.0.2.99"}},
	}
	c := PourTest(r)

	ptr, confirme, err := c.FCrDNS(context.Background(), "mail.example.com", "192.0.2.10")
	if err != nil {
		t.Fatalf("FCrDNS: %v", err)
	}
	if confirme {
		t.Errorf("FCrDNS confirmed a PTR whose forward lookup returns 192.0.2.99 (PTR %v): "+
			"a reverse zone alone proves nothing about the forward one", ptr)
	}
}

// TestFCrDNSRefuseUnAutreNom : a PTR that names another host is not confirmed,
// even when that name resolves to the IP.
func TestFCrDNSRefuseUnAutreNom(t *testing.T) {
	r := &fauxResolveur{
		ptr:  map[string][]string{"192.0.2.10": {"other.example.net."}},
		noms: map[string][]string{"other.example.net": {"192.0.2.10"}},
	}
	c := PourTest(r)

	_, confirme, err := c.FCrDNS(context.Background(), "mail.example.com", "192.0.2.10")
	if err != nil {
		t.Fatalf("FCrDNS: %v", err)
	}
	if confirme {
		t.Error("FCrDNS confirmed a PTR naming another host, which would report a reverse " +
			"zone belonging to a different name as correct")
	}
}

// TestFCrDNSSansPTR : no PTR record at all is "not confirmed", not an error.
//
// AN ABSENT RECORD IS A MEASUREMENT: the operator must see "no PTR" and the fix
// ("set the reverse DNS at your hosting provider"), not "the check failed".
func TestFCrDNSSansPTR(t *testing.T) {
	r := &fauxResolveur{ptr: map[string][]string{}}
	c := PourTest(r)

	ptr, confirme, err := c.FCrDNS(context.Background(), "mail.example.com", "192.0.2.10")
	if err != nil {
		t.Fatalf("FCrDNS without PTR: %v", err)
	}
	if confirme || len(ptr) != 0 {
		t.Errorf("FCrDNS without PTR confirmed %v / %v, expected nothing", confirme, ptr)
	}
}

// TestLeDelaiCoupeUneResolutionQuiTraene : a filtered query does not answer, and
// the bound is what turns it into a usable error.
//
// WITHOUT IT THE CONSOLE PAGE HANGS: a check that waits for the resolver's own
// timeout (tens of seconds) holds the request open, and the operator reads "the
// page is broken" rather than "port 53 is filtered".
func TestLeDelaiCoupeUneResolutionQuiTraene(t *testing.T) {
	c := &Client{r: &fauxResolveur{bloque: true}, delai: 20 * time.Millisecond}

	debut := time.Now()
	_, err := c.A(context.Background(), "mail.example.com")
	if err == nil {
		t.Fatal("a lookup waiting forever returned no error: the bound is not applied")
	}
	if ecoule := time.Since(debut); ecoule > 2*time.Second {
		t.Errorf("the bound took %s, expected about 20 ms", ecoule)
	}
}

// TestContientCompareLesAdresses : two spellings of one IPv6 address are the
// same address for the forward check.
//
// A STRING COMPARISON WOULD FAIL HERE, and the operator would be told their
// reverse DNS is wrong although the two records agree.
func TestContientCompareLesAdresses(t *testing.T) {
	if !contient([]string{"2001:DB8:0:0:0:0:0:10"}, "2001:db8::10") {
		t.Error("two spellings of one IPv6 address are not recognized as equal")
	}
	if contient([]string{"192.0.2.10"}, "192.0.2.11") {
		t.Error("two different addresses are recognized as equal")
	}
	if contient(nil, "not-an-ip") {
		t.Error("an invalid address is matched")
	}
}

// TestAUnAvecUneAdresseInexploitable : a resolver that returns a name instead of
// an address is a broken fixture, not a panic.
func TestAUnAvecUneAdresseInexploitable(t *testing.T) {
	r := &fauxResolveur{noms: map[string][]string{"mail.example.com": {"not-an-address"}}}
	c := PourTest(r)

	addrs, err := c.A(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	if len(addrs) != 0 {
		t.Errorf("A kept %v as an address: the answer would be compared with a real IP by "+
			"string, and never match while looking plausible", addrs)
	}
}

// TestNouveauConstruitUnClientUtilisable : the constructor wires a resolver.
//
// IT DOES NOT RESOLVE ANYTHING HERE, and that is the point: the test must pass
// on a machine with no network. It only refuses a nil resolver, which would
// panic on the first check instead of reporting an unreachable resolver.
func TestNouveauConstruitUnClientUtilisable(t *testing.T) {
	c := Nouveau()
	if c == nil || c.r == nil {
		t.Fatal("Nouveau returned a client with no resolver")
	}
	if c.delai <= 0 {
		t.Errorf("Nouveau returned a client with no bound: a filtered query would hold the "+
			"request open for the resolver's own timeout (delai=%s)", c.delai)
	}
	// The fake must satisfy the interface the production client uses; a change
	// to Resolveur that this test does not implement would fail to compile,
	// which is the point of declaring it here.
	var _ Resolveur = &fauxResolveur{}
}

// TestEstAbsentDistingueLeManqueDeLEchec : "the zone publishes nothing" and
// "the resolver could not answer" lead to different checks, so the helper that
// separates them is pinned on the exact errors Go produces.
//
// WHY IT MATTERS: a domain without an MX record comes back as `no such host`
// with IsNotFound set — the same answer as a domain that does not exist. Without
// this distinction every missing record was reported as an unreadable lookup,
// telling the operator to look at the network instead of at their zone.
func TestEstAbsentDistingueLeManqueDeLEchec(t *testing.T) {
	cas := []struct {
		nom    string
		err    error
		absent bool
	}{
		{"nom ou enregistrement inexistant", &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}, true},
		{"délai dépassé", &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}, false},
		{"serveur injoignable", &net.DNSError{Err: "server misbehaving", Name: "example.com", IsTemporary: true}, false},
		{"erreur enveloppée", fmt.Errorf("lookup: %w", &net.DNSError{Err: "no such host", IsNotFound: true}), true},
		{"erreur quelconque", errors.New("boom"), false},
		{"aucune erreur", nil, false},
	}
	for _, c := range cas {
		if got := EstAbsent(c.err); got != c.absent {
			t.Errorf("%s: EstAbsent = %v, want %v", c.nom, got, c.absent)
		}
	}
}
