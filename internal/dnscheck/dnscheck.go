// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package dnscheck resolves the DNS records a platform's features depend on,
// through PUBLIC resolvers.
//
// WHY NOT THE SYSTEM RESOLVER: inside the cluster the system resolver is
// CoreDNS, and a split-horizon or wildcard zone there answers for names that do
// not exist on the public Internet. A mail server's MX, SPF, DKIM and PTR
// records are read by OTHER mail servers, so the only answer that matters is
// the one the public Internet gives. CoreDNS would say "it resolves" about a
// name the outside world has never heard of — the one false positive that looks
// exactly like success.
//
// The default resolvers are Cloudflare's 1.1.1.1:53 and Quad9's 9.9.9.9:53,
// tried in that order. CEFFIO_DNS_SERVERS replaces them with a comma-separated
// list of host:port, which is also what makes the checks testable in an
// air-gapped environment.
package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

// EnvServeurs is the environment variable that replaces the default resolvers.
// Its value is a comma-separated list of host:port ("10.0.0.2:53,10.0.0.3:53").
const EnvServeurs = "CEFFIO_DNS_SERVERS"

// serveursParDefaut are queried in order: a first resolver that is blocked on
// the operator's network must not hide the answer a second one would give.
var serveursParDefaut = []string{"1.1.1.1:53", "9.9.9.9:53"}

// delai borne chaque famille de requête.
//
// WHY A BOUND AND NOT THE RESOLVER'S DEFAULT: a filtered (not refused) UDP
// query waits until the resolver's own timeout, measured in tens of seconds.
// A console page that calls ten checks would then hold the request open for
// minutes, and the operator would read "the page is broken" instead of "port 53
// is blocked here".
const delai = 5 * time.Second

// Resolveur is the subset of net.Resolver this package uses.
//
// IT IS AN INTERFACE SO THE TESTS CAN ANSWER: every function below is tested
// against a fake that returns known records and known failures. The alternative
// — hitting real DNS in a unit test — is a test that fails when the network
// does, and that never proves the failure path.
type Resolveur interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Client resolves records through one resolver, with a bound per lookup.
type Client struct {
	r     Resolveur
	delai time.Duration
}

// Nouveau returns a client on the public resolvers (see the package comment).
func Nouveau() *Client {
	return &Client{r: resolveurPublic(Serveurs()), delai: delai}
}

// PourTest returns a client on an injected resolver. The name says what it is
// for: nothing outside a test should inject a resolver, and a production caller
// treading on this seam would bypass the public-resolver rule that the whole
// package exists to enforce.
func PourTest(r Resolveur) *Client {
	return &Client{r: r, delai: delai}
}

// Serveurs returns the resolvers to query: CEFFIO_DNS_SERVERS when it holds at
// least one non-empty entry, the two public defaults otherwise.
//
// AN EMPTY OR BLANK VARIABLE FALLS BACK, IT DOES NOT DISABLE LOOKUPS: a shell
// that exports an empty variable by accident must not turn every DNS check into
// an error whose message says nothing about the cause.
func Serveurs() []string {
	brut := strings.TrimSpace(os.Getenv(EnvServeurs))
	if brut == "" {
		return append([]string(nil), serveursParDefaut...)
	}
	var out []string
	for _, s := range strings.Split(brut, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), serveursParDefaut...)
	}
	return out
}

// resolveurPublic builds a Go resolver that dials the given servers in order.
//
// PREFERGO IS NOT AN OPTIMISATION HERE: the cgo resolver reads
// /etc/resolv.conf and would answer through CoreDNS, which is the answer this
// package exists to avoid. Without PreferGo the custom Dial is ignored on a
// system built with cgo.
func resolveurPublic(serveurs []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dernier error
			for _, s := range serveurs {
				var d net.Dialer
				c, err := d.DialContext(ctx, network, s)
				if err == nil {
					return c, nil
				}
				dernier = err
			}
			return nil, fmt.Errorf("no public resolver answered (%s): %v",
				strings.Join(serveurs, ", "), dernier)
		},
	}
}

// Adresses returns the A and AAAA records of a host, sorted and without
// duplicates.
//
// ONE LOOKUP, BOTH FAMILIES: the caller almost always wants to know "what does
// this name point to", and asking twice costs two timeouts when the name does
// not exist.
func (c *Client) Adresses(ctx context.Context, hote string) ([]string, error) {
	ctx, annuler := c.borne(ctx)
	defer annuler()

	addrs, err := c.r.LookupHost(ctx, hote)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil {
			out = append(out, ip.Unmap().String())
		}
	}
	return trier(out), nil
}

// A returns the IPv4 addresses of a host.
func (c *Client) A(ctx context.Context, hote string) ([]string, error) {
	return c.parFamille(ctx, hote, true)
}

// AAAA returns the IPv6 addresses of a host.
func (c *Client) AAAA(ctx context.Context, hote string) ([]string, error) {
	return c.parFamille(ctx, hote, false)
}

func (c *Client) parFamille(ctx context.Context, hote string, v4 bool) ([]string, error) {
	addrs, err := c.Adresses(ctx, hote)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		if ip.Is4() == v4 {
			out = append(out, a)
		}
	}
	return out, nil
}

// MX returns the MX records of a domain, sorted by preference then host, with
// the trailing dots removed.
//
// THE DOT IS REMOVED BECAUSE THE OPERATOR READS THESE: `mail.example.com.` and
// `mail.example.com` are the same name, and a report that adds a dot looks like
// a different record — the operator would think their zone is wrong when it
// is not.
func (c *Client) MX(ctx context.Context, domaine string) ([]*net.MX, error) {
	ctx, annuler := c.borne(ctx)
	defer annuler()

	recs, err := c.r.LookupMX(ctx, domaine)
	if err != nil {
		return nil, err
	}
	out := make([]*net.MX, 0, len(recs))
	for _, m := range recs {
		if m == nil {
			continue
		}
		out = append(out, &net.MX{Pref: m.Pref, Host: strings.TrimSuffix(m.Host, ".")})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pref != out[j].Pref {
			return out[i].Pref < out[j].Pref
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

// TXT returns the TXT records of a name, sorted.
//
// THE ORDER DNS RETURNS THEM IN IS NOT MEANINGFUL, so it is not preserved: an
// unsorted list makes two runs of the same check print differently, and a diff
// between two reports becomes noise.
func (c *Client) TXT(ctx context.Context, nom string) ([]string, error) {
	ctx, annuler := c.borne(ctx)
	defer annuler()

	recs, err := c.r.LookupTXT(ctx, nom)
	if err != nil {
		return nil, err
	}
	return trier(recs), nil
}

// CNAME returns the canonical name of a host, without the trailing dot.
//
// IT ALWAYS RETURNS A NAME, even when the host is not an alias: the Go resolver
// answers with the name itself in that case. A caller that must distinguish
// "this is an alias" from "this name exists" compares the result with the input
// — there is no error to rely on.
func (c *Client) CNAME(ctx context.Context, hote string) (string, error) {
	ctx, annuler := c.borne(ctx)
	defer annuler()

	cname, err := c.r.LookupCNAME(ctx, hote)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(cname, "."), nil
}

// SRV returns the SRV records of a service, sorted by priority, weight then
// target, with the trailing dots removed.
func (c *Client) SRV(ctx context.Context, service, proto, nom string) ([]*net.SRV, error) {
	ctx, annuler := c.borne(ctx)
	defer annuler()

	_, recs, err := c.r.LookupSRV(ctx, service, proto, nom)
	if err != nil {
		return nil, err
	}
	out := make([]*net.SRV, 0, len(recs))
	for _, s := range recs {
		if s == nil {
			continue
		}
		out = append(out, &net.SRV{
			Target:   strings.TrimSuffix(s.Target, "."),
			Port:     s.Port,
			Priority: s.Priority,
			Weight:   s.Weight,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		if out[i].Weight != out[j].Weight {
			return out[i].Weight < out[j].Weight
		}
		return out[i].Target < out[j].Target
	})
	return out, nil
}

// PTR returns the names a reverse zone gives to an IP, without the trailing
// dots, sorted.
func (c *Client) PTR(ctx context.Context, ip string) ([]string, error) {
	ctx, annuler := c.borne(ctx)
	defer annuler()

	noms, err := c.r.LookupAddr(ctx, ip)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(noms))
	for _, n := range noms {
		out = append(out, strings.TrimSuffix(n, "."))
	}
	return trier(out), nil
}

// FCrDNS checks a forward-confirmed reverse DNS: the IP resolves back to hote,
// and hote resolves forward to the same IP. It returns what the PTR said and
// whether the confirmation holds.
//
// WHY BOTH DIRECTIONS: a PTR record alone proves nothing — anyone controlling a
// reverse zone can point it at gmail.com. Mail servers check the forward
// direction precisely because the PTR is not authoritative for the name it
// claims. Reporting "PTR is right" without the forward check would tell the
// operator to stop looking when the outbound mail is still refused.
//
// The error cases are separated on purpose: when the PTR lookup fails the caller
// learns nothing, while a forward lookup that fails after a matching PTR is a
// different fault (the A record is missing or lagging).
func (c *Client) FCrDNS(ctx context.Context, hote, ip string) ([]string, bool, error) {
	ptrs, err := c.PTR(ctx, ip)
	if err != nil {
		return nil, false, err
	}
	attendu := strings.TrimSuffix(hote, ".")
	for _, p := range ptrs {
		if !strings.EqualFold(p, attendu) {
			continue
		}
		addrs, err := c.Adresses(ctx, hote)
		if err != nil {
			return ptrs, false, err
		}
		return ptrs, contient(addrs, ip), nil
	}
	return ptrs, false, nil
}

// EstAbsent reports whether err says the name or the record asked for does not
// exist, as opposed to the resolver being unable to answer.
//
// THE DISTINCTION IS THE WHOLE POINT OF THE CHECKS: "the zone publishes no
// answer" is a finding for the operator (a missing record, a fix to write),
// while "the resolver did not answer" is a failure of the verification itself
// (a timeout, a broken network) and must not be presented as a missing record.
// Go reports the first case as a *net.DNSError with IsNotFound set — including
// for a name that exists but has no record of the type queried, which is how a
// domain without MX comes back as `no such host`.
func EstAbsent(err error) bool {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return false
	}
	return dnsErr.IsNotFound
}

// borne applies the client's bound on top of the caller's context.
func (c *Client) borne(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.delai <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.delai)
}

// trier returns a sorted copy without duplicates.
func trier(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	uniq := out[:0]
	for i, s := range out {
		if i > 0 && s == out[i-1] {
			continue
		}
		uniq = append(uniq, s)
	}
	if len(uniq) == 0 {
		return nil
	}
	return uniq
}

// contient reports whether addrs holds ip, comparing parsed addresses so that
// two spellings of the same IPv6 address (compressed, upper case) match.
func contient(addrs []string, ip string) bool {
	voulu, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if got, err := netip.ParseAddr(a); err == nil && got.Unmap() == voulu.Unmap() {
			return true
		}
	}
	return false
}
