// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// This file CHECKS the prerequisites before anything is installed, and reports
// every problem at once.
//
// # WHY CHECK RATHER THAN JUST INSTALL
//
// Two families of prerequisite exist, and they fail in opposite ways:
//
//	The SYSTEM packages are fixable here — the installer can apt-get them.
//	The DNS records are NOT: they belong to a registrar or a DNS provider,
//	and no amount of privilege on this machine will create them.
//
// Reporting them together, BEFORE the cluster is touched, is what makes the
// difference between a five-minute fix and an afternoon. Measured on the first
// deployment to ceffio.org: the DNS was wrong, nothing said so, and the
// failure surfaced forty minutes later as
//
//	ceffio: discovery does not return the expected provider
//	(https://keycloak.ceffio.org/realms/ceffio): {...}
//
// which reads like a Keycloak misconfiguration. The cause was a missing
// A record. Every host of the domain is checked here for that reason.
package bootstrap

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Prerequis is what the deployment needs from the machine and the DNS.
type Prerequis struct {
	// NomsDNS are the hostnames that must already resolve to this machine.
	NomsDNS []string
	// AdresseAttendue is the address every name above must resolve to.
	AdresseAttendue string
	// Paquets are the system packages that must be present.
	Paquets []string
	// Services are the systemd units that must be active.
	Services []string
}

// ResultatDNS is one name and what it resolved to.
type ResultatDNS struct {
	Nom      string
	Adresses []string
	Err      error
}

// OK says whether the name points at the expected address.
//
// A DOMAIN WITH NO PUBLIC NAME IS NOT AN ERROR. The `.local` profiles are
// deliberately deployed without DNS: the Ingresses are reached through
// hostAliases, and requiring a record would make the demo impossible to run.
// The caller decides whether to call this — see Verifier.
func (r ResultatDNS) OK(attendue string) bool {
	if r.Err != nil || len(r.Adresses) == 0 {
		return false
	}
	for _, a := range r.Adresses {
		if a == attendue {
			return true
		}
	}
	return false
}

// Verifier interroge le DNS pour chaque nom et rend le detail.
//
// IT RESOLVES RATHER THAN PINGS. An ICMP echo can be filtered while the name
// is perfectly correct, and then the check reports a DNS problem where there
// is none. What matters is that the name resolves to the right address.
func Verifier(ctx context.Context, noms []string) []ResultatDNS {
	res := make([]ResultatDNS, 0, len(noms))
	// One resolver with a short timeout: the default can take 5 s per name on
	// a machine with an unreachable resolver, and seven names would add up to
	// a minute of apparent hang.
	r := &net.Resolver{}
	for _, n := range noms {
		c, annule := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := r.LookupHost(c, n)
		annule()
		res = append(res, ResultatDNS{Nom: n, Adresses: addrs, Err: err})
	}
	return res
}

// Rapport décrit les problèmes de DNS, sans rien tenter.
//
// THE LIST OF EXPECTED NAMES IS BUILT FROM THE DOMAIN, so it grows with the
// product. Each one is a real host the deployment will serve: forgetting one
// here means the certificate for that host fails later, with an error that
// points at Traefik or cert-manager rather than at the missing record.
func Rapport(resultats []ResultatDNS, attendue string, domainePublic bool) []string {
	var problemes []string
	for _, r := range resultats {
		if !domainePublic {
			// Private domain: no public DNS is expected, nothing to report.
			continue
		}
		switch {
		case r.Err != nil:
			problemes = append(problemes,
				fmt.Sprintf("%s : ne resout pas (%v)", r.Nom, r.Err))
		case len(r.Adresses) == 0:
			problemes = append(problemes, fmt.Sprintf("%s : ne resout vers aucune adresse", r.Nom))
		case !r.OK(attendue):
			problemes = append(problemes, fmt.Sprintf("%s : resout vers %s, attendu %s",
				r.Nom, strings.Join(r.Adresses, ", "), attendue))
		}
	}
	return problemes
}

// AdresseLocale rend l'adresse que le DNS doit annoncer pour cet hôte.
//
// ANNOUNCED ADDRESS, NOT INTERFACE ADDRESS. On a machine behind NAT they
// differ, and the certificate is issued for the name: the operator must point
// the record at the address the INTERNET sees. We read it from a public
// echo service rather than from an interface, because an interface address on
// such a host is private and would make every check fail for the wrong reason.
func AdressePublique(ctx context.Context) string {
	// Only over IPv4: a dual-stack answer can return the v6 address first, and
	// most operators publish a single A record. Comparing against the wrong
	// family would report a failure that does not exist.
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"curl -4 -sf --max-time 8 https://api.ipify.org || curl -4 -sf --max-time 8 https://ifconfig.me/ip")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// MinHardwareOK says whether the machine meets the design minimum.
//
// Returns the shortfalls rather than a boolean, so the message can name what
// is missing instead of just refusing.
func MinHardwareOK(hw Hardware) []string {
	min := MinHardware()
	var manque []string
	if hw.CPUs < min.CPUs {
		manque = append(manque, fmt.Sprintf("%d vCPU (minimum %d)", hw.CPUs, min.CPUs))
	}
	if hw.MemoryTotalMB > 0 && hw.MemoryTotalMB < min.MemoryTotalMB {
		manque = append(manque, fmt.Sprintf("%d MB de RAM (minimum %d)",
			hw.MemoryTotalMB, min.MemoryTotalMB))
	}
	return manque
}
