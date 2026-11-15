// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/expos"
	"github.com/spf13/cobra"
)

func newExposeCmd() *cobra.Command {
	var cfgFichier string
	var oui bool
	var portsDrapeau string

	c := &cobra.Command{
		Use:   "expose",
		Short: "Publish the suite behind the firewall (OPNsense + os-caddy)",
		Long: `Declares Ceffio's public domains on the firewall side and routes them to the VM.

Deploying is not enough to make the suite reachable: the firewall terminates
the public TLS and must know every domain. Without this step, the DNS answers
but nothing reaches the cluster.

Complete order of a publication:
  1. the public DNS record exists                    (created by the operator)
  2. the wildcard certificate exists on the firewall (created by the operator)
  3. the domains + handlers are declared               <- this command
  4. the public hosts are added to the Traefik Ingresses (done by install/upgrade)

With --ports (or "ports" in the configuration file), the same command also
declares the L4/TCP port forwards the mail module needs: 25 for inbound SMTP,
and 465/993 for external clients. When the firewall API cannot create them,
the command does not fail: it prints the exact rules to create by hand. A port
is only proven by the inbound-25 check of ` + "`ceffio module check mail`" + `.

The configuration is read from a file (--config): firewall credentials,
domain, internal target. No value is written into the repository.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := expos.LireConfig(cfgFichier)
			if err != nil {
				return err
			}
			ports, err := portsEffectifs(portsDrapeau, cfg.Ports)
			if err != nil {
				return err
			}

			fmt.Println("Ceffio — publication behind the firewall")
			fmt.Println()
			fmt.Printf("Firewall : %s\n", cfg.HoteAPI)
			fmt.Printf("Domain   : %s\n", cfg.Domaine)
			fmt.Printf("Target   : %s:%s\n", cfg.IPInterne, cfg.PortInterne)
			if len(ports) > 0 {
				fmt.Printf("Ports    : TCP %s (L4 forwards to %s)\n", listePorts(ports), cfg.IPInterne)
			}
			fmt.Println()

			if !oui {
				fmt.Println("The following domains will be declared:")
				for _, s := range cfg.SousDomaines {
					fmt.Printf("  %s.%s\n", s, cfg.Domaine)
				}
				if len(ports) > 0 {
					fmt.Println("\nThe following TCP port forwards will be declared:")
					for _, p := range ports {
						fmt.Printf("  WAN %d -> %s:%d\n", p, cfg.IPInterne, p)
					}
				}
				fmt.Print("\nConfirm (type \"yes\"): ")
				var rep string
				fmt.Scanln(&rep)
				if rep != "yes" {
					fmt.Println("Canceled.")
					return nil
				}
				fmt.Println()
			}

			// The domain publication failing must not hide the L4 rules: the
			// two paths are independent, and those rules are what the mail
			// module needs. The domain error is returned at the very end, once
			// the port section has been printed.
			res, errDomaines := expos.Publier(cmd.Context(), cfg, func(e string) {
				fmt.Printf("  · %s\n", e)
			})
			if res == nil {
				res = &expos.Resultat{}
			}
			if errDomaines == nil {
				fmt.Println()
				for _, d := range res.Existants {
					fmt.Printf("  = %s (already declared)\n", d)
				}
				for _, d := range res.Created {
					fmt.Printf("  + %s\n", d)
				}
			} else if len(res.Created) > 0 {
				fmt.Println()
				for _, d := range res.Created {
					fmt.Printf("  ✓ %s\n", d)
				}
			}

			if len(ports) > 0 {
				publierPorts(cmd.Context(), cfg, ports)
			}
			if errDomaines != nil {
				return errDomaines
			}

			fmt.Println()
			fmt.Printf("✓ %d domain(s) published, certificate %s\n", len(res.Created), res.Certificat)

			fmt.Println()
			fmt.Println("Check from outside:")
			for _, d := range cfg.SousDomaines {
				fmt.Printf("  curl -sI https://%s.%s/\n", d, cfg.Domaine)
			}
			if len(ports) > 0 {
				fmt.Println()
				fmt.Println("A port forward is not proven from here, and the firewall API only says")
				fmt.Println("that it saved the rule. Verify with:")
				fmt.Println("  ceffio module check mail")
				fmt.Println("The inbound-25 check dials the public IP:25 from the server and is")
				fmt.Println("reported as a warning: it proves the port is open on the host side only.")
			}
			return nil
		},
	}

	c.Flags().StringVar(&cfgFichier, "config", "ceffio-expose.json", "Publication configuration file")
	c.Flags().BoolVar(&oui, "yes", false, "Do not ask for confirmation")
	c.Flags().StringVar(&portsDrapeau, "ports", "",
		"L4/TCP ports to forward to the target, comma-separated (e.g. 25,465,993); overrides \"ports\" from the configuration file")

	return c
}

// publierPorts prints the L4 section and never fails: the expos package has
// already turned every API problem into a warning plus the manual rules, so
// this function only formats what it gets. It is called even when the domain
// publication failed, because the two publications are independent — an
// operator who came for the mail ports still needs them when the os-caddy side
// is broken.
func publierPorts(ctx context.Context, cfg expos.Config, ports []int) {
	fmt.Println()
	fmt.Println("L4 port forwards:")
	res, err := expos.PublierPorts(ctx, cfg, ports, func(e string) {
		fmt.Printf("  · %s\n", e)
	})
	if err != nil {
		// Documented as impossible; if it ever changes, say so instead of
		// pretending the ports are handled.
		fmt.Printf("  ! port publication failed: %v\n", err)
		return
	}
	for _, p := range res.PortsExistants {
		fmt.Printf("  = port %d already forwarded\n", p)
	}
	for _, p := range res.PortsOuverts {
		if portParmi(res.PortsExistants, p) {
			continue
		}
		fmt.Printf("  + port %d forwarded\n", p)
	}
	// "confirmed by the firewall API", never "open": the API saved the rule, it
	// did not prove that the internet reaches it. Only the inbound-25 check of
	// the mail module says something about that, and only from the host side.
	fmt.Printf("  %d/%d port forward(s) confirmed by the firewall API\n",
		len(res.PortsOuverts), len(ports))
	if len(res.ReglesManuelles) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("The firewall API did not confirm every port forward:")
	for _, a := range res.Avertissemts {
		fmt.Printf("  ! %s\n", a)
	}
	fmt.Println()
	fmt.Println("Create these rules by hand (Firewall > NAT > Port Forward, then the")
	fmt.Println("matching pass rule on the WAN interface):")
	for _, r := range res.ReglesManuelles {
		fmt.Printf("    %s\n", r)
	}
}

// portsEffectifs returns the ports to forward: the --ports flag when it is set,
// the configuration file otherwise. The two are not merged on purpose — an
// operator who passes --ports expects exactly those ports, and a silent union
// with the file would make a typo in the file reappear as an extra forward.
func portsEffectifs(drapeau string, fichier []int) ([]int, error) {
	if strings.TrimSpace(drapeau) == "" {
		// File values are filtered (0, >65535, duplicates) by the expos
		// package, so the preview and the publication agree on what is kept;
		// the flag is validated here instead, because a typing mistake on the
		// command line deserves an error rather than a silently ignored port.
		return expos.PortsValides(fichier), nil
	}
	var ports []int
	for _, item := range strings.Split(drapeau, ",") {
		item = strings.TrimSpace(item)
		n, err := strconv.Atoi(item)
		if err != nil {
			return nil, fmt.Errorf("--ports: %q is not a port number", item)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("--ports: %d is outside 1-65535", n)
		}
		ports = append(ports, n)
	}
	return expos.PortsValides(ports), nil
}

// trierPorts sorts and deduplicates, so that the preview and the published
// result list the same ports in the same order.

// listePorts renders "25, 465" for the header line.
func listePorts(ports []int) string {
	noms := make([]string, len(ports))
	for i, p := range ports {
		noms[i] = strconv.Itoa(p)
	}
	return strings.Join(noms, ", ")
}

func portParmi(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

var _ = os.Getenv
