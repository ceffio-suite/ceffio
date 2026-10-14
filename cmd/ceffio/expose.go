package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/expos"
	"github.com/spf13/cobra"
)

func newExposeCmd() *cobra.Command {
	var cfgFichier string
	var oui bool

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

The configuration is read from a file (--config): firewall credentials,
domain, internal target. No value is written into the repository.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := expos.LireConfig(cfgFichier)
			if err != nil {
				return err
			}

			fmt.Println("Ceffio — publication behind the firewall")
			fmt.Println()
			fmt.Printf("Firewall : %s\n", cfg.HoteAPI)
			fmt.Printf("Domain   : %s\n", cfg.Domaine)
			fmt.Printf("Target   : %s:%s\n", cfg.IPInterne, cfg.PortInterne)
			fmt.Println()

			if !oui {
				fmt.Println("The following domains will be declared:")
				for _, s := range cfg.SousDomaines {
					fmt.Printf("  %s.%s\n", s, cfg.Domaine)
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

			res, err := expos.Publier(cmd.Context(), cfg, func(e string) {
				fmt.Printf("  · %s\n", e)
			})
			if err != nil {
				if res != nil && len(res.Created) > 0 {
					fmt.Println()
					for _, d := range res.Created {
						fmt.Printf("  ✓ %s\n", d)
					}
				}
				return err
			}

			fmt.Println()
			for _, d := range res.Existants {
				fmt.Printf("  = %s (already declared)\n", d)
			}
			for _, d := range res.Created {
				fmt.Printf("  + %s\n", d)
			}
			fmt.Println()
			fmt.Printf("✓ %d domain(s) published, certificate %s\n", len(res.Created), res.Certificat)
			fmt.Println()
			fmt.Println("Check from outside:")
			for _, d := range cfg.SousDomaines {
				fmt.Printf("  curl -sI https://%s.%s/\n", d, cfg.Domaine)
			}
			return nil
		},
	}

	c.Flags().StringVar(&cfgFichier, "config", "ceffio-expose.json", "Publication configuration file")
	c.Flags().BoolVar(&oui, "yes", false, "Do not ask for confirmation")

	return c
}

var _ = os.Getenv
