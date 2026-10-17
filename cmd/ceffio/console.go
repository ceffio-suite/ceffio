// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
)

func newConsoleCmd() *cobra.Command {
	var domain string
	var addr string
	var apiKey string
	var deployer bool
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Ceffio administration console (dashboard + SSO users)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			// THE SECRETS COME FROM THE VAULT, through the file the injector
			// made available. The console image contains no shell: it
			// therefore cannot "source" this file, it reads it. Without
			// injection, the file is absent and nothing is set — that is the
			// expected behavior outside the cluster.
			if err := secrets.ChargerDepuisFichier("/secrets/env"); err != nil {
				return err
			}
			// VAULT ACCESS OF THE CONSOLE ITSELF. The injector renders the
			// application secrets, NEVER vault credentials — so when the
			// console acts as an installer (deploy HaRP, write a shared key),
			// secrets.DepuisEnvironnement() used to find nothing and answer
			// « no vault configured ». In-cluster, the pod authenticates with
			// its own ServiceAccount (role "console", policy ceffio-console,
			// 1 h token refreshed while the server runs). Outside a cluster
			// this is a no-op and the CLI's resoudreCoffre stays in charge.
			vault.MaintenirJetonInCluster(c.Context())
			if domain == "" {
				return fmt.Errorf("--domain is required")
			}
			// DEPLOYMENT INTO THE CLUSTER: we stop here.
			//
			// Generating a key would make no sense in this case — the
			// console's lives in a Secret, and it is the deployment that
			// creates or reuses it. Making one here, then printing it, would
			// give a key that opens nothing: the most bewildering outage,
			// since it looks like a valid token.
			if deployer {
				// The vault must be resolved BEFORE: the console's
				// administration key is read from and written to it, there is
				// no Kubernetes Secret anymore.
				resoudreCoffre(c)
				return console.Deploy(c.Context(), domain)
			}
			if apiKey == "" {
				apiKey = os.Getenv("CEFFIO_KEY")
			}
			if apiKey == "" {
				k, err := genConsoleKey()
				if err != nil {
					return err
				}
				fmt.Println("No key provided → generated key:")
				fmt.Println(k)
				apiKey = k
			}
			srv, err := console.New(domain, apiKey)
			if err != nil {
				return err
			}
			log.Printf("Ceffio console started on %s (admin.<%s>)", addr, domain)
			return http.ListenAndServe(addr, srv.Handler())
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "Public domain (e.g. demo.local)")
	cmd.Flags().StringVar(&addr, "addr", ":8088", "Listen address")
	cmd.Flags().StringVar(&apiKey, "key", "", "Admin token (generated otherwise)")
	cmd.Flags().BoolVar(&deployer, "deploy", false,
		"Deploy the console into the cluster (instead of running it on this machine)")
	return cmd
}

func genConsoleKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
