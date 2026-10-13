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
)

func newConsoleCmd() *cobra.Command {
	var domain string
	var addr string
	var apiKey string
	var deployer bool
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Console d'administration Ceffio (dashboard + utilisateurs SSO)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if domain == "" {
				return fmt.Errorf("--domain est requis")
			}
			// DÉPLOIEMENT DANS LE CLUSTER : on s'arrête ici.
			//
			// Générer une clé n'aurait pas de sens dans ce cas — celle de la
			// console vit dans un Secret, et c'est le déploiement qui la crée ou
			// la réutilise. En fabriquer une ici, puis l'afficher, donnerait une
			// clé qui n'ouvre rien : la panne la plus déroutante, puisqu'elle
			// ressemble à un jeton valide.
			if deployer {
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
				fmt.Println("Aucune clé fournie → clé générée :")
				fmt.Println(k)
				apiKey = k
			}
			srv, err := console.New(domain, apiKey)
			if err != nil {
				return err
			}
			log.Printf("Console Ceffio démarrée sur %s (admin.<%s>)", addr, domain)
			return http.ListenAndServe(addr, srv.Handler())
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "Domaine public (ex. demo.local)")
	cmd.Flags().StringVar(&addr, "addr", ":8088", "Adresse d'écoute")
	cmd.Flags().StringVar(&apiKey, "key", "", "Jeton admin (sinon généré)")
	cmd.Flags().BoolVar(&deployer, "deploy", false,
		"Déployer la console dans le cluster (au lieu de la lancer sur cette machine)")
	return cmd
}

func genConsoleKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
