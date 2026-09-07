package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/console"
)

func newConsoleCmd() *cobra.Command {
	var domain string
	var addr string
	var apiKey string
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Console d'administration Ceffio (dashboard + utilisateurs SSO)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if domain == "" {
				return fmt.Errorf("--domain est requis")
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
			srv := console.New(domain, apiKey)
			log.Printf("Console Ceffio démarrée sur %s (admin.<%s>)", addr, domain)
			return http.ListenAndServe(addr, srv.Handler())
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "Domaine public (ex. demo.local)")
	cmd.Flags().StringVar(&addr, "addr", ":8088", "Adresse d'écoute")
	cmd.Flags().StringVar(&apiKey, "key", "", "Jeton admin (sinon généré)")
	return cmd
}

func genConsoleKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
