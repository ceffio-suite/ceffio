package main

import (
	"github.com/spf13/cobra"
)

func newDNSCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "dns",
		Short: "Vérifier la configuration DNS (A, AAAA, MX, SPF, DKIM, DMARC, PTR)",
	}
	c.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Afficher l'état de la configuration DNS",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("dns status")
		},
	})
	return c
}
