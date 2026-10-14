package main

import (
	"github.com/spf13/cobra"
)

func newDNSCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "dns",
		Short: "Check the DNS configuration (A, AAAA, MX, SPF, DKIM, DMARC, PTR)",
	}
	c.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show the state of the DNS configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("dns status")
		},
	})
	return c
}
