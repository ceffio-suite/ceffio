package main

import (
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnostiquer l'état de la plateforme",
		Long: `Vérifie les modules system, kubernetes, storage, dns, tls, database,
identity, files, office, matrix, video, mail et backup.

Utilisez --bundle pour produire une archive de support (sans aucun secret).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("doctor")
		},
	}

	c.Flags().Bool("bundle", false, "Produire une archive de support (mysuite-support-*.tar.gz)")

	return c
}
