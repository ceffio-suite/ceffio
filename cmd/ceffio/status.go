package main

import (
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Afficher l'état du déploiement Ceffio",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("status")
		},
	}
}
