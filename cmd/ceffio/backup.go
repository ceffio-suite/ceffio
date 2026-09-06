package main

import (
	"github.com/spf13/cobra"
)

func newBackupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backup",
		Short: "Sauvegarder les données (PostgreSQL, fichiers, media, config)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("backup")
		},
	}
}
