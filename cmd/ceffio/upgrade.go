package main

import (
	"github.com/spf13/cobra"
)

func newUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Mettre à niveau Ceffio (compatibilité + préflight + backup)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("upgrade")
		},
	}
}
