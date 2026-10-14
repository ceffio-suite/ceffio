package main

import (
	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags "-X main.version=...".
// Default value for local builds.
var version = "0.1.0-dev"

func newRootCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ceffio",
		Short: "Ceffio — your sovereign, self-hosted collaborative suite",
		Long: `Ceffio deploys a complete collaborative suite (SSO identity, files,
documents, chat, videoconferencing, mail) on Kubernetes (K3s by default)
with a single command.

Ceffio is an integration layer, not a fork: it orchestrates proven
open source projects (Keycloak, Nextcloud, ONLYOFFICE, Talk,
Stalwart) behind a unified install and management experience.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}

	c.AddCommand(
		newInstallCmd(),
		newUninstallCmd(),
		newConsoleCmd(),
		newMailCmd(),
		newOfficeCmd(),
		newTalkCmd(),
		newIdentityCmd(),
		newFilesCmd(),
		newStatusCmd(),
		newDoctorCmd(),
		newBackupCmd(),
		newRestoreCmd(),
		newUpgradeCmd(),
		newUsersCmd(),
		newDNSCmd(),
		newExposeCmd(),
		newVaultCmd(),
	)

	return c
}
