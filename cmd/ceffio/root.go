// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/version"
)

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
		Version:       version.Binary,
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
