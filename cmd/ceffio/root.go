package main

import (
	"github.com/spf13/cobra"
)

// version est surchargée au build via -ldflags "-X main.version=...".
// Valeur par défaut pour les builds locaux.
var version = "0.1.0-dev"

func newRootCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ceffio",
		Short: "Ceffio — votre suite collaborative souveraine, auto-hébergée",
		Long: `Ceffio déploie une suite collaborative complète (identité SSO, fichiers,
documents, chat, visioconférence, messagerie) sur Kubernetes (K3s par défaut)
en une seule commande.

Ceffio est une couche d'intégration, pas un fork : il orchestre des projets
open source éprouvés (Keycloak, Nextcloud, ONLYOFFICE, Talk,
Stalwart) derrière une expérience unifiée d'installation et de gestion.`,
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
