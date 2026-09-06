package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newUsersCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "users",
		Short: "Gérer les utilisateurs (provisioning Keycloak + applications)",
	}
	c.AddCommand(newUsersAddCmd())
	return c
}

func newUsersAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add EMAIL",
		Short: "Créer un utilisateur (Keycloak, Nextcloud, Matrix, boîte mail)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("provisioning de l'utilisateur %q : pas encore implémenté", args[0])
		},
	}
}
