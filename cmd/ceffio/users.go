package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newUsersCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "users",
		Short: "Manage users (Keycloak + application provisioning)",
	}
	c.AddCommand(newUsersAddCmd())
	return c
}

func newUsersAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add EMAIL",
		Short: "Create a user (Keycloak, Nextcloud, mailbox)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("provisioning user %q: not implemented yet", args[0])
		},
	}
}
