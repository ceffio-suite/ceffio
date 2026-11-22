// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/ldapshim"
)

// newLDAPResponderCmd runs the responder that OpenProject's header SSO needs.
//
// HIDDEN, AND NOT AN OPERATOR COMMAND: it is started by the OpenProject module's
// own pod, never by hand. Showing it in `ceffio --help` would suggest there is
// something to run, when the whole point is that nobody has to.
//
// WHY IT IS PART OF THE BINARY rather than its own image: the Ceffio image is
// already in the cluster — pulled, pinned, scanned — and the deployment imports
// it from the local registry like every other suite image. A second image would
// add a second thing to publish, pin and import offline for a service that
// changes with the vendor image it serves.
func newLDAPResponderCmd() *cobra.Command {
	var listen, attribute string

	c := &cobra.Command{
		Use:   "ldap-responder",
		Short: "Answer OpenProject's header-SSO user lookup (used by the pod)",
		Long: `Answers the one LDAP search OpenProject makes when it signs a user in
through a trusted header.

It is READ-ONLY and STATELESS: it holds no directory, verifies no password, and
builds its single answer from the query itself. The password was checked by the
identity provider, and whether the person may enter is decided by OpenProject's
own database — the lookup leads nowhere for a user the administrator did not
create and link to the source.

It is started by the OpenProject module's own pod; this command is not part of
the operator's daily work, which is why it is hidden.`,
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			logf := func(format string, a ...any) {
				fmt.Printf("%s ldap-responder: %s\n",
					time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listen)
			if err != nil {
				return fmt.Errorf("ldap-responder: listening on %s: %w", listen, err)
			}
			// THE LOG GOES TO THE POD'S STDOUT, and holds the login of every
			// answered lookup: it is the only place an operator can follow the
			// chain identity provider -> proxy -> lookup -> session.
			logf("listening on %s, answering %s lookups, no directory and no secret", listen, attribute)
			return ldapshim.Serve(ctx, listener, ldapshim.Options{
				Attribute: attribute,
				Log:       os.Stdout,
			})
		},
	}

	c.Flags().StringVar(&listen, "listen", ":1389",
		"address to listen on (the Service keeps 1389)")
	c.Flags().StringVar(&attribute, "attribute", "uid",
		"the attribute whose equality value is taken as a login; "+
			"must match the OpenProject source's login attribute")
	return c
}
