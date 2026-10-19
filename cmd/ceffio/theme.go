// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"github.com/ceffio-suite/ceffio/internal/theming"
	"github.com/spf13/cobra"
)

// newThemeCmd applies the Ceffio theme to Nextcloud on its own.
//
// SAME REASON AS FOR MAIL, OFFICE AND THE CONSOLE: the theme was only applied
// through `install`, which replays the whole stack — bootstrap, identity,
// files, mail, certificates. Yet the theme is precisely what one wants to
// reapply WITHOUT touching anything else, in two situations:
//
//   - after a NEXTCLOUD UPGRADE, which can reset theming values: the login page
//     goes back to the Nextcloud identity and the operator has no way of
//     resetting it short of re-running `install`;
//   - after a Ceffio RELEASE that changes the theme: the new colours and logos
//     reach existing installations through this command, not through a full
//     reinstall.
//
// The command is idempotent: it re-poses the same values, so running it twice
// changes nothing.
func newThemeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "theme",
		Short: "Reapply the Ceffio theme to Nextcloud",
		Long: `Applies the Ceffio identity (name, slogan, colours, logo, favicon,
background) to the Nextcloud of a running installation, through Nextcloud's own
Theming app.

WHY THE BUILT-IN THEMING APP AND NOT A THEME FOLDER OR CUSTOM CSS: a theme folder
is a legacy mechanism, and hand-written CSS breaks at Nextcloud upgrades. The
Theming app is the supported surface, and it survives upgrades — which is
exactly why the theme can be reapplied by a single command after one.

Idempotent: safe to run again at any time.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			return theming.Deploy(c.Context())
		},
	}
	return c
}
