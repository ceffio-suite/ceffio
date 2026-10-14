package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/talk"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// newTalkCmd deploys the Talk stack (HPB) ALONE.
//
// SAME REASON AS FOR MAIL, OFFICE AND THE CONSOLE: Talk was only deployable
// through `install`, which replays the whole stack. Yet it is the component
// whose TWO secrets are shared with Nextcloud — so the one we want to be able
// to redeploy alone after a rotation, without touching the rest.
func newTalkCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "talk",
		Short: "Deploy the Talk stack (coturn, Janus, NATS, signaling) alone",
		Long: `Deploys the high-performance signaling server and its hookup to Nextcloud.

THE SECRETS COME FROM THE VAULT, AND FROM NOWHERE ELSE. The two workloads that
consume them — coturn and signaling — read them at startup through an agent,
and the Nextcloud hookup reads the SAME entry. That is what guarantees that the
shared signaling secret and the TURN servers' secret stay identical on both
sides: a rotation never touches one without the other.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			// We resolve vault access BEFORE everything else: without it, the
			// command could neither read nor write the secrets, and the
			// Nextcloud hookup would fail without saying why.
			if client, err := k8sapi.Nouveau(); err == nil {
				if adresse, jeton, err := vault.Acces(c.Context(), client); err == nil {
					os.Setenv("BAO_ADDR", adresse)
					os.Setenv("BAO_TOKEN", jeton)
					os.Setenv("BAO_MOTEUR", "kv")
					fmt.Printf("  ∙ vault: %s (single source of secrets)\n", adresse)
				} else {
					fmt.Printf("  ∙ vault unresolved (%v) — the deployment is going to fail: that is intended\n", err)
				}
			}
			return talk.Deploy(c.Context())
		},
	}
	return c
}
