// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/recording/relay"
)

// newRecordingRelayCmd runs the relay that sits in front of the recorder.
//
// HIDDEN, AND NOT AN OPERATOR COMMAND: it is started by the recorder's pod (lot
// B2 of the plan), never by hand. Showing it in `ceffio --help` would suggest
// there is something to run, when the whole point is that nobody has to.
//
// WHY IT IS PART OF THE BINARY rather than its own image: it has to be always
// present, even when the capture module is not installed, and the Ceffio image
// already ships in the cluster and in the local registry. A relay image would
// add a second thing to publish, pin and import offline.
func newRecordingRelayCmd() *cobra.Command {
	var ecoute, amont, notifier, fichierSecret string

	c := &cobra.Command{
		Use:   "recording-relay",
		Short: "Forward Talk's recording requests, and tell the capture (used by the pod)",
		Long: `Runs in front of the recording server.

Every request Talk sends to the recorder passes through it untouched -- same
path, same body, same headers, same answer. Only after the recorder has
answered 2xx does it tell the capture service that a recording started or
stopped, in the background, without ever letting the capture slow the recording
down.

It is started by the recorder's own pod; this command is not part of the
operator's daily work, which is why it is hidden.`,
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// THE SECRET COMES FROM A FILE, NOT FROM THE ENVIRONMENT, and the
			// reason is the image this process runs in: the Ceffio image is
			// built FROM scratch, so it has no shell to source the injector's
			// /secrets/env — the file of shell assignments the recorder's
			// container reads. The injector therefore renders a SECOND file for
			// this container, holding the value and nothing else, and it is read
			// here.
			//
			// A FILE RATHER THAN A FLAG, too: a secret on a command line is
			// readable in /proc/<pid>/cmdline.
			//
			// THE ENVIRONMENT STAYS SUPPORTED: that is how a human runs the
			// command against a test recorder, and dropping it would make the
			// binary harder to try by hand for no gain.
			secret := os.Getenv("RECORDING_SECRET")
			if fichierSecret != "" {
				brut, err := os.ReadFile(fichierSecret)
				if err != nil {
					return fmt.Errorf("recording-relay: reading %s: %w", fichierSecret, err)
				}
				if len(brut) == 0 {
					return fmt.Errorf("recording-relay: %s is empty — the relay cannot "+
						"verify Talk's signature, and an unchecked relay would forward "+
						"anything to the recorder", fichierSecret)
				}
				// THE BYTES ARE THE SECRET, TRIMMED OF NOTHING: the template that
				// renders this file ends with `-}}` precisely so no newline
				// reaches it (vault.GabaritValeur). Trimming here would hide a
				// template that started appending one.
				secret = string(brut)
			}
			if secret == "" {
				return fmt.Errorf("recording-relay: no secret — set RECORDING_SECRET or " +
					"pass --secret-file; without it the relay cannot verify a signature " +
					"and would forward anything to the recorder")
			}

			logf := func(format string, a ...any) {
				fmt.Printf("%s recording-relay: %s\n",
					time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
			}

			r, err := relay.New(relay.Options{
				Upstream: amont,
				Notify:   notifier,
				Secret:   secret,
				Logf:     logf,
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if notifier == "" {
				logf("listening on %s, forwarding to %s, no capture to notify", ecoute, amont)
			} else {
				logf("listening on %s, forwarding to %s, notifying %s", ecoute, amont, notifier)
			}

			srv := &http.Server{
				Addr:    ecoute,
				Handler: r,
				// A SHORT HEADER TIMEOUT: Nextcloud is on the same cluster and
				// sends a small request. A client that opens a connection and
				// says nothing must not hold a slot.
				ReadHeaderTimeout: 5 * time.Second,
			}
			go func() {
				<-ctx.Done()
				arret, annuler := context.WithTimeout(context.Background(), 5*time.Second)
				defer annuler()
				_ = srv.Shutdown(arret)
			}()

			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("recording-relay: %w", err)
			}
			return nil
		},
	}

	c.Flags().StringVar(&ecoute, "listen", ":1235",
		"address to listen on (the Service keeps 1234, and targets this port)")
	c.Flags().StringVar(&amont, "upstream", "http://127.0.0.1:1234",
		"the recorder, in the same pod")
	c.Flags().StringVar(&notifier, "notify", "http://ceffio-capture.ceffio-video.svc:8080/v1/recording",
		"the capture's endpoint; empty disables the notification")
	c.Flags().StringVar(&fichierSecret, "secret-file", "",
		"file holding the recording secret (the pod's injected file); "+
			"RECORDING_SECRET is used when this is empty")
	return c
}
