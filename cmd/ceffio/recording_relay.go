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
	var ecoute, amont, notifier string

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
			// THE SECRET COMES FROM THE ENVIRONMENT, because that is how the
			// recorder's pod already receives it: the OpenBao injector writes
			// /secrets/env, and the container sources it. A flag would put the
			// secret on a command line, readable in /proc/<pid>/cmdline.
			secret := os.Getenv("RECORDING_SECRET")
			if secret == "" {
				return fmt.Errorf("recording-relay: RECORDING_SECRET is empty — the relay " +
					"cannot verify Talk's signature, and an unchecked relay would forward " +
					"anything to the recorder")
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
	return c
}
