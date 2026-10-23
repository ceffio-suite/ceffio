// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/publicip"
)

func newPublicIPCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "publicip",
		Short: "Inspect the public IPv4 address discovery",
		Long: `Shows the address the reporter published, checks every configured source,
and runs the reporter itself.

The reporter is normally run as a pod by ceffio install. "ceffio publicip check"
is what to run when a call connects without audio: it tells whether the
discovery itself is broken, one source at a time, instead of leaving the
operator to guess between the STUN server, the HTTP fallback and the firewall.`,
	}
	c.AddCommand(newPublicIPShowCmd(), newPublicIPCheckCmd(), newPublicIPServeCmd(), newPublicIPDeployCmd())
	return c
}

func newPublicIPShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the published address",
		RunE: func(cmd *cobra.Command, args []string) error {
			cs, err := kubeClient()
			if err != nil {
				return err
			}
			a, ok, err := publicip.Lire(cmd.Context(), cs)
			if err != nil {
				return err
			}
			if !ok || a.Vide() {
				fmt.Println("No public address published yet.")
				fmt.Println("  The reporter may not be running: ceffio module status public-ip")
				return nil
			}
			fmt.Printf("Public address  %s\n", a.IPv4)
			fmt.Printf("  source        %s (%d/%d sources agree)\n", a.Source, a.Sources, a.Total)
			fmt.Printf("  updated       %s ago\n", time.Since(a.UpdatedAt).Round(time.Second))
			if len(a.Divergence) > 0 {
				fmt.Printf("  divergence    %s\n", strings.Join(a.Divergence, ", "))
				fmt.Println("  · the sources do not agree: check for a multi-pool NAT or a filtered network")
			}
			return nil
		},
	}
}

func newPublicIPCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Test every configured discovery source",
		Long: `Queries each STUN server and each HTTP fallback separately, and prints
which ones answer and how long they took.

This is deliberately NOT the consensus path: the consensus hides a dead source
as long as two others agree, and a dead source is exactly what the operator is
looking for.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cs, err := kubeClient()
			if err != nil {
				return err
			}
			cfg := publicip.ChargerConfig(cmd.Context(), cs)
			if cfg.Static != "" {
				fmt.Printf("static address configured: %s (discovery disabled)\n", cfg.Static)
				return nil
			}

			resultats := publicip.Verifier(cmd.Context(), cfg, nil)
			fmt.Printf("%-42s %-16s %-8s %s\n", "SOURCE", "ADDRESS", "TIME", "STATUS")
			adresses := map[string]int{}
			for _, r := range resultats {
				etat := "ok"
				if !r.OK {
					etat = "FAILED — " + r.Erreur
				} else {
					adresses[r.IP]++
				}
				fmt.Printf("%-42s %-16s %-8s %s\n", r.Source, r.IP, r.Duree, etat)
			}
			if len(adresses) > 1 {
				fmt.Println()
				fmt.Println("! the sources disagree — a transparent proxy or a multi-pool NAT is rewriting the address")
			}
			return nil
		},
	}
}

// newPublicIPDeployCmd deploys the reporter alone.
//
// WHY A SEPARATE COMMAND: the reporter is normally deployed by `ceffio install`,
// but it is the one component whose absence is invisible — Janus and coturn
// silently fall back to their own lookup. Being able to repair it, or to
// validate it on an existing installation, without replaying a whole install is
// the difference between a five-second fix and a maintenance window.
func newPublicIPDeployCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "deploy",
		Short:  "Deploy or repair the reporter alone",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cs, err := kubeClient()
			if err != nil {
				return err
			}
			if err := publicip.Deploy(cmd.Context(), cs); err != nil {
				return err
			}
			fmt.Println("Reporter deployed — it publishes within a minute (ceffio publicip show).")
			return nil
		},
	}
}

func newPublicIPServeCmd() *cobra.Command {
	var addr string
	c := &cobra.Command{
		Use:    "serve",
		Short:  "Run the reporter (used by the pod)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cs, err := kubeClient()
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			logf := func(format string, a ...any) {
				fmt.Printf("%s publicip: %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
			}
			cfg := publicip.ChargerConfig(ctx, cs)
			logf("starting: %d STUN server(s), %d HTTP fallback(s), refresh %s", len(cfg.STUN), len(cfg.HTTP), cfg.Interval)

			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "ok\n")
			})
			// The HTTP endpoint is a CONVENIENCE for shells and humans; the
			// ConfigMap remains the source of truth the layers read.
			mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
				a, ok, err := publicip.Lire(r.Context(), cs)
				if err != nil || !ok || a.Vide() {
					http.Error(w, "no address published", http.StatusServiceUnavailable)
					return
				}
				_, _ = io.WriteString(w, a.IPv4+"\n")
			})

			srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logf("health server: %v", err)
				}
			}()
			go func() {
				<-ctx.Done()
				arret, annuler := context.WithTimeout(context.Background(), 5*time.Second)
				defer annuler()
				_ = srv.Shutdown(arret)
			}()

			return publicip.Surveiller(ctx, cs, logf, nil)
		},
	}
	c.Flags().StringVar(&addr, "addr", ":8080", "health/API listen address")
	return c
}
