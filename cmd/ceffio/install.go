// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ceffio-suite/ceffio/internal/apps"
	"github.com/ceffio-suite/ceffio/internal/bootstrap"
	"github.com/ceffio-suite/ceffio/internal/cluster"
	"github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/data"
	"github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/platform"
	"github.com/ceffio-suite/ceffio/internal/recording"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/sso"
	"github.com/ceffio-suite/ceffio/internal/stacks"
	"github.com/ceffio-suite/ceffio/internal/talk"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

type installOptions struct {
	domain          string
	profile         string
	runtime         string
	existingCluster bool
	mail            bool
	office          bool
	monitoring      bool

	// Outbound delivery relay. INDISPENSABLE in practice: outbound port 25 is
	// blocked by consumer ISPs (verified on Free), so Stalwart cannot deliver
	// to Gmail by itself. The authenticated relay on 587 works around this
	// block and provides the reverse DNS.
	relaisSmtpHote string
	relaisSmtpPort int
	relaisSmtpUser string
	relaisSmtpPass string
}

const devClusterName = "ceffio-dev"

func newInstallCmd() *cobra.Command {
	o := &installOptions{}

	c := &cobra.Command{
		Use:   "install",
		Short: "Install Ceffio on a machine or a Kubernetes cluster",
		Long: `Installs Ceffio end to end: Kubernetes bootstrap (K3s by default),
then deployment of the platform (ingress, TLS, database, identity)
and of the collaborative applications.

Examples:
  ceffio install
  ceffio install --domain company.fr --profile business-50
  ceffio install --runtime rke2
  ceffio install --existing-cluster`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, o)
		},
	}

	f := c.Flags()
	// PRODUCTION DEFAULT: *.ceffio.example.com is the reference domain of the
	// in-service installation (wildcard DNS + certificate + OPNsense wired up).
	// User directive: every deployment goes through this domain until further
	// notice. Overridable with --domain for another environment.
	f.StringVar(&o.domain, "domain", "ceffio.example.com", "Base domain (e.g. company.fr)")
	f.StringVar(&o.profile, "profile", "small", "Deployment profile (small, business-50, business-100, enterprise-ha)")
	f.StringVar(&o.runtime, "runtime", "k3s", "Kubernetes runtime (k3s, rke2)")
	f.BoolVar(&o.existingCluster, "existing-cluster", false, "Use an existing Kubernetes cluster")
	f.BoolVar(&o.mail, "mail", false, "Enable mail")
	f.BoolVar(&o.office, "office", true, "Enable ONLYOFFICE")
	f.BoolVar(&o.monitoring, "monitoring", true, "Enable observability")
	// Outbound relay. Default: none (Stalwart receives but does not send
	// to the outside). Since outbound port 25 is blocked by ISPs, this relay
	// is what makes mail actually usable.
	f.StringVar(&o.relaisSmtpHote, "smtp-relais", "",
		"Outbound SMTP relay (e.g. send.one.com) — required because outbound port 25 is often blocked")
	f.IntVar(&o.relaisSmtpPort, "smtp-relais-port", 587, "Outbound SMTP relay port")
	f.StringVar(&o.relaisSmtpUser, "smtp-relais-user", "", "Outbound SMTP relay user")
	f.StringVar(&o.relaisSmtpPass, "smtp-relais-pass", "", "Outbound SMTP relay password")

	return c
}

func runInstall(cmd *cobra.Command, o *installOptions) error {
	if o.domain == "" {
		return fmt.Errorf("--domain is required (e.g. --domain company.fr)")
	}

	fmt.Println("Ceffio Installer")
	fmt.Println()
	fmt.Printf("Domain:     %s\n", o.domain)
	fmt.Printf("Profile:    %s\n", o.profile)
	fmt.Printf("Runtime:    %s\n", o.runtime)
	fmt.Printf("Mail:       %s\n", yesNo(o.mail))
	fmt.Printf("Office:     %s\n", yesNo(o.office))
	fmt.Printf("Monitoring: %s\n", yesNo(o.monitoring))
	fmt.Println()

	ctx := cmd.Context()

	// 1. Hardware/OS detection + validation.
	hw := bootstrap.Detect()
	if err := bootstrap.Validate(hw.OS, hw.Arch); err != nil {
		return err
	}
	mem := "n/a"
	if hw.MemoryTotalMB > 0 {
		mem = fmt.Sprintf("%d MB", hw.MemoryTotalMB)
	}
	fmt.Printf("Machine:    %s/%s · %d vCPU · RAM %s\n", hw.OS, hw.Arch, hw.CPUs, mem)

	// 2. Runtime resolution.
	rt, err := resolveRuntime(o, hw.OS)
	if err != nil {
		return err
	}

	// 3. Kubernetes cluster provisioning.
	fmt.Printf("\nProvisioning cluster %q (%s)...\n", devClusterName, rt)
	if _, err := cluster.Provision(ctx, rt, devClusterName); err != nil {
		return err
	}

	// 4. Wait + health check.
	// 5 min: on a cold VM, k3s must start its API, pull the system images
	// (Traefik, CoreDNS, local-path) and get the node Ready.
	// 120 s systematically failed on first boot (node Ready around ~3 min).
	if err := cluster.WaitReady(ctx, 5*time.Minute); err != nil {
		return err
	}
	nodes, err := cluster.Health(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("\n✓ Cluster %q ready (%d node(s))\n", devClusterName, len(nodes))
	for _, n := range nodes {
		fmt.Printf("  ✓ node/%s Ready\n", n)
	}

	// 5. Platform deployment (Phase 2).
	//
	// Parallelization: we serialize ONLY the real dependencies.
	//   platform (namespaces, cert-manager, issuers) and data (PostgreSQL, Redis)
	//   do not depend on each other → run in parallel.
	//   identity depends on data (Keycloak needs its database) → after.
	fmt.Println("\n∙ phases 2-3 in parallel (platform ‖ data)")
	if err := runParallel(ctx,
		namedTask{"platform (Phase 2)", func(ctx context.Context) error { return platform.Deploy(ctx) }},
		namedTask{"data (Phase 3)", func(ctx context.Context) error { return data.Deploy(ctx) }},
	); err != nil {
		return err
	}

	// 6. Secrets vault (OpenBao).
	//
	// PLACED HERE, AND NOWHERE ELSE: before identity and before every
	// application layer, because from this point on the components can READ
	// their secrets instead of inventing them. If it were deployed later, each
	// component would already have generated its own and they would have to be
	// migrated after the fact — which means doing the work over again.
	//
	// AFTER the platform, on the other hand: the vault needs neither
	// cert-manager nor PostgreSQL. The order is therefore:
	// platform → vault → everything else.
	//
	// Nothing here is mandatory: if the vault fails, continuing with
	// Kubernetes Secrets is the expected behavior (see internal/secrets).
	//
	// WE PUBLISH THE ADDRESS AND THE TOKEN INTO THE ENVIRONMENT: this is how
	// the following modules will find them, via secrets.DepuisEnvironnement().
	// Without this publication, the vault would be deployed but nobody would
	// read from it — a full vault that the components would keep ignoring.
	//
	// The name is coffreBao and not coffre: the rest of the file already calls
	// "coffre" the configuration read from the environment.
	coffreBao := vault.Deploy(ctx, o.domain)
	if coffreBao.Pret {
		os.Setenv("BAO_ADDR", coffreBao.Adresse)
		os.Setenv("BAO_TOKEN", coffreBao.Jeton)
		os.Setenv("BAO_MOTEUR", "kv")
		fmt.Printf("∙ vault published for the following steps: %s (token not shown)\n", coffreBao.Adresse)
	} else {
		fmt.Println("∙ vault unavailable: secrets will stay in Kubernetes (expected behavior)")
	}

	// 7. Identity / SSO (Phase 4) — depends on the PostgreSQL database.
	if err := identity.Deploy(ctx); err != nil {
		return err
	}

	// 8-10. Application layers: files, chat and video are INDEPENDENT of each
	// other — they only depend on the platform (namespaces, ingress) and on
	// identity (hostAliases → Traefik, CA). They are therefore deployed in
	// parallel, which divides this step's time by ~3.
	// EXCLUDED from the parallel batch (real dependencies, verified in code):
	//   - office: activated via "occ" INSIDE Nextcloud → requires Nextcloud Ready;
	//   - sso/AdoptURLs: write into Keycloak, Nextcloud and Synapse → after all.
	fmt.Println("\n∙ phases 5/7/10 in parallel (files ‖ chat ‖ video)")
	// Chat and video are now provided by Nextcloud Talk (a Nextcloud app),
	// deployed with the files layer: no more Synapse/Element or Jitsi.
	appTasks := []namedTask{
		{"files (Phase 5)", func(ctx context.Context) error { return files.Deploy(ctx) }},
	}
	if err := runParallel(ctx, appTasks...); err != nil {
		return err
	}

	// 11. Office (Phase 6) — AFTER files: the ONLYOFFICE connector is
	// configured via "occ" in the Nextcloud pod (it must be Ready).
	if err := office.Deploy(ctx); err != nil {
		return err
	}

	// 12. SSO (the MVB's single sign-on): Keycloak OIDC clients + Nextcloud + Synapse.
	if err := sso.EnsureOIDCClients(ctx, o.domain); err != nil {
		return err
	}
	// Removal of the old stack (Matrix + Jitsi): idempotent cleanup of its
	// remnants on an existing cluster. Talk replaces BOTH chat and video.
	if err := stacks.RetirerMatrixEtJitsi(ctx, o.domain); err != nil {
		return err
	}
	// Talk + High Performance Backend: messaging AND videoconferencing, inside
	// Nextcloud. Deployed after the removal, to free up resources first.
	if err := talk.Deploy(ctx); err != nil {
		return err
	}
	// Nextcloud applications (Phase 12): the controlled collaboration apps
	// (free license, stable version). Without this module, a fresh install
	// would have NONE of these apps — they would only live on the machine
	// where they were installed by hand.
	if err := apps.Deploy(ctx); err != nil {
		return err
	}

	// 12bis. Mail (Phase 13): Stalwart. Nextcloud provides the interface
	// (Mail app) but not the mail server. The outbound relay is INDISPENSABLE
	// here: outbound port 25 is blocked by the ISP (verified), so Stalwart
	// cannot deliver to Gmail by itself.
	if err := mail.Deploy(ctx, o.domain, o.relaisSmtpHote, o.relaisSmtpPort,
		o.relaisSmtpUser, o.relaisSmtpPass); err != nil {
		return err
	}

	// 12ter. Stalwart single sign-on. The mail server has its own
	// administration interface, and it must delegate to Keycloak like the
	// rest of the platform. This block replays exactly the configuration that
	// was established by hand: each line corresponds to a real blocker,
	// notably the four role tables of the Authentication object, without
	// which an otherwise successful login ends in a "403".
	//
	// The domain of the ADDRESSES is the platform domain, not the web host
	// "mail.<domain>": those are two distinct things, and confusing them
	// would put the MX records in the wrong place.
	if err := mail.ConfigurerSSO(ctx, o.domain, mail.SSO{
		Hote:         mail.DomaineMessagerie(o.domain),
		Issuer:       "https://keycloak." + o.domain + "/realms/ceffio",
		ClientID:     "stalwart-webui",
		DomaineAdmin: "ceffio.local",
		CompteAdmin:  "adminceffio",
	}); err != nil {
		return err
	}

	// 12ter. Call recording (Phase 14). AFTER the mail layer, and after Talk
	// itself through the parallel phases above: the recorder authenticates
	// against the signaling server and declares itself in Nextcloud, so both
	// must already exist.
	//
	// It is the heaviest component relative to the work it does — it drives a
	// browser to capture the room — so it is deployed last, once everything it
	// could starve is already running.
	if err := recording.Deploy(ctx, o.domain); err != nil {
		return err
	}

	// Secrets vault: OpenBao when configured, Kubernetes otherwise.
	// We only STATE which one is used — it is operational information, and it
	// is also proof that the vault remains optional: no deployment should
	// fail because it is absent.
	coffre := secrets.DepuisEnvironnement()
	fmt.Println("\nSecrets vault: " + coffre.Description())
	if err := files.ConfigureOIDC(ctx, o.domain); err != nil {
		return err
	}

	fmt.Println("\n✓ OIDC SSO configured (single Keycloak login on Nextcloud).")

	// 13. Ingress / real TLS (Phase 9).
	if err := ingress.Deploy(ctx, o.domain); err != nil {
		return err
	}

	// 14. Adoption of the public URLs into the apps (homeserver, SSO redirects, https).
	if err := ingress.AdoptURLs(ctx, o.domain); err != nil {
		return err
	}

	// 15. Administration console (dashboard + SSO users).
	if err := console.Deploy(ctx, o.domain); err != nil {
		return err
	}

	// Videoconferencing was already deployed in the parallel batch above
	// (Phase 10, with files ‖ chat). Do NOT replay it here: the duplicate call
	// only reconfirmed what was done, paying a second time the
	// `kubectl rollout status` wait (240 s worst case) for an identical
	// result. A deployment twice as long with no benefit.
	return nil
}

func resolveRuntime(o *installOptions, osName string) (cluster.Runtime, error) {
	if o.existingCluster {
		return "", fmt.Errorf("--existing-cluster: not implemented yet (BYO Kubernetes)")
	}
	switch o.runtime {
	case "k3s":
		if osName == "darwin" {
			return cluster.RuntimeDev, nil // macOS → k3d (dev loop)
		}
		return cluster.RuntimeK3s, nil // Linux → real K3s
	case "rke2":
		return "", fmt.Errorf("runtime rke2: not implemented yet (Phase 17)")
	default:
		return "", fmt.Errorf("unknown runtime %q", o.runtime)
	}
}
