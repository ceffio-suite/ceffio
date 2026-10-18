// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/acme"
	"github.com/ceffio-suite/ceffio/internal/apps"
	"github.com/ceffio-suite/ceffio/internal/bootstrap"
	"github.com/ceffio-suite/ceffio/internal/cluster"
	"github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/data"
	"github.com/ceffio-suite/ceffio/internal/exapps"
	"github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/platform"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/sso"
	"github.com/ceffio-suite/ceffio/internal/stacks"
	"github.com/ceffio-suite/ceffio/internal/storage"
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
	// Live transcription (Talk). DEPRECATED FLAG, kept as an alias of
	// `--with live-transcription`: it maps onto the registry selection
	// instead of driving a hardcoded install block. Off unless asked:
	// heavy, and its settings cannot be changed once installed.
	liveTranscription bool

	// Optional modules, selected from the registry (see
	// selectedOptionalModules): `--with` adds, `--without` removes the
	// Default ones. The flags' help text is GENERATED from module.All(),
	// so a new module in the registry appears here without touching this
	// file.
	with    []string
	without []string

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
	// Live transcription in Talk. DEPRECATED: superseded by
	// `--with live-transcription`, which goes through the module registry
	// like every other optional feature. The flag still works (it feeds the
	// registry selection) and prints a deprecation notice; it will be
	// removed in two minor versions. Keeping it avoids breaking scripts
	// written against the previous release overnight.
	f.BoolVar(&o.liveTranscription, "live-transcription", false,
		"DEPRECATED: use --with live-transcription (removed in two minor versions)")
	// Optional modules. The help text is built by walking the registry: it
	// lists every Optional module with its resources and its dependencies,
	// so `ceffio install --help` never drifts from what the binary can
	// actually install.
	f.StringSliceVar(&o.with, "with", nil,
		"Optional modules to install, comma-separated (e.g. live-transcription). Known modules:"+optionalModulesHelp("", false))
	f.StringSliceVar(&o.without, "without", nil,
		"Default optional modules to SKIP, comma-separated (e.g. recording). Default modules:"+optionalModulesHelp("", true))
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

	// --live-transcription IS NOW AN ALIAS of --with live-transcription.
	// The effect goes through the registry selection below; only the
	// notice is specific to the old flag.
	if o.liveTranscription {
		fmt.Fprintln(os.Stderr, "warning: --live-transcription is deprecated: "+
			"use --with live-transcription instead; it will be removed in two minor versions")
	}

	// Resolve the optional modules EARLY. An invalid --with/--without ID
	// must fail here, before a cluster is provisioned — not forty minutes
	// into the deployment (the same lesson as the DNS check below).
	modulesOptionnels, err := selectedOptionalModules(o)
	if err != nil {
		return err
	}

	fmt.Println("Ceffio Installer")
	fmt.Println()
	fmt.Printf("Domain:     %s\n", o.domain)
	fmt.Printf("Profile:    %s\n", o.profile)
	fmt.Printf("Runtime:    %s\n", o.runtime)
	fmt.Printf("Mail:       %s\n", yesNo(o.mail))
	fmt.Printf("Office:     %s\n", yesNo(o.office))
	fmt.Printf("Monitoring: %s\n", yesNo(o.monitoring))
	if len(modulesOptionnels) == 0 {
		fmt.Println("Modules:    none")
	} else {
		ids := make([]string, 0, len(modulesOptionnels))
		for _, m := range modulesOptionnels {
			ids = append(ids, m.Info().ID)
		}
		fmt.Printf("Modules:    %s\n", strings.Join(ids, ", "))
	}
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

	// 1bis. PREREQUISITES, CHECKED BEFORE ANYTHING IS INSTALLED.
	//
	// Two families, and they fail in opposite ways. The system packages can be
	// fixed here; the DNS records cannot — they belong to a registrar, and no
	// privilege on this machine will create them. Checking both together, and
	// BEFORE touching the cluster, is the difference between a five-minute fix
	// and an afternoon: on the first deployment to ceffio.org the DNS was
	// missing, nothing said so, and the failure only surfaced forty minutes
	// later as an OIDC discovery error that pointed at Keycloak.
	//
	// The DNS check does NOT stop the run. A record can be wrong in a way that
	// does not prevent the cluster from being built, and an operator fixing
	// DNS while watching a stopped installer has no reason to be stopped. The
	// warning is printed, the deployment continues, and the failure — if it
	// comes — arrives with the list already on screen.
	if err := verifierPrerequis(ctx, o, hw); err != nil {
		return err
	}

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

	// 4bis. STORAGE (Phase 2, before the platform).
	//
	// It comes FIRST because every other layer writes volumes: PostgreSQL, the
	// Nextcloud data, Stalwart, Keycloak. Installing the storage driver after
	// them means those PVCs land on whatever default existed at the time —
	// local-path, which cannot be expanded nor backed up — and switching later
	// requires recreating PVCS, so losing the data.
	//
	// It also prepares the HOST: the iSCSI client and its daemon. Their absence
	// is invisible from inside the cluster (pods Running, StorageClass
	// present, volumes never leaving `creating`), and the first deployment to
	// ceffio.org lost hours to exactly that.
	fmt.Println("\n∙ storage layer (host prerequisites + Longhorn)")
	if err := storage.Install(ctx); err != nil {
		return err
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
		// THIS IS NOT A NEUTRAL FALLBACK, and saying so was misleading.
		//
		// The message announced « secrets will stay in Kubernetes (expected
		// behavior) », which suggests the rest copes with an absent vault. It
		// does NOT: the identity layer refuses to start without it, and the
		// operator discovered further down
		//
		//	vault unreadable for keycloak/db: no vault configured
		//
		// An error that blames a missing configuration while the subject is a
		// vault that did not start.
		//
		// WE CONTINUE ANYWAY, because the platform deployment (namespaces,
		// ingress, StorageClass) does not need the vault and it is better to
		// let the rest attempt it: a partial but diagnosable installation
		// beats an immediate stop. What changes is that the message now says
		// what is going to happen.
		fmt.Println("  ⚠ vault unavailable — the identity layer will fail without it")
		fmt.Println("    check `kubectl -n ceffio-vault get pods` and the openbao logs")
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

	// 10bis. THE LOCAL NEXTCLOUD ACCOUNT, and it belongs HERE rather than in the
	// identity layer.
	//
	// THE ORDER IS NOT A DETAIL: the identity layer (Phase 4) creates the
	// realm and the Keycloak account, but Nextcloud only exists from the line
	// above onwards. Created too early, the Nextcloud account failed and the
	// platform started with only one of the two entry doors.
	//
	// THIS ACCOUNT IS THE FALLBACK PATH: it allows logging in directly if
	// Keycloak is unavailable. A platform whose only access is a dependency is
	// a platform that an outage of that dependency locks out.
	//
	// Idempotent: an existing account is left as-is, password included.
	if err := identity.EnsureCompteNextcloud(ctx); err != nil {
		// Non-blocking, and reported: Keycloak is what the interface uses,
		// and interrupting a successful installation for the fallback path
		// would be a bad trade. The console can create it later.
		fmt.Printf("  ⚠ compte Nextcloud non créé : %v\n", err)
		fmt.Println("    (créable depuis la page Administration de la console)")
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

	// --- Ingress / real TLS (Phase 9) — MOVED HERE, BEFORE THE OIDC BLOCKS ---
	//
	// WHY IT MOVED: this block used to run at the very end, after the mail
	// layer. But Stalwart's single sign-on verifies its own configuration by
	// asking for the OIDC discovery document at
	// https://keycloak.<domain>/realms/ceffio — an address that only exists
	// once the Ingress is applied. At that point the name resolved, Traefik
	// answered, and the answer was Stalwart's own discovery document instead
	// of Keycloak's:
	//
	//   ceffio: discovery does not return the expected provider
	//   (https://keycloak.ceffio.org/realms/ceffio):
	//   {"issuer":"","authorization_endpoint":"/login","token_endpoint":"/auth/token",...}
	//
	// The deployment stopped there, on the last mile, with everything else
	// installed and healthy. Keycloak itself was fine all along — reached on
	// its cluster address it answers correctly.
	//
	// Nothing here depends on an application: these are Ingress objects and a
	// CA. Applying them first is always valid, and it makes the OIDC
	// verification run against a real address.
	//
	// The ACME settings are resolved ONCE, before the ingress layer, and
	// reused by the optional-module phase further down. Resolving them twice
	// would let the two halves of one installation disagree — and the ingress
	// layer is where they decide which certificate gets issued.
	reglagesACME, err := acme.DepuisEnvironnement()
	if err != nil {
		return err
	}
	// The settings are also published in the vault, which is where the CONSOLE
	// reads them from: its container declares no environment variable at all,
	// so a value written only here would leave the TLS page reporting the
	// default while the cluster runs another challenge.
	//
	// Non-blocking on purpose: the ingress layer below is what makes HTTPS
	// work, and a vault that refuses this write must not cost the operator the
	// whole installation over a display value.
	if err := vault.PoserReglagesACME(ctx, reglagesACME); err != nil {
		fmt.Printf("  ⚠ ACME settings not published to the vault (%v) — the console will "+
			"show the default challenge; the certificates themselves are unaffected\n", err)
	}
	if err := ingress.Deploy(ctx, o.domain, reglagesACME); err != nil {
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

	// 12ter. THE RECORDING SERVER IS NO LONGER DEPLOYED HERE.
	//
	// It used to be an unconditional recording.Deploy call at this exact
	// spot. Recording is now a registry module (Optional, Default=true),
	// installed with the other selected optional modules just below — the
	// same behavior for a default install, plus `--without recording` for
	// those who do not want it. Deploying it twice would only re-pay the
	// rollout waits of an idempotent call.

	// 12quater. THE EXAPP DEPLOY DAEMON IS NOT INSTALLED HERE, ON PURPOSE.
	//
	// HaRP lets Nextcloud install components ON ITS OWN. Deploying it at
	// installation would make it present on every machine, whether or not the
	// operator ever wants that — and it is not free: it adds a namespace, a
	// workload, and a permanent right for Nextcloud to start containers.
	//
	// It is now installed from the administration console, where it belongs:
	// the Applications page has a "Deploy the deployer" button, and the same
	// page installs live transcription right after. An operator who wants
	// neither never deploys it. From the CLI, `--with exapps-daemon` (and
	// anything that requires it, e.g. `--with live-transcription`) installs
	// it through the registry, in the optional-modules phase below.
	//
	// THE NAMESPACE IS STILL CREATED HERE, because it is cheap, because the
	// console's write permissions live in it, and because waiting for it to
	// exist before the first click is a better first experience than creating
	// it on demand.
	if err := exapps.Preparer(ctx); err != nil {
		return err
	}

	// 12quinquies. OPTIONAL MODULES, DRIVEN BY THE REGISTRY.
	//
	// This replaces the former hardcoded `if o.liveTranscription {
	// exapps.TranscriptionDeploye(...) }` block and the unconditional
	// recording.Deploy call above: the selection comes from --with/--without
	// (and the deprecated --live-transcription alias), the ORDER comes from
	// module.All() (topological), and the dependencies of a selected module
	// are pulled in automatically. Placement is deliberate — after the core
	// sequence (every optional module builds on talk/files/ingress) and
	// before the console (the console must observe the final state, and its
	// summary runs last).
	if err := installerModulesOptionnels(ctx, o, modulesOptionnels); err != nil {
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

	// 14. Adoption of the public URLs into the apps (homeserver, SSO redirects, https).
	//
	// The Ingress itself was applied earlier — before the OIDC blocks, because
	// Stalwart's SSO verification needs https://keycloak.<domain> to exist.
	// What runs here needs the apps to be up: it writes the public URL into
	// Nextcloud (https protocol, proxy headers), the SSO redirect URIs, and
	// the ONLYOFFICE connector.
	if err := ingress.AdoptURLs(ctx, o.domain); err != nil {
		return err
	}

	// 15. Administration console (dashboard + SSO users).
	if err := console.Deploy(ctx, o.domain); err != nil {
		return err
	}

	// 16. THE CLOSING SUMMARY.
	//
	// It runs LAST, because most of what it shows only exists now: the
	// administration key was generated a moment ago, the certificate dates
	// come from when Let's Encrypt answered, and the pod state is what
	// actually came up. Printed anywhere else it would be a guess.
	//
	// It cannot fail the installation: the deployment succeeded, and turning a
	// success into a failure over a summary line would be the worst possible
	// trade. See the note in console.Synthese.
	console.Synthese(ctx, o.domain)

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

// nomsAttendus lists every hostname this deployment will serve, derived from
// the domain rather than hardcoded.
//
// THE LIST IS THE PRODUCT'S SURFACE. Each entry is a certificate cert-manager
// will request and an Ingress Traefik will publish; a missing record means the
// HTTP-01 challenge never completes for that host, and the symptom appears much
// later, during the TLS phase, as a certificate that stays unissued.
func nomsAttendus(domain string) []string {
	// cloud, keycloak, office, spreed (signaling), bao (vault) — the five
	// Ingresses of ingressManifest, plus admin (console) and mail (Stalwart),
	// which are written by their own packages.
	return []string{
		"cloud." + domain,
		"keycloak." + domain,
		"office." + domain,
		"spreed." + domain,
		"bao." + domain,
		"admin." + domain,
		"mail." + domain,
	}
}

// verifierPrerequis checks the DNS and the machine, and REPORTS WITHOUT
// STOPPING.
//
// WHY IT DOES NOT ABORT ON A DNS PROBLEM: the records live at a registrar, the
// operator may be fixing them right now, and stopping the installer would force
// a full re-run — k3s provisioning included — for something that does not
// prevent the cluster from being built. The check exists to put the information
// on screen BEFORE the confusing error, not to gate the deployment.
//
// The one thing that does abort is the hardware minimum: below it the platform
// does not run at all, and going further would produce a half-installed
// machine.
func verifierPrerequis(ctx context.Context, o *installOptions, hw bootstrap.Hardware) error {
	fmt.Println("\nPrerequisites:")

	// --- 1. Hardware -------------------------------------------------------
	if manque := bootstrap.MinHardwareOK(hw); len(manque) > 0 {
		return fmt.Errorf("hardware below the minimum (%s)", strings.Join(manque, ", "))
	}
	fmt.Printf("  ✓ hardware (%d vCPU, %d MB RAM)\n", hw.CPUs, hw.MemoryTotalMB)

	// --- 2. DNS ------------------------------------------------------------
	// A private domain (*.local) has no public record by design: the demo
	// reaches its Ingresses through hostAliases, and asking for a record would
	// make it impossible to run. We say so rather than reporting seven
	// failures that are not failures.
	public := !strings.HasSuffix(o.domain, ".local")

	noms := nomsAttendus(o.domain)
	resultats := bootstrap.Verifier(ctx, noms)

	// The address to compare against: what the INTERNET sees, not what an
	// interface reports. On a host behind NAT they differ, and the certificate
	// is issued for the name — so the record must carry the public address.
	attendue := bootstrap.AdressePublique(ctx)

	problemes := bootstrap.Rapport(resultats, attendue, public)
	switch {
	case !public:
		fmt.Println("  ∙ DNS: private domain, no public record expected")
	case len(problemes) == 0:
		fmt.Printf("  ✓ DNS (%d names → %s)\n", len(noms), attendue)
	default:
		// THE BLOCK IS DELIBERATELY LOUD AND COMPLETE. Reporting one name at a
		// time would mean seven round trips to the registrar.
		fmt.Printf("  ! DNS: %d problème(s) — à corriger chez le registrar avant le TLS\n", len(problemes))
		for _, p := range problemes {
			fmt.Printf("      · %s\n", p)
		}
		if attendue == "" {
			fmt.Println("      (adresse publique illisible — comparer à la main)")
		} else {
			fmt.Printf("      attendu : %s\n", attendue)
		}
		fmt.Println("      le déploiement continue : les certificats de ces hôtes échoueront")
	}

	// --- 3. System packages ------------------------------------------------
	// NOT INSTALLED HERE. This function only reports; the storage layer
	// installs what is missing, a few seconds later, with the privileges it
	// already uses. Two places installing packages would be two places to fix
	// when one of them is wrong.
	if manquants := storage.PaquetsAbsents(ctx); len(manquants) > 0 {
		fmt.Printf("  ∙ packages manquants, installés à l'étape suivante: %s\n",
			strings.Join(manquants, " "))
	} else {
		fmt.Println("  ✓ system packages")
	}
	return nil
}

// optionalModulesHelp builds the catalog part of the --with/--without help
// text FROM THE REGISTRY: one line per Optional module, with its resources
// and its dependencies.
//
// WHY GENERATED: a help text maintained by hand drifts from the registry the
// day a module is added — and the drift is invisible until an operator
// wonders why `--with new-module` "is not documented". Walking module.All()
// makes the documentation a projection of what the binary can install.
//
// seulementDefaut narrows the list to the Default modules: --without only
// has an effect on those (a non-default module is skipped by not asking for
// it), so showing the others under a "Default modules" header would be a
// lie.
func optionalModulesHelp(intro string, seulementDefaut bool) string {
	var b strings.Builder
	b.WriteString(intro)
	for _, m := range module.All() {
		i := m.Info()
		if i.Kind != module.Optional {
			continue
		}
		if seulementDefaut && !i.Default {
			continue
		}
		b.WriteString("\n  - " + i.ID)
		if i.Default {
			b.WriteString(" (installed by default)")
		}
		if i.Resources != "" {
			b.WriteString(": " + i.Resources)
		}
		if len(i.Requires) > 0 {
			b.WriteString(" [requires " + strings.Join(i.Requires, ", ") + "]")
		}
	}
	return b.String()
}

// selectedOptionalModules resolves --with/--without (plus the deprecated
// --live-transcription alias) into the ordered list of Optional modules the
// installer must deploy, with their dependencies pulled in automatically.
//
// A module is selected when: (a) it is Default and not named by --without,
// or (b) it is named by --with. The result follows module.All() order —
// topological — so dependencies install before the modules that need them.
//
// Unknown IDs are an ERROR, not a warning: a typo in `--with
// live-transcripion` must not silently produce an installation without the
// feature the operator asked for.
func selectedOptionalModules(o *installOptions) ([]module.Module, error) {
	avec := map[string]bool{}
	for _, id := range o.with {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		avec[id] = true
	}
	// The deprecated flag is a plain alias: its whole effect is to select
	// the module through the registry.
	if o.liveTranscription {
		avec["live-transcription"] = true
	}
	sans := map[string]bool{}
	for _, id := range o.without {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		sans[id] = true
	}

	// Validate every named ID against the registry, and check the flags do
	// not contradict each other (--with X --without X asks for X and its
	// absence at once; refusing is cheaper than picking a side silently).
	for id := range avec {
		m, ok := module.Get(id)
		if !ok {
			return nil, fmt.Errorf("--with: unknown module %q (optional modules: %s)",
				id, strings.Join(optionalIDs(), ", "))
		}
		if m.Info().Kind != module.Optional {
			return nil, fmt.Errorf("--with %s: %q is a core module, always installed by the sequence", id, id)
		}
	}
	for id := range sans {
		m, ok := module.Get(id)
		if !ok {
			return nil, fmt.Errorf("--without: unknown module %q (optional modules: %s)",
				id, strings.Join(optionalIDs(), ", "))
		}
		if m.Info().Kind != module.Optional {
			return nil, fmt.Errorf("--without %s: %q is a core module and cannot be excluded", id, id)
		}
		if avec[id] {
			return nil, fmt.Errorf("module %q is both in --with and --without", id)
		}
	}

	retenu := map[string]bool{}
	for id := range avec {
		retenu[id] = true
	}
	for _, m := range module.All() {
		i := m.Info()
		if i.Kind == module.Optional && i.Default && !sans[i.ID] {
			retenu[i.ID] = true
		}
	}

	// Pull the dependencies in, and SAY SO: an operator who asked only for
	// live-transcription must see exapps-daemon appear rather than wonder
	// where the extra namespace came from. The expansion is transitive
	// (a dependency may itself require one), hence the recursion.
	var expand func(m module.Module)
	expand = func(m module.Module) {
		for _, dep := range m.Info().Requires {
			if retenu[dep] {
				continue
			}
			retenu[dep] = true
			fmt.Printf("∙ %s requires %s: adding it\n", m.Info().ID, dep)
			if dm, ok := module.Get(dep); ok {
				expand(dm)
			}
		}
	}
	for _, m := range module.All() {
		if retenu[m.Info().ID] {
			expand(m)
		}
	}

	// Final list in REGISTRY order: module.All() is topological, so
	// filtering it keeps a valid install sequence.
	var out []module.Module
	for _, m := range module.All() {
		if retenu[m.Info().ID] {
			out = append(out, m)
		}
	}
	return out, nil
}

// installerModulesOptionnels deploys the selected Optional modules, in
// registry order, through the module.Module contract.
//
// WHY THE REGISTRY AND NOT DIRECT CALLS: the modules already wrap the
// existing installs (recording.Deploy, exapps.Deploy,
// exapps.TranscriptionDeploye) behind idempotent Install methods — this is
// exactly what B1-B3 built and tested. Calling the packages directly again
// would fork the behavior between the CLI and the console, the two
// frontends the registry exists to keep identical.
func installerModulesOptionnels(ctx context.Context, o *installOptions, modules []module.Module) error {
	if len(modules) == 0 {
		fmt.Println("\n∙ optional modules: none selected")
		return nil
	}

	// The Kubernetes client is built ONCE for the whole phase: the modules
	// use Env.Kube for their state reads, and re-resolving the kubeconfig
	// per module would multiply the failure points for no benefit.
	kube, err := kubeClient()
	if err != nil {
		return fmt.Errorf("optional modules need a Kubernetes client: %w", err)
	}

	// The ACME settings are resolved HERE and handed to the modules: a module
	// never reads the environment itself. An invalid configuration stops the
	// phase instead of installing modules that would act on settings nobody
	// validated — the ingress module is precisely the one that writes a
	// ClusterIssuer from them.
	reglages, err := acme.DepuisEnvironnement()
	if err != nil {
		return err
	}

	env := module.Env{Domain: o.domain, Kube: kube, Out: os.Stdout, Acme: reglages}

	fmt.Printf("\n∙ optional modules from the registry (%d)\n", len(modules))
	for _, m := range modules {
		i := m.Info()
		fmt.Printf("→ installing %s (%s)\n", i.ID, i.Title)
		if err := m.Install(ctx, env); err != nil {
			return fmt.Errorf("installing module %q: %w", i.ID, err)
		}
		fmt.Printf("✓ %s installed\n", i.ID)
	}
	return nil
}
