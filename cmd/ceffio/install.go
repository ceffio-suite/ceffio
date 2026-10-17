// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

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
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/platform"
	"github.com/ceffio-suite/ceffio/internal/recording"
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
	// Live transcription (Talk). Off unless asked: heavy, and its settings
	// cannot be changed once installed.
	liveTranscription bool

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
	// Live transcription in Talk. OFF BY DEFAULT, and that is deliberate:
	// ~2.5 GB image + ~6 GB of models + ~16 GB of RAM, and its two settings
	// cannot be changed after installation (the app must be removed and
	// reinstalled). An installation that does not want it should not carry it,
	// and the administration console can install and remove it later.
	f.BoolVar(&o.liveTranscription, "live-transcription", false, "Enable live transcription in Talk (heavy: ~9 GB disk, ~16 GB RAM)")
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
	fmt.Printf("Transcription: %s\n", yesNo(o.liveTranscription))
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
		// CE N'EST PAS UN REPLI NEUTRE, et le dire ainsi était trompeur.
		//
		// Le message annonçait « secrets will stay in Kubernetes (expected
		// behavior) », ce qui laisse croire que la suite s'accommode d'un vault
		// absent. Elle ne s'en accommode PAS : la couche identity refuse de
		// démarrer sans lui, et l'opérateur découvrait plus loin
		//
		//	vault unreadable for keycloak/db: no vault configured
		//
		// Une erreur qui accuse une configuration absente alors que le sujet
		// est un vault qui n'a pas démarré.
		//
		// ON CONTINUE QUAND MÊME, parce que le déploiement de la plateforme
		// (namespaces, ingress, StorageClass) n'a pas besoin du coffre et qu'il
		// vaut mieux laisser la suite le tenter : une installation partielle
		// mais diagnostiquable vaut mieux qu'un arrêt immédiat. Ce qui change,
		// c'est que le message dit maintenant ce qui va se passer.
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
	// L'ORDRE N'EST PAS UN DÉTAIL : la couche identity (Phase 4) crée le realm
	// et le compte Keycloak, mais Nextcloud n'existe qu'à partir de la ligne
	// ci-dessus. Créé trop tôt, le compte Nextcloud échouait et la plateforme
	// démarrait avec une seule des deux portes d'entrée.
	//
	// CE COMPTE EST LE CHEMIN DE SECOURS : il permet de se connecter en direct
	// si Keycloak est indisponible. Une plateforme dont l'unique accès est une
	// dépendance est une plateforme qu'une panne de cette dépendance enferme.
	//
	// Idempotent : un compte présent est laissé tel quel, mot de passe compris.
	if err := identity.EnsureCompteNextcloud(ctx); err != nil {
		// Non bloquant, et rapporté : Keycloak est ce que l'interface utilise,
		// et interrompre une installation réussie pour le chemin de secours
		// serait un mauvais échange. La console peut le créer plus tard.
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
	if err := ingress.Deploy(ctx, o.domain); err != nil {
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
	// neither never deploys it.
	//
	// THE NAMESPACE IS STILL CREATED HERE, because it is cheap, because the
	// console's write permissions live in it, and because waiting for it to
	// exist before the first click is a better first experience than creating
	// it on demand.
	if err := exapps.Preparer(ctx); err != nil {
		return err
	}

	// Live transcription is OPT-IN. It is installed only when asked, because
	// of its weight and because its configuration is not revisable in place.
	if o.liveTranscription {
		if err := exapps.TranscriptionDeploye(ctx, o.domain); err != nil {
			return err
		}
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
