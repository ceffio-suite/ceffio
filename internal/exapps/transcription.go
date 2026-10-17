// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package exapps

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// The app id, as Nextcloud knows it.
const appTranscription = "live_transcription"

// The namespace holding Nextcloud, and the label its Deployment carries.
const (
	nsNextcloud   = "ceffio-files"
	etiqNextcloud = "nextcloud"
)

// TranscriptionDeploye installs the live transcription ExApp in Talk.
//
// IT IS NOT PART OF `install` BY DEFAULT, and that is a deliberate choice:
//
//   - weight: ~2.5 GB for the image and ~6 GB for the speech models, plus
//     around 16 GB of RAM for one or two concurrent calls. That is a lot to
//     impose on an installation that does not want transcription.
//   - reversibility: the two environment variables below CANNOT be changed
//     after the fact. Nextcloud's documentation is explicit: "Changing these
//     environment variables after installation is possible through a
//     re-installation of the app after uninstalling it first." So an installer
//     that sets them without being asked would create an app that cannot be
//     corrected without removing it.
//
// Hence: opt-in at install time (--live-transcription), and fully managed from
// the administration console afterwards.
func TranscriptionDeploye(ctx context.Context, domain string) error {
	fmt.Println("\nDeploying live transcription (ExApp)...")

	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	pod, err := cli.PodDuDeploiement(ctx, nsNextcloud, "nextcloud", etiqNextcloud)
	if err != nil {
		return err
	}

	if err := verifierHarp(ctx, cli, pod); err != nil {
		return err
	}

	// The recorder of before taught this lesson: the two values below must be
	// the ones the rest of the platform actually serves. LT_HPB_URL points at
	// the signaling WITHOUT the /standalone-signaling prefix — this signaling
	// serves /spreed on the root, and a prefixed path answers 404.
	urlSignaling := fmt.Sprintf("wss://spreed.%s/spreed", domain)

	// THE SIGNALING SECRET IS READ FROM NEXTCLOUD, NOT FROM THE VAULT.
	//
	// Why not the vault: secrets.DepuisEnvironnement() reads BAO_ADDR/BAO_TOKEN,
	// which the deployment process has and the CONSOLE DOES NOT. Its image has
	// no shell, and the injector only gives it its own secrets already resolved
	// (CEFFIO_KEY, KC_ADMIN, NC_USER) — never vault credentials. Reading the
	// vault here worked from the command line and answered, in the interface:
	//
	//   no vault configured: cannot read talk/signaling
	//
	// So we ask the service that already holds the value: Talk. The setting is
	// exactly what the signaling uses, it is already stored in the database, and
	// reading it there needs no vault access at all.
	secretInterne, err := secretSignaling(ctx, cli, pod)
	if err != nil {
		return err
	}

	fmt.Printf("∙ registering %s (signaling: %s)\n", appTranscription, urlSignaling)

	// REGISTER WITHOUT --wait-finish, and this is not an oversight.
	//
	// --wait-finish waits for the ExApp to report itself READY — and an ExApp
	// reports ready only once it is ENABLED. This one starts reporting
	// "App is disabled on startup", which is its normal post-install state.
	// AppAPI therefore polls /exapps/live_transcription/heartbeat, gets
	//   "ExApp with appId live_transcription is disabled"
	// and waits forever. The command never returns, and the installation is
	// never confirmed: that is exactly what happened, twice.
	//
	// The order has to be register -> enable -> verify. We do not need
	// --wait-finish anyway: the enable step below IS the confirmation, and it
	// fails loudly if the ExApp did not come up.
	sortie, err := occ(ctx, cli, pod,
		"app_api:app:register", appTranscription,
		"--env", "LT_HPB_URL="+urlSignaling,
		"--env", "LT_INTERNAL_SECRET="+secretInterne)
	if err != nil {
		return fmt.Errorf("registering %s: %w", appTranscription, err)
	}
	fmt.Println("  ✓ " + derniereLigneUtile(sortie))

	// ENABLE. register only INSTALLS: the ExApp starts and reports
	// "App is disabled on startup". Without this step the component is there,
	// running, and Talk still has no transcription — which reads as a failed
	// installation when everything actually worked.
	//
	// "Install completely" means installed AND usable, so we do not stop at
	// the deployment.
	fmt.Println("∙ enabling the app...")
	if _, err := occ(ctx, cli, pod, "app_api:app:enable", appTranscription); err != nil {
		return fmt.Errorf("enabling %s (it is installed but inactive): %w", appTranscription, err)
	}

	// We do not trust the exit code: we read the state back, because the only
	// thing that matters is what AppAPI reports.
	verif, err := occ(ctx, cli, pod, "app_api:app:list")
	if err == nil && strings.Contains(verif, "[disabled]") {
		return fmt.Errorf("%s is still reported as disabled after enabling", appTranscription)
	}

	fmt.Println("✓ Live transcription deployed and enabled")
	fmt.Println("  The speech models are downloaded on first use (~6 GB).")
	return nil
}

// secretSignaling reads the internal secret of the signaling FROM NEXTCLOUD.
//
// WHERE THE VALUE LIVES: Talk stores it in its own settings, under
// `signaling_servers`, as
//
//	{"servers":[{"server":"..."}],"secret":"..."}
//
// It is the same value the signaling uses for [clients] internalsecret, so
// reading it there guarantees byte-for-byte agreement — which is the only thing
// that matters: a near-miss secret produces an app that starts, looks healthy,
// and is rejected on every connection attempt.
//
// WHY NOT THE VAULT: the administration console has no vault credentials (see
// the note in TranscriptionDeploye). Nextcloud is the source of truth for this
// value anyway, and asking it needs no elevated right at all.
func secretSignaling(ctx context.Context, cli *k8sapi.Client, pod string) (string, error) {
	sortie, err := occ(ctx, cli, pod, "config:app:get", "spreed", "signaling_servers")
	if err != nil {
		return "", fmt.Errorf("reading the signaling settings from Talk: %w", err)
	}

	brut := strings.TrimSpace(sortie)
	// occ may prefix its answer with a progress line; keep the last line, which
	// is the JSON document.
	if i := strings.LastIndex(brut, "\n"); i >= 0 {
		brut = strings.TrimSpace(brut[i+1:])
	}
	if brut == "" {
		return "", fmt.Errorf("Talk has no signaling server configured: deploy the Talk layer first")
	}

	var reglages struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(brut), &reglages); err != nil {
		return "", fmt.Errorf("reading the Talk signaling settings (unexpected format): %w", err)
	}
	if reglages.Secret == "" {
		return "", fmt.Errorf("Talk's signaling settings carry no secret: live transcription cannot authenticate to the signaling")
	}
	return reglages.Secret, nil
}

// TranscriptionSupprime removes the ExApp and everything it leaves behind.
//
// "UNINSTALL COMPLETELY" MEANS MORE THAN ONE COMMAND, and this is the part
// that is easy to get wrong:
//
//  1. unregister from AppAPI — this is what tells HaRP to delete the ExApp
//     Deployment, its Service and its PersistentVolumeClaim in
//     ceffio-exapps. Skipping it leaves a running workload nobody manages.
//  2. disable the app itself in Nextcloud, otherwise it stays listed and Talk
//     keeps advertising a transcription capability that has no backend.
//  3. the downloaded language models live in the ExApp's volume. Removing the
//     PVC (step 1) frees them; there is nothing else to clean by hand.
//
// The order matters: unregister first, while the app is still known, so HaRP
// can find and delete its resources. Removing the app first would orphan them.
func TranscriptionSupprime(ctx context.Context) error {
	fmt.Println("\nRemoving live transcription (ExApp)...")

	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	pod, err := cli.PodDuDeploiement(ctx, nsNextcloud, "nextcloud", etiqNextcloud)
	if err != nil {
		return err
	}

	if _, err := occ(ctx, cli, pod, "app_api:app:disable", appTranscription); err != nil {
		// Not fatal: it may already be disabled. Reported, not swallowed.
		fmt.Printf("  note: disable returned: %v\n", err)
	}

	if _, err := occ(ctx, cli, pod, "app_api:app:unregister", appTranscription); err != nil {
		if estAbsent(err) {
			fmt.Println("  live transcription is not installed — nothing to remove")
			return nil
		}
		return fmt.Errorf("unregistering %s: %w", appTranscription, err)
	}

	// Confirm HaRP actually tore the workload down, rather than trusting the
	// unregister call: a leftover Deployment would keep consuming RAM.
	if err := attendreDisparition(ctx, cli, pod); err != nil {
		return err
	}

	fmt.Println("✓ Live transcription removed (workload, service and volume freed)")
	return nil
}

// verifierHarp refuses to go further when no deploy daemon is registered.
//
// Without one the registration fails with a message about a daemon that is not
// configured, which reads like an app problem rather than a missing
// prerequisite. Asking AppAPI directly is also the honest check: the daemon
// could be running while not registered, and registering an ExApp needs the
// registration, not the pod.
func verifierHarp(ctx context.Context, cli *k8sapi.Client, pod string) error {
	sortie, err := occ(ctx, cli, pod, "app_api:daemon:list")
	if err != nil {
		return fmt.Errorf("cannot read the AppAPI daemon list: %w", err)
	}
	if !strings.Contains(strings.ToLower(sortie), nomHarp) {
		return fmt.Errorf("no ExApp deploy daemon is registered in AppAPI (expected %q): run 'ceffio install' first", nomHarp)
	}
	return nil
}

// attendreDisparition waits for the ExApp to be gone from AppAPI.
//
// We poll AppAPI rather than the Deployment: AppAPI is what decides, and HaRP
// removes the workload as a consequence. Watching the wrong one would report
// success while the workload is still there.
func attendreDisparition(ctx context.Context, cli *k8sapi.Client, pod string) error {
	fmt.Println("∙ waiting for the ExApp to be removed...")
	fin := time.Now().Add(120 * time.Second)
	for time.Now().Before(fin) {
		sortie, err := occ(ctx, cli, pod, "app_api:app:list")
		if err == nil && !strings.Contains(sortie, appTranscription) {
			fmt.Println("  ✓ workload removed")
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("the ExApp is still listed after 120s — check the ExApp namespace %s", nsExapps)
}

// occ runs an occ command inside the Nextcloud pod, THROUGH THE KUBERNETES API.
//
// WHY NOT kubectl: the administration console runs in a distroless container
// with no shell and no kubectl binary. Shelling out to kubectl works from the
// command line but fails inside the console with
//
//	exec: "kubectl": executable file not found in $PATH
//
// which is exactly what happened in production. The API does the same thing
// over HTTP and works in both contexts, so there is one code path, not two
// that drift apart.
func occ(ctx context.Context, cli *k8sapi.Client, pod string, args ...string) (string, error) {
	complet := append([]string{"php", "occ"}, args...)
	return cli.Executer(ctx, nsNextcloud, pod, "nextcloud", complet...)
}

func estAbsent(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "not installed") || strings.Contains(m, "not found") ||
		strings.Contains(m, "no app") || strings.Contains(m, "does not exist")
}

// derniereLigneUtile returns the last non-empty line of an occ output, which is
// where the outcome is reported. Printing the whole thing would drown the
// deployment log in progress lines.
func derniereLigneUtile(s string) string {
	lignes := strings.Split(s, "\n")
	for i := len(lignes) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lignes[i])
		if l != "" {
			return l
		}
	}
	return "registered"
}
