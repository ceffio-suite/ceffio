// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package exapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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
//
// langues are the speech models placed on disk — the module's `languages`
// setting, already validated by LanguesDepuisListe. They are placed LAST, once
// the ExApp pod exists, because that pod is what holds the volume.
func TranscriptionDeploye(ctx context.Context, domain string, langues []string) error {
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

	// WHICH SPEECH MODELS GET DOWNLOADED.
	//
	// The ExApp announces 27 languages but downloads three: it asks for the
	// whole HuggingFace repository with no filter, and the repository's three
	// largest models happen to be the ones that fit its default budget —
	// en-us (2.9 GB), ar (700 MB) and br (311 MB), 3.6 GB in total. Every
	// other language is offered in the interface and then fails at the first
	// call with
	//
	//   Error in connection and start of the Vosk server.
	//   Cannot continue further.
	//
	// because vosk_server.py loads a directory that was never downloaded, and
	// the process dies on the missing model. Measured: a French call, French
	// selected, `vosk-model-small-fr-0.22` absent, Vosk core dump.
	//
	// So we download the models ourselves, into the ExApp's volume, before it
	// ever starts. The ExApp then finds the directory it expects and serves the
	// language instead of dying on it.
	//
	// The alternative — letting the ExApp fetch and patching its image to filter
	// — means forking an upstream image and rebuilding it on every release to
	// carry a one-line change. Placing the files is the smaller, more honest
	// intervention: it uses the same volume the ExApp reads, and it survives the
	// ExApp being reinstalled or upgraded.
	if len(langues) == 0 {
		return errors.New("no speech language configured: the app would advertise transcription and serve no model")
	}
	fmt.Printf("∙ speech models: %s%s\n", strings.Join(langues, ", "), resumeModeles(langues))

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
	//
	// REGISTRATION IS CONDITIONAL, AND THIS IS WHAT MAKES A RE-RUN USEFUL.
	// `app_api:app:register` refuses an appid it already knows, and AppAPI has
	// no update command. Called unconditionally, a second installation would
	// fail HERE — before the models, which are the reason to run it again. On
	// an existing installation the app is therefore kept as it is, and the run
	// proceeds to what is actually missing.
	etat, err := etatAppAPI(ctx, cli, pod)
	if err != nil {
		return err
	}
	if etat != "" {
		fmt.Printf("∙ %s already registered (%s) — models only\n", appTranscription, etat)
	} else {
		fmt.Printf("∙ registering %s (signaling: %s)\n", appTranscription, urlSignaling)
		sortie, err := occ(ctx, cli, pod,
			"app_api:app:register", appTranscription,
			"--env", "LT_HPB_URL="+urlSignaling,
			"--env", "LT_INTERNAL_SECRET="+secretInterne)
		if err != nil {
			return fmt.Errorf("registering %s: %w", appTranscription, err)
		}
		fmt.Println("  ✓ " + derniereLigneUtile(sortie))
		etat = "disabled" // register only installs: see ENABLE below
	}

	// ENABLE. register only INSTALLS: the ExApp starts and reports
	// "App is disabled on startup". Without this step the component is there,
	// running, and Talk still has no transcription — which reads as a failed
	// installation when everything actually worked.
	//
	// "Install completely" means installed AND usable, so we do not stop at
	// the deployment.
	//
	// Skipped when AppAPI already reports it enabled: a second enable is a
	// no-op at best, an error that hides the real state at worst.
	if etat == "disabled" {
		fmt.Println("∙ enabling the app...")
		if _, err := occ(ctx, cli, pod, "app_api:app:enable", appTranscription); err != nil {
			return fmt.Errorf("enabling %s (it is installed but inactive): %w", appTranscription, err)
		}
	}

	// We do not trust the exit code: we read the state back, because the only
	// thing that matters is what AppAPI reports.
	verif, err := occ(ctx, cli, pod, "app_api:app:list")
	if err == nil && strings.Contains(verif, "[disabled]") {
		return fmt.Errorf("%s is still reported as disabled after enabling", appTranscription)
	}

	fmt.Println("✓ Live transcription deployed and enabled")

	// The models go in AFTER the app runs, not before: the ExApp pod is what
	// holds the volume, and it does not exist until AppAPI has deployed it. The
	// ExApp downloads its own three models during `init`; this adds the ones its
	// list did not cover, which is why it happens last and why the download
	// skips whatever is already on disk.
	fmt.Println("∙ placing the speech models...")
	if err := telechargerModeles(ctx, cli, langues); err != nil {
		// Not fatal: recording and the rest of Talk work without the models, and
		// the module's settings place them on save — which is the supported way
		// to add a language, not a reinstall.
		fmt.Printf("  ⚠ %v\n", err)
		fmt.Println("  Transcription is installed; add the language from the module settings, which places its model.")
		return nil
	}

	fmt.Printf("  Speech models in place: %s%s instead of 6.3 GB for the whole repository.\n",
		strings.Join(langues, ", "), resumeModeles(langues))
	return nil
}

// LanguesParDefaut is the model set placed on an installation that never chose
// one.
//
// WHY FRENCH: 68 MB against 6.3 GB for the whole repository, and a language
// nobody speaks costs disk on a machine that may not have it. The value is
// the module's default; changing it there changes what a new installation
// places, and an installation that already stores a list keeps it.
var LanguesParDefaut = []string{"fr"}

// LanguesDepuisListe turns the stored setting — "fr,ar" — into the model codes
// to place, refusing anything the ExApp could not serve.
//
// WHY VALIDATE HERE AND NOT IN THE FORM: the setting is also written by the
// CLI and by the installer, which do not draw a form. A code that does not
// exist in modelesVosk would download 404 pages and leave vosk_server.py with
// a directory it cannot open — the exact failure this work removes. The error
// names the accepted codes, because that is the whole list an operator needs.
func LanguesDepuisListe(liste string) ([]string, error) {
	champs := strings.FieldsFunc(liste, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\t' || r == '\n'
	})
	if len(champs) == 0 {
		return nil, errors.New("no language given")
	}

	vus := make(map[string]bool, len(champs))
	langues := make([]string, 0, len(champs))
	inconnues := make([]string, 0)
	for _, c := range champs {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" || vus[c] {
			continue
		}
		if _, ok := modelesVosk[c]; !ok {
			inconnues = append(inconnues, c)
			continue
		}
		vus[c] = true
		langues = append(langues, c)
	}
	if len(inconnues) > 0 {
		return nil, fmt.Errorf("no speech model for %s (known: %s)",
			strings.Join(inconnues, ", "), strings.Join(ModelesConnus(), ", "))
	}
	return langues, nil
}

// ModelesConnus returns the language codes the ExApp can serve, sorted for a
// stable message.
func ModelesConnus() []string {
	codes := make([]string, 0, len(modelesVosk))
	for code := range modelesVosk {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}

// PlacerModeles downloads the models of the given languages into the ExApp's
// volume, then reads back what is actually on disk.
//
// It is exported for the module's settings: adding a language in the console
// has to download it at that moment, not at some hypothetical reinstall.
func PlacerModeles(ctx context.Context, langues []string) error {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	return telechargerModeles(ctx, cli, langues)
}

// ModelesAbsents returns the languages whose model is not on disk yet.
//
// Read from the pod, not from a local map: the volume is the only truth, and a
// download interrupted halfway leaves a directory that looks present. The
// acoustic model file is the witness — every other file is useless without it.
func ModelesAbsents(ctx context.Context, langues []string) ([]string, error) {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return nil, fmt.Errorf("Kubernetes client: %w", err)
	}
	return modelesAbsents(ctx, cli, langues)
}

// telechargerModeles places the speech models for the given languages into the
// ExApp's volume.
//
// It runs INSIDE the ExApp pod, which is the only place that has both the
// volume mounted and a shell to fetch with. The deployment process has neither:
// it talks to the cluster through the API, and the ExApp's image is the one
// holding the volume.
//
// IDEMPOTENT: a language whose directory already holds its model is left
// alone. Re-running `install` therefore does not re-download 68 MB, and adding
// a language later downloads only the difference — which is what makes the
// list safe to grow.
func telechargerModeles(ctx context.Context, cli *k8sapi.Client, langues []string) error {
	const depot = "https://huggingface.co/Nextcloud-AI/vosk-models/resolve/main"

	for _, l := range langues {
		dossier, ok := modelesVosk[l]
		if !ok {
			return fmt.Errorf("no model known for language %q: the ExApp would serve a directory that does not exist", l)
		}

		// The model is complete when its acoustic model is there: every other
		// file is useless without it, and its presence means an interrupted
		// download did not leave a half-copied directory behind.
		script := fmt.Sprintf(`
set -e
D="%s"
T="%s/$D"
if [ -f "$T/am/final.mdl" ]; then
  echo "  %s already present"
  exit 0
fi
mkdir -p "$T"
for f in README am/final.mdl conf/mfcc.conf conf/model.conf \
         graph/Gr.fst graph/HCLr.fst graph/disambig_tid.int \
         graph/phones/word_boundary.int ivector/final.dubm ivector/final.ie \
         ivector/final.mat ivector/global_cmvn.stats \
         ivector/online_cmvn.conf ivector/splice.conf; do
  mkdir -p "$T/$(dirname "$f")"
  curl -sfL --retry 3 --max-time 300 "%s/$D/$f" -o "$T/$f"
done
echo "  %s downloaded"
`, dossier, modeleRepertoire, l, depot, l)

		if _, err := exappsExec(ctx, cli, script); err != nil {
			return fmt.Errorf("downloading the %s model: %w", l, err)
		}
	}

	// READ BACK, DO NOT TRUST THE DOWNLOAD. A curl that exits 0 after writing a
	// truncated file leaves a directory that looks complete; the acoustic model
	// is the file vosk_server.py opens first, so its presence is the witness
	// that matters. This is also what the settings page reports.
	manquants, err := modelesAbsents(ctx, cli, langues)
	if err != nil {
		return fmt.Errorf("checking the speech models: %w", err)
	}
	if len(manquants) > 0 {
		return fmt.Errorf("model incomplete for %s: the ExApp would fail these languages on the first call",
			strings.Join(manquants, ", "))
	}
	return nil
}

// modelesAbsents returns the languages whose model the volume does not hold.
//
// ONE exec for the whole list: a call per language would be one round trip per
// language for a question a shell loop answers at once.
func modelesAbsents(ctx context.Context, cli *k8sapi.Client, langues []string) ([]string, error) {
	if len(langues) == 0 {
		return nil, nil
	}

	var pairs []string
	for _, l := range langues {
		dossier, ok := modelesVosk[l]
		if !ok {
			return nil, fmt.Errorf("no model known for language %q", l)
		}
		pairs = append(pairs, l+":"+dossier)
	}

	script := fmt.Sprintf(`for P in %s; do
  code="${P%%%%:*}"
  D="${P#*:}"
  if [ -f "%s/$D/am/final.mdl" ]; then echo "ok $code"; else echo "missing $code"; fi
done
`, strings.Join(pairs, " "), modeleRepertoire)

	sortie, err := exappsExec(ctx, cli, script)
	if err != nil {
		return nil, err
	}
	var absents []string
	for _, ligne := range strings.Split(sortie, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ligne), "missing ") {
			absents = append(absents, strings.TrimPrefix(strings.TrimSpace(ligne), "missing "))
		}
	}
	return absents, nil
}

// modeleRepertoire is the ExApp's persistent volume, where vosk_server.py looks
// for its models. It is read from the ExApp rather than assumed: that path is
// the contract between the two, and a wrong one downloads 68 MB nobody reads.
const modeleRepertoire = "/nc_app_live_transcription_data"

// tailleModeles returns the disk footprint of the given languages, in
// megabytes, and whether EVERY one of them is accounted for. Indicative —
// measured from the repository's file listing — and used only to show the
// order of magnitude, never to decide anything.
//
// WHY THE SECOND RESULT: the table covers the languages this platform
// realistically meets, not all 27. Summing the known ones and printing the
// total would announce 68 MB for a list whose other half is unknown, which is
// worse than saying nothing.
func tailleModeles(langs []string) (float64, bool) {
	// Sizes per language, from the HuggingFace file listing.
	tailles := map[string]float64{
		"fr": 68.5, "en": 2866, "de": 95.6, "es": 60.3, "it": 91.3,
		"nl": 68.7, "pt": 53.6, "ar": 698.2, "br": 310.9,
	}
	var total float64
	for _, l := range langs {
		t, ok := tailles[l]
		if !ok {
			return total, false
		}
		total += t
	}
	return total, true
}

// resumeModeles renders " (68 MB)", or nothing when a size is unknown.
func resumeModeles(langues []string) string {
	if mo, ok := tailleModeles(langues); ok {
		return fmt.Sprintf(" (%.0f MB)", mo)
	}
	return ""
}

// modelesVosk maps a language code to its directory in the HuggingFace
// repository, mirroring the ExApp's own models.py. The names are the contract
// between the two: vosk_server.py joins persistent_storage() with exactly this
// directory name, so a typo downloads a model that is never found.
var modelesVosk = map[string]string{
	"fr": "vosk-model-small-fr-0.22",
	"en": "vosk-model-en-us-0.22",
	"de": "vosk-model-small-de-0.15",
	"es": "vosk-model-small-es-0.42",
	"it": "vosk-model-small-it-0.22",
	"nl": "vosk-model-small-nl-0.22",
	"pt": "vosk-model-small-pt-0.3",
	"ar": "vosk-model-ar-mgb2-0.4",
	"br": "vosk-model-br-0.8",
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

// nomDeploiement is the name HaRP gives the ExApp's Deployment, its Service and
// the label of its pods: nc-app-<id>, with UNDERSCORES REPLACED BY HYPHENS.
//
// WHY IT MATTERS: "live_transcription" is a valid AppAPI id but not a valid
// Kubernetes LABEL VALUE, and HaRP sanitises it on the way in. Querying with
// the raw id does not fail cleanly — the selector parser answers
// `found '=', expected ','`, which reads as "no such pod" and sends the
// diagnosis after a nonexistent deployment.
func nomDeploiement() string {
	return "nc-app-" + strings.ReplaceAll(appTranscription, "_", "-")
}

// exappsExec runs a shell command inside the ExApp pod, THROUGH THE KUBERNETES
// API — same reasoning as occ below: the console's container is distroless and
// has no kubectl to shell out to.
//
// The ExApp is the only place that holds the speech-model volume, so the shell
// available is the one in ITS image (Debian here, with curl), not Nextcloud's.
func exappsExec(ctx context.Context, cli *k8sapi.Client, script string) (string, error) {
	// The fourth argument is the LABEL VALUE, not a selector: PodDuDeploiement
	// prefixes "app=" itself, and passing a selector here yields "app=app=…",
	// which the label parser rejects.
	pod, err := cli.PodDuDeploiement(ctx, nsExapps, nomDeploiement(), nomDeploiement())
	if err != nil {
		return "", fmt.Errorf("no %s pod in %s: the model cannot be placed before the ExApp runs: %w",
			appTranscription, nsExapps, err)
	}
	// NO CONTAINER NAME: the API then targets the pod's only container, which
	// is what this ExApp has. HaRP names it "app" — not the app id, which is
	// what an earlier version assumed, and the failure ("container
	// live_transcription is not valid for pod …") is reported only at exec
	// time, long after the model was believed placed.
	return cli.Executer(ctx, nsExapps, pod, "", "sh", "-c", script)
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
// etatAppAPI returns the AppAPI status of the app — "enabled", "disabled" — or
// "" when the app is not registered at all.
//
// It reads `app_api:app:list` instead of trusting a previous call: the state
// that matters is the one AppAPI currently reports, and a re-run has to answer
// the same question as a first installation.
func etatAppAPI(ctx context.Context, cli *k8sapi.Client, pod string) (string, error) {
	sortie, err := occ(ctx, cli, pod, "app_api:app:list")
	if err != nil {
		return "", fmt.Errorf("reading the ExApp list: %w", err)
	}
	for _, ligne := range strings.Split(sortie, "\n") {
		ligne = strings.TrimSpace(ligne)
		if !strings.HasPrefix(ligne, appTranscription+" (") {
			continue
		}
		switch {
		case strings.Contains(ligne, "[enabled]"):
			return "enabled", nil
		case strings.Contains(ligne, "[disabled]"):
			return "disabled", nil
		}
		return "unknown", nil
	}
	return "", nil
}

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
