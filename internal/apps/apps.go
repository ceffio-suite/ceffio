// Package apps installs and configures the Nextcloud applications selected
// for Ceffio.
//
// WHY THIS MODULE EXISTS: a Nextcloud app installed by hand is part of no
// installation. It lives in /var/www/html/custom_apps — hence in the
// container, on a persistent volume: it survives restarts, but disappears as
// soon as one deploys on a fresh machine. Without this module, a Ceffio
// installation would have NONE of these apps, and the selection work would
// have to be redone every time.
//
// WHAT DECIDES THE CONTENT OF THE LIST:
//   - FREE license without restriction on commercial use (AGPL-3.0, never a
//     user quota nor a proprietary license);
//   - STABLE published version (no beta);
//   - real contribution to multi-user work.
//
// What is VOLUNTARILY EXCLUDED:
//   - richdocuments (Collabora): ONLYOFFICE is already deployed, a second
//     office-editing server would double the load and maintenance for the
//     same function;
//   - theme/decoration apps: they bring nothing to collaboration.
package apps

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// categorie distinguishes apps by what they require beyond themselves. This is
// the distinction that matters for a deployment: a server-category app will
// not work after a plain `app:install`.
type categorie int

const (
	// simple: the app lives in custom_apps and works as soon as it is enabled.
	simple categorie = iota
	// serveur: the app needs a separate service to be fully functional
	// (real-time, heavy computation). Installed without it, it enables but
	// stays limited.
	serveur
)

// App describes an application installed by Ceffio.
type App struct {
	ID        string    // app store identifier (= custom_apps folder name)
	Nom       string    // human-readable name
	Role      string    // what it is for, in one line
	Licence   string    // license observed on the app store
	Cat       categorie //
	DependsOn string    // required service, empty if none
	// Avertissement signals a RISK, not a dependency: the app can be enabled,
	// but not lightly. Distinct from DependsOn, which means "a service is
	// missing, do not enable it".
	Avertissement string
}

// Catalogue: the selected inventory, checked on the official app store for
// Nextcloud 34. ALL entries are under a free license (AGPL-3.0), with no
// restriction on commercial use and no user quota.
//
// The category separates two things the user must NOT confuse:
//
//	simple  → the app works as soon as it is enabled (page 1, installable)
//	serveur → the app needs a separate service (page 2, read-only)
//
// The two lists are DISJOINT: an app appears on a single page.
var Catalogue = []App{
	// ── Page 1: no dependency, installable ──────────────────────────────
	{ID: "deck", Nom: "Deck", Cat: simple, Licence: "AGPL-3.0",
		Role: "shared Kanban boards (project management)"},
	{ID: "collectives", Nom: "Collectives", Cat: simple, Licence: "AGPL-3.0",
		Role: "team wiki and documentation"},
	{ID: "forms", Nom: "Forms", Cat: simple, Licence: "AGPL-3.0",
		Role: "forms and surveys"},
	{ID: "polls", Nom: "Polls", Cat: simple, Licence: "AGPL-3.0",
		Role: "availability polls (plan a meeting)"},
	{ID: "tasks", Nom: "Tasks", Cat: simple, Licence: "AGPL-3.0",
		Role: "shared tasks and lists"},
	{ID: "calendar", Nom: "Calendar", Cat: simple, Licence: "AGPL-3.0",
		Role: "shared calendar"},
	{ID: "contacts", Nom: "Contacts", Cat: simple, Licence: "AGPL-3.0",
		Role: "shared contact book"},
	{ID: "tables", Nom: "Tables", Cat: simple, Licence: "AGPL-3.0",
		Role: "structured tables (lightweight database)"},
	{ID: "notes", Nom: "Notes", Cat: simple, Licence: "AGPL-3.0",
		Role: "note-taking (markdown)"},
	{ID: "groupfolders", Nom: "Team folders", Cat: simple, Licence: "AGPL-3.0",
		Role: "group-shared folders (not user-to-user)"},
	{ID: "appointments", Nom: "Appointments", Cat: simple, Licence: "AGPL-3.0",
		Role: "appointment booking with a public link"},
	{ID: "mail", Nom: "Mail", Cat: simple, Licence: "AGPL-3.0",
		Role: "integrated mail client"},
	{ID: "announcementcenter", Nom: "Announcements", Cat: simple, Licence: "AGPL-3.0",
		Role: "admin announcements to all users"},
	{ID: "files_retention", Nom: "Retention", Cat: simple, Licence: "AGPL-3.0",
		Role: "automatic deletion of files after a duration"},
	{ID: "files_accesscontrol", Nom: "Access control", Cat: simple, Licence: "AGPL-3.0",
		Role: "file access rules (forbid a type, a group…)"},
	{ID: "bookmarks", Nom: "Bookmarks", Cat: simple, Licence: "AGPL-3.0",
		Role: "shared bookmarks"},
	{ID: "external", Nom: "External sites", Cat: simple, Licence: "AGPL-3.0",
		Role: "links to external sites in the interface"},
	{ID: "group_everyone", Nom: "Everyone group", Cat: simple, Licence: "AGPL-3.0",
		Role: "automatic group containing all users"},

	// ── Page 2: external dependency, NOT installable ───────────────────
	{
		ID: "whiteboard", Nom: "Whiteboard", Cat: serveur, Licence: "AGPL-3.0",
		Role:      "collaborative whiteboard (real-time)",
		DependsOn: "WebSocket server to deploy (port 3002)",
	},
	{
		ID: "recognize", Nom: "Recognize", Cat: serveur, Licence: "AGPL-3.0",
		Role:      "AI search and classification in documents",
		DependsOn: "AI models to download (several hundred MB)",
	},
	{
		ID: "files_antivirus", Nom: "Antivirus", Cat: serveur, Licence: "AGPL-3.0",
		Role:      "antivirus scanning of uploaded files",
		DependsOn: "ClamAV server to deploy separately",
	},
	{
		ID: "encryption", Nom: "Storage encryption", Cat: serveur, Licence: "AGPL-3.0",
		Role: "encryption of files at rest",
		// CAUTION: this is NOT a missing dependency, it is a RISK.
		// We therefore leave it installable (empty DependsOn) but we flag it
		// separately — disabling it automatically would be excessive, enabling
		// it silently would be dangerous.
		Avertissement: "irreversible: once enabled, decrypting takes days",
	},
}

// Deploy installs and enables the selected applications, idempotently.
//
// Idempotent in the strict sense: `app:install` fails if the app is already
// there and `app:enable` succeeds doing nothing. We therefore do NOT treat
// the install failure as an error — otherwise a second pass would report a
// failure where everything is fine.
//
// WHAT WE DO NOT ENABLE, AND WHY: an application whose DependsOn is set
// requires a service that is NOT deployed by Ceffio (whiteboard WebSocket
// server, ClamAV, AI models…). Enabling it anyway installs it in a state
// where it gets in the way and breaks whatever it touches: observed with
// files_antivirus, enabled without clamscan, which made EVERY connection fail
// with error 500 ("No connection to anti virus"). We therefore install it
// without enabling it: it is present, visible, and one only has to deploy its
// dependency then enable it to use it.
func Deploy(ctx context.Context) error {
	fmt.Println("\nInstalling Nextcloud applications (Phase 12)...")

	// 1. Initial state: "present" and "active" are TWO things.
	//    We read both, because an app with an external dependency must stay
	//    present without being active.
	deja := appsInstallees(ctx)
	actives0 := appsActives(ctx)

	var actives, nouvelles, posees, enAttente []string
	for _, a := range Catalogue {
		if _, ok := deja[a.ID]; !ok {
			nouvelles = append(nouvelles, a.Nom)
		}
		// 2. Install if absent.
		if err := occ(ctx, "app:install", a.ID); err != nil &&
			!strings.Contains(err.Error(), "already installed") {
			// A real failure: we report it and continue. An unavailable app
			// must not prevent the others from installing.
			fmt.Printf("  ! %s: installation impossible (%v)\n", a.Nom, err)
			continue
		}

		// 3. External dependency not provided: we install WITHOUT enabling.
		//    Enabling it would make it run without its service and break the
		//    instance — that is exactly the files_antivirus trap.
		if a.DependsOn != "" {
			// If it had been enabled by a previous version, we disable it: the
			// fix must apply to existing instances, not only to fresh
			// installs.
			if _, active := actives0[a.ID]; active {
				if err := occ(ctx, "app:disable", a.ID); err == nil {
					fmt.Printf("  ∙ %s: disabled (missing dependency: %s)\n",
						a.Nom, a.DependsOn)
				}
			}
			posees = append(posees, a.Nom)
			enAttente = append(enAttente, fmt.Sprintf("%s (requires %s)", a.Nom, a.DependsOn))
			continue
		}

		if err := occ(ctx, "app:enable", a.ID); err != nil {
			fmt.Printf("  ! %s: activation impossible (%v)\n", a.Nom, err)
			continue
		}
		actives = append(actives, a.Nom)
	}

	if len(nouvelles) > 0 {
		fmt.Printf("  ∙ %d new: %s\n",
			len(nouvelles), strings.Join(nouvelles, ", "))
	} else {
		fmt.Println("  ∙ all applications were already installed")
	}
	fmt.Printf("  ✓ %d active applications: %s\n",
		len(actives), strings.Join(actives, ", "))

	// 4. Report the apps installed but left INACTIVE, with what it would take
	//    to enable them. Transparency: without this message, the user would
	//    believe they are available.
	if len(posees) > 0 {
		fmt.Printf("  ∙ %d application(s) installed but left inactive:\n", len(posees))
		for _, e := range enAttente {
			fmt.Println("      " + e)
		}
		fmt.Println("      → deploy the dependency, then enable the app in Nextcloud")
	}

	// 4. Clean the app cache: without this, Nextcloud can keep serving a
	//    stale app list after an installation.
	if err := occ(ctx, "maintenance:repair", "--include-expensive"); err != nil {
		// Non-blocking: the repairer can fail on inconsequential details, and
		// the app installation is already done.
		fmt.Printf("  (cache repair ignored: %v)\n", err)
	}

	fmt.Println("✓ Nextcloud applications installed")
	return nil
}

// appsInstallees returns the set of app identifiers already present.
func appsInstallees(ctx context.Context) map[string]struct{} {
	out, err := occSortie(ctx, "app:list", "--output=json")
	if err != nil {
		return map[string]struct{}{}
	}
	// We do not parse the JSON: we simply look for the known identifiers in
	// the output. Strict parsing would be fragile, and it serves no purpose
	// here — we only want to know "already there" or not.
	connus := map[string]struct{}{}
	for _, a := range Catalogue {
		if strings.Contains(out, `"`+a.ID+`"`) {
			connus[a.ID] = struct{}{}
		}
	}
	return connus
}

// appsActives returns the set of ACTIVE app identifiers.
//
// WHY SEPARATE FROM appsInstallees: `app:list` contains two sections,
// "enabled" and "disabled". An app can be PRESENT without being active —
// which is exactly the state we want to leave the external-dependency ones
// in. Searching for the identifier in the whole output therefore does not say
// whether the app runs: one must read the "enabled" section.
func appsActives(ctx context.Context) map[string]struct{} {
	out, err := occSortie(ctx, "app:list", "--output=json")
	if err != nil {
		return map[string]struct{}{}
	}
	// "enabled" section only. If the JSON changes shape, we return nothing:
	// better to disable nothing by mistake than to touch an app whose state we
	// misread.
	var liste struct {
		Enabled map[string]any `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(out), &liste); err != nil {
		return map[string]struct{}{}
	}
	actives := map[string]struct{}{}
	for id := range liste.Enabled {
		actives[id] = struct{}{}
	}
	return actives
}

// occ runs an occ command in the Nextcloud pod.
func occ(ctx context.Context, args ...string) error {
	_, err := occSortie(ctx, args...)
	return err
}

// occSortie runs occ and returns the standard output.
func occSortie(ctx context.Context, args ...string) (string, error) {
	complet := append([]string{
		"exec", "-n", "ceffio-files", "deploy/nextcloud", "-c", "nextcloud", "--",
		"php", "occ",
	}, args...)
	cmd := k8s.Command(ctx, "kubectl", complet...)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
