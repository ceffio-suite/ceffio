// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// semence describes one vault entry, and where it comes from.
type semence struct {
	composant string   // tree: kv/ceffio/<composant>/<nom>
	nom       string   // entry name — the one looked up in the vault
	ns        string   // source Kubernetes namespace
	secret    string   // Kubernetes Secret name
	cles      []string // keys taken over, grouped into ONE entry
}

// semences lists what gets lifted into the vault.
//
// ONE ENTRY PER ACCOUNT OR PER PACKAGE, NOT ONE PER KEY. That correction comes
// from practice: filed by key, Nextcloud's administration account existed
// nowhere as an entry — you found "a password" without knowing what it opened,
// and looking for the account gave nothing. A vault where you cannot find what
// you put in it does not do its job.
//
// ORDER MATTERS: start with the LEAVES — a component few things depend on.
// Stalwart first: one account, one consumer, no duplication. Talk and SMTP
// sending come next, and they do carry duplication — but SEEDING does not
// touch it: we copy, we modify nothing.
//
// NOTHING IS OMITTED OUT OF CAUTION, and that is deliberate. Nextcloud and
// Keycloak were kept out of the first list in the name of risk — but "seeding"
// is a COPY: there is nothing to break. A secret missing from the vault reads
// as an installation defect, and that is exactly what happened. Restraint
// belongs to the last step — switching CONSUMPTION over — not to this one.
var semences = []semence{
	// Leaves
	{composant: "stalwart", nom: "admin", ns: "ceffio-mail", secret: "stalwart-admin",
		cles: []string{"username", "password", "storage"}},
	{composant: "onlyoffice", nom: "jwt", ns: "ceffio-office", secret: "onlyoffice-secret",
		cles: []string{"jwt"}},
	{composant: "talk", nom: "signaling", ns: "ceffio-video", secret: "talk-secrets",
		cles: []string{"hash-key", "block-key", "partage", "turn-secret"}},
	{composant: "console", nom: "api", ns: "ceffio-system", secret: "ceffio-console-key",
		cles: []string{"key"}},
	{composant: "nextcloud", nom: "oidc", ns: "ceffio-identity", secret: "nextcloud-oidc",
		cles: []string{"client-id", "client-secret"}},
	{composant: "openbao", nom: "oidc", ns: "ceffio-identity", secret: "openbao-oidc",
		cles: []string{"client-id", "client-secret"}},
	{composant: "smtp", nom: "relais", ns: "ceffio-files", secret: "nextcloud-smtp",
		cles: []string{"username", "password"}},

	// Local service accounts: this is what gets looked up here first.
	{composant: "nextcloud", nom: "admin", ns: "ceffio-files", secret: "nextcloud-admin",
		cles: []string{"username", "password"}},
	{composant: "nextcloud", nom: "db", ns: "ceffio-files", secret: "nextcloud-db",
		cles: []string{"username", "password"}},
	{composant: "console", nom: "nextcloud-api", ns: "ceffio-system", secret: "nextcloud-console-api",
		cles: []string{"username", "password"}},
	{composant: "keycloak", nom: "admin", ns: "ceffio-identity", secret: "keycloak-admin",
		cles: []string{"username", "password"}},
	{composant: "keycloak", nom: "db", ns: "ceffio-identity", secret: "keycloak-db",
		cles: []string{"username", "password"}},
	{composant: "postgres", nom: "app", ns: "ceffio-data", secret: "ceffio-pg-app",
		// Credentials only: the same Secret contains connection strings that
		// RESTATE them. Seeding those would make three copies of one password,
		// and three places to fix on rotation day.
		cles: []string{"username", "password"}},
}

// Semer lifts into the vault the secrets that ALREADY live in Kubernetes.
//
// READ FIRST, SERVICES RUNNING, NOTHING SWITCHED OVER. At this stage no
// component reads from the vault: we build the reference copy, and verify it
// reads back. Switching consumption over is a different job, and it happens
// one component at a time.
//
// TWO RULES, AND THEY ARE THE WHOLE POINT:
//
//   - NEVER OVERWRITE. An entry already present is not replaced: it may be
//     newer than the Kubernetes copy, or currently in service. Overwriting on
//     every pass would turn every redeployment into a silent rotation —
//     exactly what we are trying to avoid.
//   - REGENERATE NOTHING. If the value exists nowhere, we do not invent it, we
//     SAY SO. An invented secret would correspond to nothing alive, and would
//     break the service at the very moment it was handed over.
//
// The result is idempotent: running it again changes nothing, and the report
// shows that instead of leaving it assumed.
func Semer(ctx context.Context, cli *k8sapi.Client) error {
	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return err
	}
	var poses, deja, incompletes int
	for _, s := range semences {
		chemin := "kv/ceffio/" + s.composant + "/" + s.nom

		donnees := map[string]string{}
		manquantes := []string{}
		for _, cle := range s.cles {
			valeur, err := cli.LireSecret(ctx, s.ns, s.secret, cle)
			if err != nil {
				return fmt.Errorf("reading %s/%s: %w", s.ns, s.secret, err)
			}
			if valeur == "" {
				manquantes = append(manquantes, cle)
				continue
			}
			donnees[cle] = valeur
		}
		if len(manquantes) > 0 {
			// SAY it rather than filling in an invented value: a half-false
			// entry looks complete, and that is the worst case.
			fmt.Printf("  ∙ %s: %v absent from Kubernetes — not invented\n", chemin, manquantes)
			incompletes++
		}
		if len(donnees) == 0 {
			continue
		}

		presente, err := entreePresente(ctx, cli, adm, chemin, s.cles[0])
		if err != nil {
			return err
		}
		if presente {
			deja++
			continue
		}
		if err := poserAuCoffre(ctx, cli, adm, chemin, donnees); err != nil {
			return fmt.Errorf("writing %s: %w", chemin, err)
		}
		fmt.Printf("  + %s (%d key(s))\n", chemin, len(donnees))
		poses++
	}
	fmt.Printf("  ∙ seeding: %d entry/entries placed, %d already present, %d incomplete\n",
		poses, deja, incompletes)
	return nil
}

// entreePresente reports whether the entry already exists in the vault.
//
// A FAILURE ALONE DOES NOT PROVE "ABSENT". An error can mean "not there yet" —
// the common case on the first pass — or an access refusal, or even an
// unreachable vault. Confusing the two would mean writing blind, or worse,
// skipping an entry wrongly in the belief it exists. The question is settled
// by asking a second time, differently.
//
// MIND THE PATH: `kv` commands take the LOGICAL path ("kv/ceffio", the key
// implied). They add the "metadata/" segment themselves when needed. Passing
// "kv/metadata/ceffio" therefore produces "kv/metadata/metadata/ceffio", and
// the resulting error — "No value found" — reads wrongly as a vault down.
// Observed in service.
func entreePresente(ctx context.Context, cli *k8sapi.Client, jeton, chemin, cleTemoin string) (bool, error) {
	if _, err := baoAvecJeton(ctx, cli, jeton, "kv", "get", "-field="+cleTemoin, chemin); err == nil {
		return true, nil
	}
	if _, err := baoAvecJeton(ctx, cli, jeton, "kv", "list", "kv/ceffio"); err != nil {
		return false, fmt.Errorf("the vault is not answering correctly (entry %s): %w", chemin, err)
	}
	return false, nil
}

// poserAuCoffre writes one entry, going through a payload file.
//
// WHY NOT AS ARGUMENTS: the values ARE the secrets. On a command line they
// would be readable in the container's process list — and the vault exists
// precisely to avoid that kind of trace.
func poserAuCoffre(ctx context.Context, cli *k8sapi.Client, jeton, chemin string, donnees map[string]string) error {
	if err := ecrirePayloadCoffre(ctx, cli, "/tmp/semence.json", donnees); err != nil {
		return err
	}
	_, err := baoAvecJeton(ctx, cli, jeton, "kv", "put", chemin, "@/tmp/semence.json")
	// The payload carried the values: it disappears as soon as it has served,
	// whatever the outcome.
	retirerPayloadCoffre(ctx, cli, "/tmp/semence.json")
	return err
}
