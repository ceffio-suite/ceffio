// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The Nextcloud Mail side of an internal user's mailbox (§4.7, §9.J).
//
// # Why the account is created through `occ`
//
// Nextcloud Mail keeps its own account rows in its app tables, and no public
// HTTP endpoint creates one on behalf of another user: the Mail app's API is
// scoped to the logged-in user. The provisioned account is therefore written
// with the CLI, inside the Nextcloud pod, exactly like the platform's address
// book and calendar steps do (`internal/platformmail`).
//
// # The password is briefly visible in the pod's process list
//
// `occ mail:account:create-imap` takes the IMAP and SMTP passwords as ARGUMENTS,
// so for the duration of the call they appear in `ps` inside the Nextcloud pod
// (§4.7 documents this). It is accepted rather than hidden: the only other way
// is the Mail app's HTTP API driven with the user's own session, which Ceffio
// must not hold, and the alternative — leaving the user to type their app
// password by hand — reintroduces the manual step the feature exists to remove.
// The exposure is bounded by the pod's RBAC (pods/exec is already granted to
// the mail module) and by the fact that anyone who can read that process list
// can exec into the pod anyway.
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	nsFichiers        = "ceffio-files"
	deploiementNC     = "nextcloud"
	conteneurNC       = "nextcloud"
	etiquetteNC       = "nextcloud"
	portIMAP          = "993"
	portSMTP          = "465"
	modeSSL           = "ssl" // implicit TLS on 993 and 465 (§9.J)
	methodeAuthCompte = "password"
)

// comptesNextcloud mirrors what `mail:account:export` prints: a JSON array of
// the user's provisioned accounts.
//
// ONLY THE FIELDS THE CALLER USES: the export also carries every IMAP and SMTP
// setting, and decoding them would couple us to a shape the app may change.
type compteNextcloud struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// occComptes returns a function that runs `php occ` inside the Nextcloud pod.
//
// THE POD IS LOOKED UP ONCE PER CALL: a mailbox operation issues two or three
// occ commands, and resolving the pod each time would let a rolling restart
// change the target in the middle of them.
//
// IT IS A SEAM: `commandeOcc` is a variable so the tests exercise the argument
// list without a cluster, and the rest of this file never mentions the pod.
var commandeOcc = occComptes

func occComptes(ctx context.Context) (func(args ...string) (string, error), error) {
	client, err := clientK8s()
	if err != nil {
		return nil, fmt.Errorf("connecting to the cluster to reach Nextcloud: %w", err)
	}
	pod, err := client.PodDuDeploiement(ctx, nsFichiers, deploiementNC, etiquetteNC)
	if err != nil {
		return nil, fmt.Errorf("finding the Nextcloud pod: %w", err)
	}
	return func(args ...string) (string, error) {
		return client.Executer(ctx, nsFichiers, pod, conteneurNC,
			append([]string{"php", "occ"}, args...)...)
	}, nil
}

// AssurerCompteNextcloudMail creates the user's Mail account if it is missing.
//
// THE ADDRESS IS THE IDENTITY, NOT THE ID: the account is looked up by the
// address the user sees, because that is what `EnsureAccount` owns and what the
// deletion path matches on. A user who already created the account by hand for
// the same address is adopted — recreating it would lose their sent folder and
// their per-account preferences.
func AssurerCompteNextcloudMail(ctx context.Context, utilisateur, nomAffiche, adresse, hote, login, motDePasse string) error {
	occ, err := commandeOcc(ctx)
	if err != nil {
		return err
	}
	existants, err := compterNextcloud(ctx, occ, utilisateur)
	if err != nil {
		return err
	}
	for _, existant := range existants {
		if strings.EqualFold(existant.Email, adresse) {
			return nil
		}
	}
	// A NAMED ACCOUNT, NOT A PROVISIONED ONE: `mail:account:create-imap` writes
	// a plain account the user can edit; the provisioning flow is for
	// auto-configured domains and cannot be deleted from the CLI (§9.J), which
	// would make `delete-mailbox` fail for every user.
	_, err = occ("mail:account:create-imap",
		utilisateur, nomAffiche, adresse,
		hote, portIMAP, modeSSL, login, motDePasse,
		hote, portSMTP, modeSSL, login, motDePasse,
		methodeAuthCompte,
	)
	if err != nil {
		return fmt.Errorf("creating the Nextcloud Mail account of %s: %w", utilisateur, err)
	}
	return nil
}

// SupprimerCompteNextcloudMail removes the user's Mail account(s) carrying the
// platform address.
//
// EVERY MATCH IS DELETED, NOT THE FIRST ONE: a retried install or a user who
// created the account twice can leave duplicates, and leaving one behind means
// the mailbox keeps being polled after the Stalwart account is gone.
func SupprimerCompteNextcloudMail(ctx context.Context, utilisateur, adresse string) error {
	occ, err := commandeOcc(ctx)
	if err != nil {
		return err
	}
	existants, err := compterNextcloud(ctx, occ, utilisateur)
	if err != nil {
		return err
	}
	var dernier error
	for _, existant := range existants {
		if !strings.EqualFold(existant.Email, adresse) {
			continue
		}
		if _, err := occ("mail:account:delete", fmt.Sprintf("%d", existant.ID)); err != nil {
			dernier = fmt.Errorf("deleting the Nextcloud Mail account %d of %s: %w", existant.ID, utilisateur, err)
		}
	}
	return dernier
}

// compterNextcloud returns the user's Mail accounts.
//
// A USER WITHOUT ANY ACCOUNT IS NOT AN ERROR: `mail:account:export` prints an
// empty array, which is exactly the state of a freshly created user. Only a
// failing command is an error.
func compterNextcloud(ctx context.Context, occ func(args ...string) (string, error), utilisateur string) ([]compteNextcloud, error) {
	brut, err := occ("mail:account:export", utilisateur, "--output=json")
	if err != nil {
		return nil, fmt.Errorf("listing the Nextcloud Mail accounts of %s: %w", utilisateur, err)
	}
	// THE OUTPUT MAY CARRY LOG LINES BEFORE THE JSON: `occ` prints its bootstrap
	// warnings on stdout, so the array is located rather than expected at the
	// first byte.
	debut := strings.Index(brut, "[")
	if debut < 0 {
		return nil, fmt.Errorf("the Nextcloud Mail export of %s holds no JSON array", utilisateur)
	}
	var comptes []compteNextcloud
	if err := json.Unmarshal([]byte(brut[debut:]), &comptes); err != nil {
		return nil, fmt.Errorf("decoding the Nextcloud Mail export of %s: %w", utilisateur, err)
	}
	return comptes, nil
}
