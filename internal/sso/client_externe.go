// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package sso

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// Client is an OIDC client a module declares for itself.
//
// WHY THIS TYPE EXISTS: the core's clients are a central list (clientsOIDC), and
// adding a module's client there would mean editing this package every time a feature
// is added — exactly what the module system exists to avoid. A module that needs a
// client calls AssurerClient with its own description, and this package never learns
// its name.
type Client struct {
	// ID is the clientId in Keycloak. It appears in the application's configuration,
	// so it must be stable.
	ID string

	// Redirects is the comma-separated list of return addresses. Keycloak keeps this
	// list separately from PostLogout: filling one does not fill the other, and a
	// client with only redirects refuses to return anywhere after a sign-out.
	Redirects string

	// PostLogout is the comma-separated list of addresses allowed after a SIGN-OUT.
	PostLogout string

	// Public marks a client that cannot keep a secret — a browser application. Such a
	// client has no secret, and PKCE becomes mandatory rather than optional.
	Public bool

	// CoffreComposant and CoffreChemin are where the secret is STORED inside OpenBao,
	// as the (component, path) pair the vault API takes.
	//
	// A MODULE OWNS ITS OWN PATH: writing under the core's convention would put a
	// module's credential where the core's clients live, and a later core change would
	// walk over it.
	//
	// EMPTY MEANS "the caller keeps the secret itself": a PUBLIC client has none, and
	// a caller that manages its own vault entry writes it there.
	CoffreComposant string
	CoffreChemin    string

	// Audience marks a client that VALIDATES the token's audience. Keycloak never puts
	// the caller's own clientId in `aud` on its own: without an explicit mapper the
	// claim is absent, and a relying party that checks it refuses every token — after
	// a login that looked successful.
	Audience bool
}

// AssurerClient creates or updates an OIDC client, IDEMPOTENTLY, and returns its
// secret.
//
// IT IS THE GENERIC FORM of what assurerUnClient does for the core's clients, with the
// secret STORED IN THE VAULT under the client's own id. A module gets the same
// guarantees the core relies on:
//
//   - the properties are written on BOTH paths, creation and update. Returning early
//     when the client exists is how a property added later never reaches an
//     installation already in place;
//   - the secret is REUSED, never regenerated: it is known to Keycloak AND to the
//     application, and inventing a new one breaks the pair with a failure that says
//     nothing about the cause;
//   - a PUBLIC client has no secret at all, and the function returns "" rather than
//     writing one onto a client that refuses it.
//
// THE SECRET IS RETURNED RATHER THAN ASSUMED STORED: a module needs it to build its
// pod's configuration, and reading it back from the vault would be a second path to
// the same value.
func AssurerClient(ctx context.Context, c Client) (string, error) {
	if c.ID == "" {
		return "", fmt.Errorf("sso: a client needs an ID")
	}
	if c.Redirects == "" {
		return "", fmt.Errorf("sso: client %s declares no redirect URI: Keycloak refuses "+
			"every login until one is listed", c.ID)
	}

	uuid, err := ensureClient(ctx, c.ID, c.Redirects, c.PostLogout, c.Public)
	if err != nil {
		return "", fmt.Errorf("OIDC client %s: %w", c.ID, err)
	}

	// THE AUDIENCE MAPPER, BEFORE ANY SECRET WORK: a client that verifies `aud` needs
	// the claim to exist, and the mapper is what puts it there.
	if c.Audience {
		if err := assurerMapperAudience(ctx, uuid, c.ID); err != nil {
			return "", fmt.Errorf("OIDC client %s: %w", c.ID, err)
		}
	}

	if c.Public {
		// A public client authenticates by PKCE. Writing a secret onto it would make
		// the console announce a client that cannot work.
		return "", nil
	}

	// REUSE THE STORED SECRET, otherwise take back the one Keycloak already knows,
	// otherwise generate. The order matters: the vault is what the application reads,
	// Keycloak is the authority on its own client, and generating is the LAST RESORT —
	// it is the only step that can break a pair that was working.
	secretVal, ok := secretDuCoffre(ctx, c)
	if !ok {
		if depuisKeycloak, errKC := lireSecretClientKeycloak(ctx, uuid); errKC == nil && depuisKeycloak != "" {
			secretVal = depuisKeycloak
		} else {
			nouveau, err := genSecret(24)
			if err != nil {
				return "", fmt.Errorf("OIDC client %s: generating a secret: %w", c.ID, err)
			}
			secretVal = nouveau
		}
	}

	if err := setClientSecret(ctx, uuid, secretVal); err != nil {
		return "", fmt.Errorf("OIDC client %s: %w", c.ID, err)
	}
	if err := ecrireSecretClient(ctx, c, secretVal); err != nil {
		return "", fmt.Errorf("OIDC client %s: storing its secret: %w", c.ID, err)
	}
	return secretVal, nil
}

// secretDuCoffre reads the client's secret from ITS OWN vault entry.
//
// A MISSING ENTRY IS NOT AN ERROR HERE: the caller falls back to Keycloak, then to a
// generated value. Reporting it would turn the first installation into a failure.
func secretDuCoffre(ctx context.Context, c Client) (string, bool) {
	if c.CoffreComposant == "" || c.CoffreChemin == "" {
		return "", false
	}
	entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(),
		c.CoffreComposant, c.CoffreChemin)
	if err != nil {
		return "", false
	}
	v := entree["client-secret"]
	return v, v != ""
}

// ecrireSecretClient stores the secret where the module will read it.
//
// A CLIENT WITH NO Coffre KEEPS NOTHING: the caller owns its storage, and writing under
// a path it did not ask for would be a credential in a place nobody reads.
func ecrireSecretClient(ctx context.Context, c Client, secret string) error {
	if c.CoffreComposant == "" || c.CoffreChemin == "" {
		return nil
	}
	return secrets.EcrireDansCoffre(ctx, secrets.DepuisEnvironnement(),
		c.CoffreComposant, c.CoffreChemin,
		map[string]string{"client-id": c.ID, "client-secret": secret})
}
