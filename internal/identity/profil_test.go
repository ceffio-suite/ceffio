// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// WHY THESE TESTS EXIST: the unmanaged-attribute policy is the one Keycloak
// setting whose failure is INVISIBLE. With the default policy (DISABLED) every
// attribute write succeeds and then reads back as absent, so no error, no log and
// no exit code tells the operator that the module contract silently stopped
// working. The convergence step is therefore asserted on three points that a
// passing install would not reveal: the profile is READ (not assumed), the whole
// document is SENT BACK (a partial body wipes the profile), and the result is
// verified after the write.

// Les profils de référence reproduisent la forme que kcadm renvoie sur un realm
// neuf : les quatre champs par défaut, sans politique d'attributs.
const profilSansPolitique = `{
  "attributes": [
    {"name": "username", "displayName": "Username", "validations": {"length": {"min": 3, "max": 255}}},
    {"name": "email", "displayName": "Email", "validations": {"email": {"maxLocalLength": 64}}},
    {"name": "firstName", "displayName": "First name"},
    {"name": "lastName", "displayName": "Last name"}
  ],
  "groups": [{"name": "user-metadata", "displayHeader": "User metadata", "displayDescription": "Attributes"}]
}`

func TestLeProfilEstLuPuisEcritEnEntier(t *testing.T) {
	var commandes, entrees []string
	vues := 0
	ancien := executerKcadm
	t.Cleanup(func() { executerKcadm = ancien })
	executerKcadm = func(_ context.Context, _ string, entree, commande string) (string, error) {
		commandes = append(commandes, commande)
		entrees = append(entrees, entree)
		if entree == "" {
			vues++
			if vues == 1 {
				return "Logging into http://localhost:8080 as user admin of realm master\n" + profilSansPolitique, nil
			}
			// LA RELECTURE PROUVE LA PRISE : le profil revient avec la politique.
			return `{"attributes": [{"name": "username"}], "unmanagedAttributePolicy": "ADMIN_EDIT"}`, nil
		}
		return "", nil
	}

	if err := autoriserAttributsPlateforme(context.Background()); err != nil {
		t.Fatalf("autoriserAttributsPlateforme: %v", err)
	}
	if len(commandes) != 3 {
		t.Fatalf("kcadm was invoked %d time(s), want 3 (read, write, read back): %v", len(commandes), commandes)
	}
	if entrees[0] != "" {
		t.Fatalf("the first read carries a payload: %q", entrees[0])
	}
	if !strings.Contains(commandes[1], "update users/profile") ||
		!strings.Contains(commandes[1], "-f /dev/stdin") {
		t.Fatalf("the profile is not written through a file on stdin: %s", commandes[1])
	}

	var envoye map[string]any
	if err := json.Unmarshal([]byte(entrees[1]), &envoye); err != nil {
		t.Fatalf("the document sent to kcadm is not JSON: %v (%q)", err, entrees[1])
	}
	// THE WHOLE DOCUMENT GOES BACK: `update users/profile -f` REPLACES the
	// representation, and a body carrying only the policy wiped the four default
	// fields in a live probe — the login form would have asked for nothing.
	if _, ok := envoye["attributes"]; !ok {
		t.Fatalf("the write drops the profile's fields, which a partial body replaces: %q", entrees[1])
	}
	if _, ok := envoye["groups"]; !ok {
		t.Fatalf("the write drops the profile's groups: %q", entrees[1])
	}
	if envoye["unmanagedAttributePolicy"] != "ADMIN_EDIT" {
		t.Fatalf("the write does not set the policy: %q", entrees[1])
	}
}

func TestLeProfilDejaConvergeNEstPasReecrit(t *testing.T) {
	var commandes []string
	ancien := executerKcadm
	t.Cleanup(func() { executerKcadm = ancien })
	executerKcadm = func(_ context.Context, _ string, _ string, commande string) (string, error) {
		commandes = append(commandes, commande)
		return `{"attributes": [{"name": "username"}], "unmanagedAttributePolicy": "ADMIN_EDIT"}`, nil
	}

	if err := autoriserAttributsPlateforme(context.Background()); err != nil {
		t.Fatalf("autoriserAttributsPlateforme: %v", err)
	}
	if len(commandes) != 1 {
		t.Fatalf("a converged realm is written again (%d kcadm calls): %v", len(commandes), commandes)
	}
}

func TestUneEcritureSansEffetEstUneErreur(t *testing.T) {
	ancien := executerKcadm
	t.Cleanup(func() { executerKcadm = ancien })
	ecrit := false
	executerKcadm = func(_ context.Context, _ string, entree, _ string) (string, error) {
		if entree != "" {
			ecrit = true
		}
		// kcadm accepte le document et ne change rien : c'est le mode d'échec
		// silencieux que cette étape existe pour rendre visible.
		return profilSansPolitique, nil
	}

	if err := autoriserAttributsPlateforme(context.Background()); err == nil {
		t.Fatal("an update that did not land was reported as a success")
	}
	if !ecrit {
		t.Fatal("the policy was never written, so the failure is not the read-back")
	}
}
