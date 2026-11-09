// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the OIDC directory payload.
//
// WHY THEY EXIST: Stalwart 1.0 renamed the audience fields, and REFUSES the
// old names — the whole patch is rejected ("invalidPatch", "Invalid property:
// requireAudience"). Measured on 1.0.3 by replaying the pre-1.0 payload. The
// SSO step runs during `ceffio upgrade`: writing the wrong format fails the
// upgrade after the new pod is already serving. These tests make the two
// formats explicit and keep one from leaking into the other.
package mail

import (
	"testing"
)

var annuaireTest = SSO{
	Hote:         "mail.ceffio.example.com",
	Issuer:       "https://keycloak.ceffio.example.com/realms/ceffio",
	ClientID:     "stalwart-webui",
	DomaineAdmin: "ceffio.local",
	CompteAdmin:  "adminceffio",
}

// The 1.0 format: the audience is a SET, and the pre-1.0 field names are
// absent — their mere presence is what 1.0 refuses.
func TestChampsAnnuaireModerne(t *testing.T) {
	corps := champsAnnuaire(annuaireTest, true)

	audiences, ok := corps["acceptedAudiences"].(map[string]any)
	if !ok {
		t.Fatalf("acceptedAudiences missing or of the wrong type: %T", corps["acceptedAudiences"])
	}
	if _, ok := audiences["stalwart-webui"]; !ok {
		t.Errorf("acceptedAudiences = %v, the WebUI client is missing", audiences)
	}
	for _, interdit := range []string{"requireAudience", "requireScopes"} {
		if _, present := corps[interdit]; present {
			t.Errorf("%s is present in the 1.0 payload: Stalwart 1.0 refuses the whole patch", interdit)
		}
	}

	// Settings shared by both formats: losing them would break SSO silently.
	for champ, attendu := range map[string]string{
		"@type":          "Oidc",
		"issuerUrl":      annuaireTest.Issuer,
		"claimUsername":  "preferred_username",
		"usernameDomain": annuaireTest.DomaineAdmin,
	} {
		if corps[champ] != attendu {
			t.Errorf("%s = %v, want %q", champ, corps[champ], attendu)
		}
	}
}

// The pre-1.0 format, kept for a store that has not been migrated yet.
func TestChampsAnnuaireHeritage(t *testing.T) {
	corps := champsAnnuaire(annuaireTest, false)

	if corps["requireAudience"] != annuaireTest.ClientID {
		t.Errorf("requireAudience = %v, want %q", corps["requireAudience"], annuaireTest.ClientID)
	}
	scopes, ok := corps["requireScopes"].(map[string]any)
	if !ok || len(scopes) != 0 {
		t.Errorf("requireScopes = %v, want an empty map (null is refused by the API)", corps["requireScopes"])
	}
	if _, present := corps["acceptedAudiences"]; present {
		t.Error("acceptedAudiences is present in the pre-1.0 payload")
	}
}
