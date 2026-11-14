// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package platformmail

import (
	"context"
	"errors"
	"io"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// WHY THESE TESTS EXIST: `Resolve` decides WHICH sender the whole platform uses,
// and its three situations are not variations of one another — they are three
// different products an operator can be running. A regression that silently
// prefers the external relay on a platform that has its own mail server sends
// every password reset through a third party, and nothing reports it.

// reglagesFaux is a ConfigMapStore over a map.
type reglagesFaux struct {
	valeurs map[string]string
	err     error
	lies    int
}

func (r *reglagesFaux) Lire(_ context.Context, _, _, cle string) (string, error) {
	r.lies++
	if r.err != nil {
		return "", r.err
	}
	return r.valeurs[cle], nil
}

func (r *reglagesFaux) Ecrire(context.Context, string, string, map[string]string) error { return nil }
func (r *reglagesFaux) Supprimer(context.Context, string, string, string) error         { return nil }

// envPalier builds an Env the way the CLI does, with only what Resolve reads.
func envPalier(settings module.ConfigMapStore) module.Env {
	return module.Env{
		Domain:   "example.com",
		Kube:     kubefake.NewSimpleClientset(deploiementMailPresent()),
		Out:      io.Discard,
		ModuleID: "files",
		Settings: settings,
	}
}

// deploiementMailPresent is the mail module's Deployment, reduced to what
// MailInstalle reads: its name and its namespace.
func deploiementMailPresent() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: deploiementMail, Namespace: nsMail},
		Spec:       appsv1.DeploymentSpec{},
	}
}

// cofferFaux replaces the vault seam with a map.
func cofferFaux(t *testing.T, entrees map[string]map[string]string, err error) {
	t.Helper()
	remplacer(t, &lireCoffre, func(_ context.Context, composant, nom string) (map[string]string, error) {
		if err != nil {
			return nil, err
		}
		return entrees[composant+"/"+nom], nil
	})
}

func remplacer[T any](t *testing.T, cible *T, valeur T) {
	t.Helper()
	ancien := *cible
	*cible = valeur
	t.Cleanup(func() { *cible = ancien })
}

// TestResolvePrefersThePlatformMailServer : a platform with its own mail server
// sends through it, with the noreply credential and the certificate's hostname.
func TestResolvePrefersThePlatformMailServer(t *testing.T) {
	cofferFaux(t, map[string]map[string]string{
		ComposantCoffre + "/" + SousCheminNoreply: {
			"user":     "noreply@example.com",
			"password": "app-secret",
		},
	}, nil)

	s, err := Resolve(context.Background(), envPalier(&reglagesFaux{}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if s == nil {
		t.Fatal("Resolve returned no sender, but the mail module is installed and its " +
			"noreply credential exists: the platform must send through its own server")
	}
	if s.Host != "mail.example.com" || s.Port != 465 || s.Security != "ssl" {
		t.Fatalf("the platform sender is %s:%d (%s); want mail.example.com:465 (ssl), "+
			"because the mail module's certificate names that host", s.Host, s.Port, s.Security)
	}
	if s.User != "noreply@example.com" || s.From != "noreply@example.com" || s.Password != "app-secret" {
		t.Fatalf("the sender authenticates as %q and sends as %q; want noreply@example.com "+
			"for both, with the stored credential", s.User, s.From)
	}
	if s.FromName == "" {
		t.Fatal("the sender has no display name: the recipient would see the bare address")
	}
}

// TestResolveFallsBackToTheStoredRelayWhenTheCredentialIsMissing : a mail module
// without its noreply credential must not block the platform's mail — the relay
// the operator already configured keeps working.
func TestResolveFallsBackToTheStoredRelayWhenTheCredentialIsMissing(t *testing.T) {
	remplacer(t, &lireCoffre, func(context.Context, string, string) (map[string]string, error) {
		return nil, secrets.ErrEntreeAbsente
	})
	reglages := &reglagesFaux{valeurs: map[string]string{
		cleReglagesSmtp: `{"hote":"relay.example.net","port":"2525","securite":"ssl",` +
			`"utilisateur":"ceffio@example.com","expediteur":"no-reply","nom_expediteur":"Example"}`,
	}}

	s, err := Resolve(context.Background(), envPalier(reglages))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if s == nil {
		t.Fatal("Resolve returned no sender although the relay settings are filled")
	}
	if s.Host != "relay.example.net" || s.Port != 2525 || s.Security != "ssl" {
		t.Fatalf("the relay sender is %s:%d (%s); want relay.example.net:2525 (ssl)",
			s.Host, s.Port, s.Security)
	}
	if s.From != "no-reply@example.com" {
		t.Fatalf("the sender sends as %q; want the local part from the form completed with "+
			"the platform domain", s.From)
	}
	if s.FromName != "Example" {
		t.Fatalf("the sender's display name is %q; want the configured one", s.FromName)
	}
	if s.Password != "" {
		t.Fatalf("the sender carries a password (%q) that no vault entry holds", s.Password)
	}
}

// TestResolveReturnsNothingWithoutAMailServerOrARelay : the "no sender" case is a
// legitimate state, and it must be nil rather than an empty Sender — the writers
// distinguish the two (nil CLEARS a previous configuration).
func TestResolveReturnsNothingWithoutAMailServerOrARelay(t *testing.T) {
	env := envPalier(&reglagesFaux{})
	env.Kube = kubefake.NewSimpleClientset()

	s, err := Resolve(context.Background(), env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if s != nil {
		t.Fatalf("Resolve invented a sender (%+v) on a platform with no mail server and no "+
			"relay settings", s)
	}
}

// TestResolveDefaultsTheRelayPortAndStartTLS : the form's `tls` choice is
// STARTTLS, and the port defaults to 587 when the operator left it empty.
func TestResolveDefaultsTheRelayPortAndStartTLS(t *testing.T) {
	remplacer(t, &lireCoffre, func(context.Context, string, string) (map[string]string, error) {
		return map[string]string{"mot_de_passe": "relay-secret"}, nil
	})
	env := envPalier(&reglagesFaux{valeurs: map[string]string{
		cleReglagesSmtp: `{"hote":"relay.example.net","securite":"tls",` +
			`"utilisateur":"ceffio@example.net","expediteur":"ceffio"}`,
	}})
	env.Kube = kubefake.NewSimpleClientset()

	s, err := Resolve(context.Background(), env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if s == nil {
		t.Fatal("Resolve returned no sender although the relay settings are filled")
	}
	if s.Port != 587 || s.Security != "starttls" {
		t.Fatalf("the relay sender is %s:%d (%s); want port 587 with starttls, which is what "+
			"the form's `tls` choice means", s.Host, s.Port, s.Security)
	}
	if s.Password != "relay-secret" {
		t.Fatalf("the relay password was not read from the vault: %q", s.Password)
	}
}

// TestResolveReportsAnUnreadableSettingsStore : "could not read" and "nothing
// configured" must not be the same answer — one leaves mail alone, the other
// points it somewhere.
func TestResolveReportsAnUnreadableSettingsStore(t *testing.T) {
	env := envPalier(&reglagesFaux{err: errors.New("configmaps \"ceffio-settings\" is forbidden")})
	env.Kube = kubefake.NewSimpleClientset()

	if _, err := Resolve(context.Background(), env); err == nil {
		t.Fatal("Resolve swallowed a settings read error: an installation would then report " +
			"'no sender' while the operator's relay may well be configured")
	}
}

// TestResolveReportsACorruptedSettingsDocument : a JSON document that does not
// parse is a corrupted setting, and reading it as empty would silently disable
// the platform's sender.
func TestResolveReportsACorruptedSettingsDocument(t *testing.T) {
	env := envPalier(&reglagesFaux{valeurs: map[string]string{cleReglagesSmtp: `{"hote":`}})
	env.Kube = kubefake.NewSimpleClientset()

	if _, err := Resolve(context.Background(), env); err == nil {
		t.Fatal("Resolve accepted a truncated JSON document as 'no configuration'")
	}
}

// TestResolveReportsAVaultError : a vault that answers with a real error (a
// revoked token, a sealed cluster) is not "no credential".
func TestResolveReportsAVaultError(t *testing.T) {
	cofferFaux(t, nil, errors.New("vault is sealed"))

	if _, err := Resolve(context.Background(), envPalier(&reglagesFaux{})); err == nil {
		t.Fatal("Resolve swallowed a vault error")
	}
}
