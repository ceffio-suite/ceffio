// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the landing page's settings: the form as it is declared, the
// address travelling from the store to the published ConfigMap, and the
// refusals that happen before anything is written.
//
// WHY THEY EXIST: the contact address is the one value of the page that is
// DATA and not a derivation of the host. Every failure mode below is silent in
// production — a stored address the page ignores, a page that keeps publishing
// the address it was asked to remove, a roll that never happens so the pod
// serves the previous page — and none of them would be caught by installing
// once and looking at the result.
package website

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/module"
	site "github.com/ceffio-suite/ceffio/internal/website"
)

// magasinTest is the settings ConfigMap in memory: enough to prove what a save
// writes, and what it does NOT write when it refuses.
type magasinTest struct {
	donnees   map[string]string
	ecritures []map[string]string
}

func nouveauMagasin() *magasinTest { return &magasinTest{donnees: map[string]string{}} }

func (m *magasinTest) Lire(_ context.Context, _, _, cle string) (string, error) {
	return m.donnees[cle], nil
}

func (m *magasinTest) Ecrire(_ context.Context, _, _ string, donnees map[string]string) error {
	copie := map[string]string{}
	for cle, valeur := range donnees {
		copie[cle] = valeur
		m.donnees[cle] = valeur
	}
	m.ecritures = append(m.ecritures, copie)
	return nil
}

func (m *magasinTest) Supprimer(_ context.Context, _, _, cle string) error {
	delete(m.donnees, cle)
	return nil
}

// adresseTest is the address the tests publish: example.com is the domain
// RFC 2606 reserves for documentation, so no real person is named.
const adresseTest = "equipe@example.com"

// fakeCluster is a cluster that answers like a real one, controller included.
func fakeCluster(t *testing.T) *fake.Clientset {
	t.Helper()
	cs := fake.NewSimpleClientset()
	fauxControleur(cs)
	return cs
}

// pagePubliee reads the ConfigMap the visitor is actually served.
func pagePubliee(t *testing.T, cs *fake.Clientset) map[string]string {
	t.Helper()
	cm, err := cs.CoreV1().ConfigMaps(nsSite).Get(context.Background(), nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the published ConfigMap is missing: %v", err)
	}
	return cm.Data
}

// annotationDeploiement reads the checksum that decides whether the pod rolls.
func annotationDeploiement(t *testing.T, cs *fake.Clientset) string {
	t.Helper()
	d, err := cs.AppsV1().Deployments(nsSite).Get(context.Background(), nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the Deployment is missing: %v", err)
	}
	return d.Spec.Template.Annotations["ceffio.io/page-checksum"]
}

// TestSettingsDeclarentLeContact proves the form the operator sees: one group,
// one optional field, and the SAME address pattern the renderer enforces.
func TestSettingsDeclarentLeContact(t *testing.T) {
	groupes := (&websiteModule{}).Settings()
	if len(groupes) != 1 {
		t.Fatalf("%d settings groups declared, expected 1", len(groupes))
	}
	g := groupes[0]
	if g.ID != groupePage {
		t.Errorf("group ID = %q, expected %q", g.ID, groupePage)
	}
	if g.Title == "" || g.Description == "" {
		t.Error("the group has no title or no description: the console form would be unexplained")
	}
	if len(g.Fields) != 1 {
		t.Fatalf("%d fields declared, expected 1", len(g.Fields))
	}
	f := g.Fields[0]
	if f.Key != cleContact {
		t.Errorf("field key = %q, expected %q", f.Key, cleContact)
	}
	if f.Label == "" || f.Help == "" {
		t.Error("the field has no label or no help: the operator would not know what it does")
	}
	if f.Type != module.Text {
		t.Errorf("field type = %v, expected Text", f.Type)
	}
	if f.Required {
		t.Error("the address must stay optional: an installation without one publishes no address")
	}
	if f.Default != "" {
		t.Errorf("the address has a default (%q): an installation must not publish one it was never given", f.Default)
	}
	// The form and the renderer must agree on what an address looks like, or
	// the console accepts a value the install then refuses.
	if f.Pattern != site.MotifAdresse {
		t.Errorf("the form's pattern is %q, the renderer's is %q: they must be the same", f.Pattern, site.MotifAdresse)
	}
	if !site.AdresseValide(adresseTest) || site.AdresseValide("pas une adresse") {
		t.Error("the shared pattern does not separate a usable address from a sentence")
	}
}

// TestInstallPublieLeContactStocke proves the address set before the module
// exists ends up in the published page: Apply stores it (there is nothing to
// republish yet, which is normal), and the Install that follows reads it.
func TestInstallPublieLeContactStocke(t *testing.T) {
	ctx := context.Background()
	cs := fakeCluster(t)
	store := nouveauMagasin()
	env := testEnv(cs)
	env.Settings = store

	m := &websiteModule{}
	if err := m.Apply(ctx, env, groupePage, module.Values{cleContact: adresseTest}); err != nil {
		t.Fatalf("Apply on an absent module: %v", err)
	}
	if len(store.ecritures) != 1 {
		t.Fatalf("%d writes recorded, expected 1", len(store.ecritures))
	}
	if _, err := cs.CoreV1().ConfigMaps(nsSite).Get(ctx, nomPage, metav1.GetOptions{}); err == nil {
		t.Error("Apply created the published ConfigMap before the module was installed")
	}

	// The Install that follows is the one the runner performs, with the same
	// stores: it must read the address Apply just recorded.
	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	donnees := pagePubliee(t, cs)
	for _, cle := range []string{site.CleIndexFR, site.CleIndexEN} {
		if n := strings.Count(donnees[cle], "mailto:"+adresseTest); n != 2 {
			t.Errorf("%s publishes the configured address %d times, expected 2", cle, n)
		}
	}
	valeurs, err := m.Current(ctx, env, groupePage)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if valeurs[cleContact] != adresseTest {
		t.Errorf("Current = %q, expected the stored %q", valeurs[cleContact], adresseTest)
	}
}

// TestApplyRepublieLaPageEtFaitTournerLePod proves the visible half of a save:
// the ConfigMap changes immediately, the pod template changes with it (that
// annotation is what rolls the pod — nginx has already read the old page), and
// saving the same value twice rolls nothing.
func TestApplyRepublieLaPageEtFaitTournerLePod(t *testing.T) {
	ctx := context.Background()
	cs := fakeCluster(t)
	env := testEnv(cs)
	env.Settings = nouveauMagasin()

	m := &websiteModule{}
	installer(t, cs, m)
	avant := pagePubliee(t, cs)
	if strings.Contains(avant[site.CleIndexFR], "mailto:") {
		t.Fatal("the page publishes an address while none is configured")
	}
	empreinteAvant := annotationDeploiement(t, cs)

	if err := m.Apply(ctx, env, groupePage, module.Values{cleContact: adresseTest}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	avec := pagePubliee(t, cs)
	if !strings.Contains(avec[site.CleIndexFR], "mailto:"+adresseTest) {
		t.Error("the FR page does not publish the address that was just saved")
	}
	if !strings.Contains(avec[site.CleIndexEN], "mailto:"+adresseTest) {
		t.Error("the EN page does not publish the address that was just saved")
	}
	empreinteAvec := annotationDeploiement(t, cs)
	if empreinteAvec == empreinteAvant {
		t.Error("the Deployment did not change: the pod would keep serving the previous page")
	}

	// Saving the same value again must not roll the pod for nothing.
	if err := m.Apply(ctx, env, groupePage, module.Values{cleContact: adresseTest}); err != nil {
		t.Fatalf("Apply (same value): %v", err)
	}
	if got := annotationDeploiement(t, cs); got != empreinteAvec {
		t.Error("re-saving the same address rolled the pod: the checksum changed although the page did not")
	}

	// An empty address is a decision, not a missing value: the page must go
	// back to saying that no address is published.
	if err := m.Apply(ctx, env, groupePage, module.Values{cleContact: ""}); err != nil {
		t.Fatalf("Apply (empty): %v", err)
	}
	sans := pagePubliee(t, cs)
	if strings.Contains(sans[site.CleIndexFR], "mailto:") {
		t.Error("the page still publishes an address after the operator removed it")
	}
	if !strings.Contains(sans[site.CleIndexFR], "Aucune adresse de contact n'est publiée ici") {
		t.Error("the page does not say that no address is published")
	}
	if got := annotationDeploiement(t, cs); got != empreinteAvant {
		t.Error("removing the address did not restore the page the installation started with")
	}
}

// TestApplySansClientStockeSeulement proves a save with no cluster still
// records the decision: a binary run outside a cluster (or a test) must not
// lose the address it was given, and Install reads it later.
func TestApplySansClientStockeSeulement(t *testing.T) {
	store := nouveauMagasin()
	env := module.Env{Domain: domaineTest, ModuleID: "website", Settings: store}
	if err := (&websiteModule{}).Apply(context.Background(), env, groupePage, module.Values{cleContact: adresseTest}); err != nil {
		t.Fatalf("Apply without a Kubernetes client: %v", err)
	}
	if len(store.ecritures) != 1 {
		t.Fatalf("%d writes recorded, expected 1", len(store.ecritures))
	}
}

// TestApplyRefuseEtNEnregistreRien proves the refusals happen BEFORE the write:
// an installation whose store contains a rejected value would fail every
// following install with an error nobody can trace back to its input.
func TestApplyRefuseEtNEnregistreRien(t *testing.T) {
	ctx := context.Background()
	store := nouveauMagasin()
	env := module.Env{Domain: domaineTest, ModuleID: "website", Settings: store, Kube: fakeCluster(t)}

	m := &websiteModule{}
	for _, contact := range []string{"pas une adresse", "a@b", "<script>@example.com"} {
		err := m.Apply(ctx, env, groupePage, module.Values{cleContact: contact})
		if err == nil {
			t.Errorf("Apply accepted %q as a contact address", contact)
		}
	}
	if len(store.ecritures) != 0 {
		t.Errorf("%d writes recorded for refused values, expected none", len(store.ecritures))
	}
	valeurs, err := m.Current(ctx, env, groupePage)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if valeurs[cleContact] != "" {
		t.Errorf("the store contains %q after every save was refused", valeurs[cleContact])
	}

	// The surrounding spaces of a text input are a typo, not part of the
	// address: trimming them is part of accepting the value.
	if err := m.Apply(ctx, env, groupePage, module.Values{cleContact: "  " + adresseTest + "  "}); err != nil {
		t.Fatalf("Apply refused a correctly shaped address surrounded by spaces: %v", err)
	}
	if valeurs, _ = m.Current(ctx, env, groupePage); valeurs[cleContact] != adresseTest {
		t.Errorf("the stored address is %q, expected %q", valeurs[cleContact], adresseTest)
	}
}

// TestApplySansDomaineRefuseAvantDEcrire proves a save that could not become
// visible does not reach the store: "Apply failed" must mean "nothing
// changed", otherwise the store and the public page disagree with no way to
// tell which one the operator meant.
func TestApplySansDomaineRefuseAvantDEcrire(t *testing.T) {
	ctx := context.Background()
	cs := fakeCluster(t)
	store := nouveauMagasin()
	env := testEnv(cs)
	env.Settings = store
	m := &websiteModule{}
	installer(t, cs, m)

	// The console always knows the installation's domain; a hand-run CLI
	// without --domain does not, and the page cannot be re-rendered without it.
	env.Domain = ""
	err := m.Apply(ctx, env, groupePage, module.Values{cleContact: adresseTest})
	if err == nil {
		t.Fatal("Apply accepted an address while the installation's domain is unknown")
	}
	if !strings.Contains(err.Error(), "--domain") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}
	if len(store.ecritures) != 0 {
		t.Errorf("%d writes recorded for a save that was refused, expected none", len(store.ecritures))
	}
}

// TestGroupesInconnusRefuses proves both halves of the contract reject a group
// the module does not declare, instead of silently answering for it.
func TestGroupesInconnusRefuses(t *testing.T) {
	env := module.Env{Domain: domaineTest, ModuleID: "website", Settings: nouveauMagasin()}
	m := &websiteModule{}
	if _, err := m.Current(context.Background(), env, "nope"); err == nil {
		t.Error("Current accepted an undeclared settings group")
	}
	if err := m.Apply(context.Background(), env, "nope", module.Values{}); err == nil {
		t.Error("Apply accepted an undeclared settings group")
	}
}
