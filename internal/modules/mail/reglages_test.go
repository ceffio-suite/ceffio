// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the mail module's settings: the form as it is declared, the refusals
// that happen before anything is written, and the two writes that must not
// destroy each other.
//
// WHY THEY EXIST: these values are what `ceffio mail deploy`, `ceffio install`
// and the console all apply, and they are stored in one ConfigMap key read by
// three paths. The failure modes are not theoretical: a relay saved without its
// Test leaves outbound mail on a route that bounces, and re-applying the send
// mode used to overwrite the volume size and the exposure choice because the
// whole group was rewritten from its defaults.
package mail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/module"
)

// magasinTest is the settings ConfigMap in memory: enough to prove what a save
// writes, and what it does NOT write when it refuses.
type magasinTest struct {
	donnees   map[string]string
	ecritures []map[string]string
}

func nouveauMagasin(donnees map[string]string) *magasinTest {
	if donnees == nil {
		donnees = map[string]string{}
	}
	return &magasinTest{donnees: donnees}
}

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

// environnement builds an Env with that store and nothing else.
func environnement(store module.ConfigMapStore) module.Env {
	return module.Env{Settings: store}
}

// neutraliserLesAppels makes the two external decisions deterministic: the
// volume size the cluster reports, and whether the relay answers.
func neutraliserLesAppels(t *testing.T, taille int, present bool, relaisRepond bool) {
	t.Helper()
	ancienTaille, ancienRelais := tailleVolume, verifierRelaisSMTP
	tailleVolume = func(context.Context) (int, bool, error) {
		return taille, present, nil
	}
	verifierRelaisSMTP = func(string, int, string, string) (bool, string) {
		if relaisRepond {
			return true, "authenticated as the relay user"
		}
		return false, "cannot reach the relay: connection refused"
	}
	t.Cleanup(func() { tailleVolume, verifierRelaisSMTP = ancienTaille, ancienRelais })
}

// TestLesGroupesDeclares: the two groups and their defaults are the plan's
// §4.2 table. A changed default is a behaviour change on every fresh install,
// so it is fixed here rather than discovered in the field.
func TestLesGroupesDeclares(t *testing.T) {
	groupes := (&mailModule{}).Settings()
	if len(groupes) != 2 {
		t.Fatalf("%d groups declared, want the relay and server groups", len(groupes))
	}
	attendu := map[string]map[string]string{
		"relay": {
			"hote": "", "port": "587", "utilisateur": "", "mot_de_passe": "", "exiger_tls": "true",
		},
		"server": {
			"envoi": "direct", "volume_gio": "20", "quota_defaut_gio": "1", "clients_externes": "true",
		},
	}
	for _, groupe := range groupes {
		voulus, ok := attendu[groupe.ID]
		if !ok {
			t.Errorf("unexpected group %q", groupe.ID)
			continue
		}
		for _, champ := range groupe.Fields {
			defaut, connu := voulus[champ.Key]
			if !connu {
				t.Errorf("%s: unexpected field %q", groupe.ID, champ.Key)
				continue
			}
			if champ.Default != defaut {
				t.Errorf("%s.%s default = %q, want %q", groupe.ID, champ.Key, champ.Default, defaut)
			}
		}
		if len(groupe.Fields) != len(voulus) {
			t.Errorf("%s declares %d fields, want %d", groupe.ID, len(groupe.Fields), len(voulus))
		}
	}

	// The send mode is a choice, not free text: anything else would be stored
	// and then refused at apply time, after the operator saw a green page.
	for _, groupe := range groupes {
		for _, champ := range groupe.Fields {
			if champ.Key == "envoi" && (champ.Type != module.Choice || len(champ.Options) != 2) {
				t.Errorf("envoi is not a two-option choice: type %v, %d options", champ.Type, len(champ.Options))
			}
		}
	}
}

// TestApplyRefuseUnGroupeInconnu: a group that does not exist is an error, not a
// silent success that stores nothing.
func TestApplyRefuseUnGroupeInconnu(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)

	err := m.Apply(context.Background(), environnement(store), "inconnu", module.Values{})
	if !errors.Is(err, module.ErrUnknownGroup) {
		t.Fatalf("Apply(inconnu) = %v, want ErrUnknownGroup", err)
	}
	if len(store.ecritures) != 0 {
		t.Errorf("an unknown group wrote to the store: %v", store.ecritures)
	}
}

// TestApplyRefuseUnRelaisIncomplet: the host and the username are required by the
// form itself, so the refusal happens before the vault and before the server.
func TestApplyRefuseUnRelaisIncomplet(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)

	err := m.Apply(context.Background(), environnement(store), "relay",
		module.Values{"hote": "", "port": "587", "utilisateur": "quelqu'un"})
	if !errors.Is(err, module.ErrInvalidSettings) {
		t.Fatalf("Apply(relay incomplete) = %v, want ErrInvalidSettings", err)
	}
	if len(store.ecritures) != 0 {
		t.Errorf("an incomplete relay wrote to the store: %v", store.ecritures)
	}
}

// TestApplyRefuseUnQuotaPlusGrandQueLeVolume: the coherence rule of §4.2, which a
// per-field form cannot express. The refusal must come before the store is
// touched, or a refused value would be the stored one anyway.
func TestApplyRefuseUnQuotaPlusGrandQueLeVolume(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)

	err := m.Apply(context.Background(), environnement(store), "server", module.Values{
		"envoi": "direct", "volume_gio": "10", "quota_defaut_gio": "20", "clients_externes": "true",
	})
	if !errors.Is(err, module.ErrInvalidSettings) {
		t.Fatalf("Apply(quota > volume) = %v, want ErrInvalidSettings", err)
	}
	if !strings.Contains(err.Error(), "cannot exceed the volume") {
		t.Errorf("the error does not explain the rule: %v", err)
	}
	if len(store.ecritures) != 0 {
		t.Errorf("a refused value was written to the store: %v", store.ecritures)
	}
}

// TestApplyRefuseUnVolumeNonEntier: the number fields are text in the form; a
// typo is refused with a message naming the field, not parsed as zero.
func TestApplyRefuseUnVolumeNonEntier(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)

	err := m.Apply(context.Background(), environnement(store), "server", module.Values{
		"envoi": "direct", "volume_gio": "20 Go", "quota_defaut_gio": "1",
	})
	if !errors.Is(err, module.ErrInvalidSettings) {
		t.Fatalf("Apply(volume_gio=20 Go) = %v, want ErrInvalidSettings", err)
	}
	if len(store.ecritures) != 0 {
		t.Errorf("a refused value was written to the store: %v", store.ecritures)
	}
}

// TestApplyRefuseLeModeRelaisSansRelaisConfigure: choosing the relay as send mode
// while the relay group is empty is refused — otherwise every message would be
// handed to a host that does not exist.
func TestApplyRefuseLeModeRelaisSansRelaisConfigure(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)
	neutraliserLesAppels(t, 20, true, true)

	err := m.Apply(context.Background(), environnement(store), "server", module.Values{
		"envoi": "relais", "volume_gio": "20", "quota_defaut_gio": "1", "clients_externes": "true",
	})
	if !errors.Is(err, module.ErrInvalidSettings) {
		t.Fatalf("Apply(envoi=relais, no relay) = %v, want ErrInvalidSettings", err)
	}
	if len(store.ecritures) != 0 {
		t.Errorf("a relay mode without a relay was written to the store: %v", store.ecritures)
	}
}

// TestApplyRefuseUnRelaisQuiNeRepondPas: "its Test must pass" is checked when the
// value is SAVED, not when the first message bounces.
func TestApplyRefuseUnRelaisQuiNeRepondPas(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(map[string]string{
		"mail.relay": `{"hote":"smtp.example.com","port":"587","utilisateur":"ceffio","exiger_tls":"true"}`,
	})
	neutraliserLesAppels(t, 20, true, false)

	err := m.Apply(context.Background(), environnement(store), "server", module.Values{
		"envoi": "relais", "volume_gio": "20", "quota_defaut_gio": "1", "clients_externes": "true",
	})
	if !errors.Is(err, module.ErrInvalidSettings) {
		t.Fatalf("Apply(relay down) = %v, want ErrInvalidSettings", err)
	}
	if !strings.Contains(err.Error(), "refuses the connection") {
		t.Errorf("the error does not say the relay was contacted: %v", err)
	}
	if len(store.ecritures) != 0 {
		t.Errorf("a relay that does not answer was written to the store: %v", store.ecritures)
	}
}

// TestStockerRelaisEcritLesChampsOrdinaires: the ordinary values go to the shared
// store under their own key, with the password KEPT OUT of it.
func TestStockerRelaisEcritLesChampsOrdinaires(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)

	err := m.stockerRelais(context.Background(), environnement(store), module.Values{
		"hote": "smtp.example.com", "port": "", "utilisateur": "ceffio",
		"mot_de_passe": module.SecretSet, "exiger_tls": "",
	})
	if err != nil {
		t.Fatalf("stockerRelais() = %v", err)
	}

	brut := store.donnees[mail.CleRelais]
	if brut == "" {
		t.Fatal("the relay was not stored")
	}
	stoc := map[string]string{}
	if err := json.Unmarshal([]byte(brut), &stoc); err != nil {
		t.Fatalf("the stored relay is not a map of strings: %v", err)
	}
	if stoc["hote"] != "smtp.example.com" || stoc["utilisateur"] != "ceffio" {
		t.Errorf("the stored relay lost its coordinates: %v", stoc)
	}
	// Empty fields fall back to the values the deployment always used.
	if stoc["port"] != "587" || stoc["exiger_tls"] != "true" {
		t.Errorf("the empty fields did not fall back to their defaults: %v", stoc)
	}
	for _, cle := range []string{"mot_de_passe", "motdepasse", "password"} {
		if _, present := stoc[cle]; present {
			t.Errorf("the password was written to the ConfigMap under %q", cle)
		}
	}
}

// TestForcerModeEnvoiConserveLesAutresReglages: switching the send mode is a
// one-key change. Rewriting the whole group from its defaults would silently
// reset the volume size and the exposure choice of an operator who had set them.
func TestForcerModeEnvoiConserveLesAutresReglages(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(map[string]string{
		mail.CleServeur: `{"envoi":"direct","volume_gio":30,"quota_defaut_gio":2,"clients_externes":false}`,
	})

	if err := m.forcerModeEnvoi(context.Background(), environnement(store), mail.ModeRelais); err != nil {
		t.Fatalf("forcerModeEnvoi() = %v", err)
	}

	relu, present, err := mail.LireServeur(store.donnees[mail.CleServeur])
	if err != nil || !present {
		t.Fatalf("the stored server entry is unreadable: %v (present %v)", err, present)
	}
	if relu.Envoi.Mode != mail.ModeRelais {
		t.Errorf("send mode = %q, want %q", relu.Envoi.Mode, mail.ModeRelais)
	}
	if relu.VolumeGio != 30 {
		t.Errorf("volume_gio = %d, want the operator's 30", relu.VolumeGio)
	}
	if relu.QuotaDefautGio != 2 {
		t.Errorf("quota_defaut_gio = %d, want the operator's 2", relu.QuotaDefautGio)
	}
	if relu.ClientsExternes {
		t.Error("clients_externes was reset to true: the exposure choice was lost")
	}
}

// TestForcerModeEnvoiSansMagasin: an installation path that has no store must not
// panic on a nil interface.
func TestForcerModeEnvoiSansMagasin(t *testing.T) {
	m := &mailModule{}
	if err := m.forcerModeEnvoi(context.Background(), module.Env{}, mail.ModeRelais); err != nil {
		t.Fatalf("forcerModeEnvoi(nil store) = %v", err)
	}
}

// TestCurrentServeurRapporteLaTailleEnPlace: the form must show the size that is
// actually in effect. Showing the stored request over a larger claim would invite
// the operator to "reduce" it to a value Kubernetes refuses.
func TestCurrentServeurRapporteLaTailleEnPlace(t *testing.T) {
	cas := []struct {
		nom     string
		stocke  string
		taille  int
		present bool
		voulu   string
	}{
		{"rien de stocké", "", 20, true, "20"},
		{"stocké plus petit que le claim", `{"envoi":"direct","volume_gio":20,"quota_defaut_gio":1,"clients_externes":true}`, 30, true, "30"},
		{"stocké plus grand que le claim", `{"envoi":"direct","volume_gio":40,"quota_defaut_gio":1,"clients_externes":true}`, 30, true, "40"},
		{"aucun claim", "", 0, false, "20"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			m := &mailModule{}
			store := nouveauMagasin(map[string]string{})
			if c.stocke != "" {
				store.donnees[mail.CleServeur] = c.stocke
			}
			neutraliserLesAppels(t, c.taille, c.present, true)

			values, err := m.Current(context.Background(), environnement(store), "server")
			if err != nil {
				t.Fatalf("Current(server) = %v", err)
			}
			if values["volume_gio"] != c.voulu {
				t.Errorf("volume_gio = %q, want %q", values["volume_gio"], c.voulu)
			}
		})
	}
}

// TestCurrentRefuseUnGroupeInconnu: same contract as Apply.
func TestCurrentRefuseUnGroupeInconnu(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)
	if _, err := m.Current(context.Background(), environnement(store), "inconnu"); !errors.Is(err, module.ErrUnknownGroup) {
		t.Fatalf("Current(inconnu) = %v, want ErrUnknownGroup", err)
	}
}

// TestTesterServeurRefuseUnQuotaIncoherentSansCluster: the incoherence is answered
// without dialling the cluster — this is what makes the check usable from the
// console, which has no kubectl and no cluster-admin.
func TestTesterServeurRefuseUnQuotaIncoherentSansCluster(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)

	var appeleVolume bool
	ancien := tailleVolume
	tailleVolume = func(context.Context) (int, bool, error) {
		appeleVolume = true
		return 20, true, nil
	}
	t.Cleanup(func() { tailleVolume = ancien })

	resultat := m.Test(context.Background(), environnement(store), "server", module.Values{
		"envoi": "direct", "volume_gio": "10", "quota_defaut_gio": "20", "clients_externes": "true",
	})
	if resultat.OK {
		t.Fatal("Test() accepted a quota larger than the volume")
	}
	if !strings.Contains(resultat.Detail, "cannot exceed the volume") {
		t.Errorf("the detail does not explain the rule: %s", resultat.Detail)
	}
	if appeleVolume {
		t.Error("the cluster was read before the values were checked for coherence")
	}
}

// TestTesterServeurRefuseUneReduction: the volume in place decides whether the
// asked size is reachable, and the answer names the size in effect.
func TestTesterServeurRefuseUneReduction(t *testing.T) {
	m := &mailModule{}
	store := nouveauMagasin(nil)
	neutraliserLesAppels(t, 30, true, true)

	resultat := m.Test(context.Background(), environnement(store), "server", module.Values{
		"envoi": "direct", "volume_gio": "10", "quota_defaut_gio": "1", "clients_externes": "true",
	})
	if resultat.OK {
		t.Fatal("Test() accepted a volume smaller than the claim in place")
	}
	if !strings.Contains(resultat.Detail, "cannot shrink") || !strings.Contains(resultat.Detail, "30") {
		t.Errorf("the detail does not explain the reduction: %s", resultat.Detail)
	}
}

// TestTesterServeurDitCeQuiSeraPublie: the Test answers the exposure question too,
// because it is the value most likely to be saved without being understood —
// publishing IMAP and SMTPS is what lets a phone reach a mailbox.
func TestTesterServeurDitCeQuiSeraPublie(t *testing.T) {
	cas := map[string]struct {
		clients string
		attendu string
	}{
		"publiés": {"true", "465, 993"},
		"fermés":  {"false", "25, 8080"},
	}
	for nom, c := range cas {
		t.Run(nom, func(t *testing.T) {
			m := &mailModule{}
			store := nouveauMagasin(nil)
			neutraliserLesAppels(t, 0, false, true)

			resultat := m.Test(context.Background(), environnement(store), "server", module.Values{
				"envoi": "direct", "volume_gio": "20", "quota_defaut_gio": "1",
				"clients_externes": c.clients,
			})
			if !resultat.OK {
				t.Fatalf("Test() = %+v, want OK", resultat)
			}
			if !strings.Contains(resultat.Detail, c.attendu) {
				t.Errorf("the detail does not say what is published (%q): %s", c.attendu, resultat.Detail)
			}
		})
	}
}
