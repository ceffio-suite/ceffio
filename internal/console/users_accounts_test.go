// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

// WHY THESE TESTS EXIST
//
// The console is the only place where a platform account and the objects the
// modules own for it are created together. Three failures there are invisible
// in production until it is too late:
//
//  1. A module refusing a creation AFTER Keycloak accepted it leaves a user
//     with no mailbox and no way to finish from the page.
//  2. A write-back that does not happen leaves an internal user with the
//     operator's typed address instead of the one the mailbox answers on.
//  3. A deletion that goes to Keycloak first leaves orphan objects no page can
//     reach.
//
// The tests below pin the ORDER (validation → platform → modules → write-back),
// the WRITE-BACK (address + attributes), the TYPED CONFIRMATIONS, the
// protection of the administration account, and the page's tolerance when a
// module cannot answer. They use a fake Keycloak (httptest), a fake module
// registry and a fake occ executor: none of them needs a cluster.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// ---------------------------------------------------------------------------
// fakes

// moduleFauxComptes is a module that implements module.Accounts and records
// every call in the shared journal, so the tests can assert the ORDER.
type moduleFauxComptes struct {
	id      string
	etat    module.Status
	champs  []module.AccountField
	valider func(module.User, module.Values) error
	assurer func(module.User, module.Values) (module.AccountResult, error)
	infos   func([]module.User) (map[string]module.AccountInfo, error)
	agir    func(module.User, string, module.Values) error
	journal *[]string
}

func (f *moduleFauxComptes) note(quoi string) {
	if f.journal != nil {
		*f.journal = append(*f.journal, f.id+":"+quoi)
	}
}

func (f *moduleFauxComptes) Info() module.Info {
	return module.Info{ID: f.id, Title: strings.ToUpper(f.id), Kind: module.Optional}
}
func (f *moduleFauxComptes) Install(context.Context, module.Env) error   { return nil }
func (f *moduleFauxComptes) Uninstall(context.Context, module.Env) error { return nil }
func (f *moduleFauxComptes) State(context.Context, module.Env) module.State {
	if f.etat == "" {
		return module.State{Status: module.Installed}
	}
	return module.State{Status: f.etat}
}

func (f *moduleFauxComptes) AccountFields(context.Context, module.Env) []module.AccountField {
	return f.champs
}
func (f *moduleFauxComptes) ValidateAccount(_ context.Context, _ module.Env, u module.User, v module.Values) error {
	f.note("validate:" + u.Username)
	if f.valider != nil {
		return f.valider(u, v)
	}
	return nil
}
func (f *moduleFauxComptes) EnsureAccount(_ context.Context, _ module.Env, u module.User, v module.Values) (module.AccountResult, error) {
	f.note("ensure:" + u.Username)
	if f.assurer != nil {
		return f.assurer(u, v)
	}
	return module.AccountResult{}, nil
}
func (f *moduleFauxComptes) AccountInfos(_ context.Context, _ module.Env, users []module.User) (map[string]module.AccountInfo, error) {
	f.note("infos")
	if f.infos != nil {
		return f.infos(users)
	}
	return map[string]module.AccountInfo{}, nil
}
func (f *moduleFauxComptes) AccountAction(_ context.Context, _ module.Env, u module.User, action string, v module.Values) error {
	f.note("action:" + action)
	if f.agir != nil {
		return f.agir(u, action, v)
	}
	return nil
}
func (f *moduleFauxComptes) SuspendAccount(context.Context, module.Env, module.User) error {
	f.note("suspend")
	return nil
}
func (f *moduleFauxComptes) ResumeAccount(context.Context, module.Env, module.User) error {
	f.note("resume")
	return nil
}
func (f *moduleFauxComptes) DeleteAccount(_ context.Context, _ module.Env, u module.User) error {
	f.note("delete:" + u.Username)
	return nil
}

// kcFaux is a Keycloak Admin API just complete enough for the console: token,
// list, read, create, update, delete. It records what was asked, in order.
type kcFaux struct {
	mu       sync.Mutex
	ordre    *[]string
	requetes []string
	corps    []string
	users    map[string]map[string]any
	// cree counts the Keycloak creations: a validation refusal must leave it 0.
	cree int
}

func newKcFaux(t *testing.T) (*kcFaux, *Server) {
	t.Helper()
	kc := &kcFaux{users: map[string]map[string]any{
		"u-admin": {"id": "u-admin", "username": compteAdmin, "enabled": true},
		"u-alice": {"id": "u-alice", "username": "alice", "email": "alice@exemple.test",
			"enabled": true, "attributes": map[string]any{"ceffio_kind": []string{"internal"}}},
	}}
	ts := httptest.NewServer(http.HandlerFunc(kc.servir))
	t.Cleanup(ts.Close)
	// The token cache is global: one test's token must not answer the next.
	kcTokMu.Lock()
	kcToken, kcExpires = "", time.Time{}
	kcTokMu.Unlock()
	return kc, &Server{kcBase: ts.URL, kcAdmin: "admin", kcPass: "secret", Domain: "exemple.test"}
}

func (k *kcFaux) journaliser(quoi string) {
	k.requetes = append(k.requetes, quoi)
	if k.ordre != nil {
		*k.ordre = append(*k.ordre, quoi)
	}
}

func (k *kcFaux) servir(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case r.URL.Path == "/realms/master/protocol/openid-connect/token":
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "jeton", "expires_in": 300})
	case r.URL.Path == "/admin/realms/"+realm+"/users" && r.Method == http.MethodGet:
		nom := r.URL.Query().Get("username")
		var liste []map[string]any
		for _, u := range k.users {
			if nom == "" || strings.EqualFold(u["username"].(string), nom) {
				liste = append(liste, u)
			}
		}
		k.journaliser("keycloak:list")
		_ = json.NewEncoder(w).Encode(liste)
	case r.URL.Path == "/admin/realms/"+realm+"/users" && r.Method == http.MethodPost:
		var corps map[string]any
		_ = json.NewDecoder(r.Body).Decode(&corps)
		nom, _ := corps["username"].(string)
		id := "u-" + nom
		corps["id"] = id
		k.users[id] = corps
		k.cree++
		k.journaliser("keycloak:create:" + nom)
		w.Header().Set("Location", "http://keycloak/admin/realms/"+realm+"/users/"+id)
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(r.URL.Path, "/admin/realms/"+realm+"/users/"):
		id := strings.TrimPrefix(r.URL.Path, "/admin/realms/"+realm+"/users/")
		id, _ = url.PathUnescape(id)
		u, connu := k.users[id]
		if strings.Contains(id, "/") {
			// A sub-resource (reset-password): the console sets a password
			// right after creating the account.
			k.journaliser("keycloak:password")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !connu {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			k.journaliser("keycloak:read:" + id)
			_ = json.NewEncoder(w).Encode(u)
		case http.MethodPut:
			if !connu {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			var corps map[string]any
			_ = json.NewDecoder(r.Body).Decode(&corps)
			corps["id"] = id
			k.users[id] = corps
			k.journaliser("keycloak:update:" + id)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			delete(k.users, id)
			k.journaliser("keycloak:delete:" + id)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// avecModules replaces the registry seam for the duration of the test.
func avecModules(t *testing.T, mods ...module.Module) {
	t.Helper()
	ancien := moduleAll
	moduleAll = func() []module.Module { return mods }
	t.Cleanup(func() { moduleAll = ancien })
}

// avecOcc replaces the Kubernetes exec seam for the duration of the test.
func avecOcc(t *testing.T, journal *[]string) {
	t.Helper()
	ancien := executerOcc
	executerOcc = func(_ *Server, _ context.Context, script string) (string, error) {
		if journal != nil {
			*journal = append(*journal, "occ:"+script)
		}
		return "", nil
	}
	t.Cleanup(func() { executerOcc = ancien })
}

func poster(t *testing.T, s *Server, chemin, corps string, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, chemin, strings.NewReader(corps))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// creation

// TestLaCreationValideTousLesModulesAvantKeycloak pins the first line of the
// contract: a refusal must arrive BEFORE any account exists.
func TestLaCreationValideTousLesModulesAvantKeycloak(t *testing.T) {
	ordre := []string{}
	kc, s := newKcFaux(t)
	kc.ordre = &ordre
	avecOcc(t, &ordre)
	moduleA := &moduleFauxComptes{id: "alpha", journal: &ordre}
	moduleB := &moduleFauxComptes{id: "beta", journal: &ordre,
		valider: func(module.User, module.Values) error { return errFaux("beta refuse") }}
	avecModules(t, moduleA, moduleB)

	rec := poster(t, s, "/api/users", `{"username":"bob","password":"x"}`, s.handleUsers)

	if rec.Code != 400 {
		t.Fatalf("attendu 400 (validation refusée), obtenu %d: %s", rec.Code, rec.Body)
	}
	if kc.cree != 0 {
		t.Fatalf("Keycloak a créé %d compte(s) alors que la validation a échoué — "+
			"l'ordre du contrat §4.6 est inversé: %v", kc.cree, ordre)
	}
	for _, appel := range ordre {
		if strings.Contains(appel, ":ensure:") {
			t.Fatalf("un module a provisionné (%q) avant la validation de tous les autres: %v", appel, ordre)
		}
	}
}

// TestLaCreationSuitLOrdreDuContrat pins the whole sequence, which is the
// paragraph of §4.6 a future refactor is most likely to flatten.
func TestLaCreationSuitLOrdreDuContrat(t *testing.T) {
	ordre := []string{}
	kc, s := newKcFaux(t)
	kc.ordre = &ordre
	avecOcc(t, &ordre)
	m := &moduleFauxComptes{id: "mail", journal: &ordre,
		assurer: func(module.User, module.Values) (module.AccountResult, error) {
			return module.AccountResult{
				Email:      "bob@exemple.test",
				Attributes: map[string]string{"ceffio_kind": "internal"},
			}, nil
		}}
	avecModules(t, m)

	rec := poster(t, s, "/api/users", `{"username":"bob","password":"x","email":"bob@ailleurs.test"}`, s.handleUsers)

	if rec.Code != 201 {
		t.Fatalf("attendu 201, obtenu %d: %s", rec.Code, rec.Body)
	}
	indice := func(motif string) int {
		for i, appel := range ordre {
			if strings.Contains(appel, motif) {
				return i
			}
		}
		t.Fatalf("appel %q absent du journal %v", motif, ordre)
		return -1
	}
	valide := indice("mail:validate")
	cree := indice("keycloak:create")
	assure := indice("mail:ensure")
	maj := indice("keycloak:update")
	if !(valide < cree && cree < assure && assure < maj) {
		t.Fatalf("ordre du contrat §4.6 non respecté (validation → Keycloak → module → écriture): %v", ordre)
	}
	// The address the module assigns is what the platform must carry, not the
	// one typed: otherwise the internal user cannot receive mail at the address
	// Keycloak shows.
	u := kc.users["u-bob"]
	if u["email"] != "bob@exemple.test" {
		t.Fatalf("l'adresse du résultat du module n'a pas été écrite dans Keycloak: %v", u["email"])
	}
	if u["emailVerified"] != true {
		t.Fatalf("l'adresse d'un compte provisionné doit être vérifiée: %v", u["emailVerified"])
	}
	attrs, _ := u["attributes"].(map[string]any)
	if attrs["ceffio_kind"] == nil {
		t.Fatalf("les attributs du résultat n'ont pas été écrits: %v", u["attributes"])
	}
	// And the Nextcloud account carries it too.
	trouve := false
	for _, appel := range ordre {
		if strings.Contains(appel, "user:setting") && strings.Contains(appel, "bob@exemple.test") {
			trouve = true
		}
	}
	if !trouve {
		t.Fatalf("l'adresse n'a pas été posée sur le compte Nextcloud: %v", ordre)
	}
}

// TestLeChampQuiRemplaceLEmailLeMasque verifies that an internal mailbox
// replaces the typed address: a module that computes it must not receive one.
func TestLeChampQuiRemplaceLEmailLeMasque(t *testing.T) {
	ordre := []string{}
	kc, s := newKcFaux(t)
	avecOcc(t, &ordre)
	var vu module.User
	m := &moduleFauxComptes{id: "mail", journal: &ordre,
		champs: []module.AccountField{{Field: module.Field{Key: "boite", Type: module.Bool, Default: "true"}, ReplacesEmail: true}},
		valider: func(u module.User, _ module.Values) error {
			vu = u
			return nil
		}}
	avecModules(t, m)

	rec := poster(t, s, "/api/users", `{"username":"bob","email":"bob@ailleurs.test","password":"x"}`, s.handleUsers)

	if rec.Code != 201 {
		t.Fatalf("attendu 201, obtenu %d: %s", rec.Code, rec.Body)
	}
	if vu.Email != "" {
		t.Fatalf("le module a reçu l'adresse %q alors que son champ la remplace", vu.Email)
	}
	if _, present := kc.users["u-bob"]["email"]; present {
		t.Fatalf("Keycloak a été créé avec une adresse alors que le module la remplace: %v", kc.users["u-bob"])
	}
}

// TestUnChampInconnuEstRefuse: a typo must be said, not silently dropped.
func TestUnChampInconnuEstRefuse(t *testing.T) {
	ordre := []string{}
	_, s := newKcFaux(t)
	avecOcc(t, &ordre)
	m := &moduleFauxComptes{id: "mail", journal: &ordre,
		champs: []module.AccountField{{Field: module.Field{Key: "quota_gio", Type: module.Number}}}}
	avecModules(t, m)

	rec := poster(t, s, "/api/users",
		`{"username":"bob","modules":{"mail":{"quota_gb":"5"}}}`, s.handleUsers)

	if rec.Code != 400 {
		t.Fatalf("attendu 400 pour un champ inconnu, obtenu %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "quota_gb") {
		t.Fatalf("le message doit nommer le champ refusé: %s", rec.Body)
	}
}

// TestUnModuleInconnuEstRefuse: the page must not invent a module.
func TestUnModuleInconnuEstRefuse(t *testing.T) {
	ordre := []string{}
	_, s := newKcFaux(t)
	avecOcc(t, &ordre)
	avecModules(t, &moduleFauxComptes{id: "mail", journal: &ordre})

	rec := poster(t, s, "/api/users",
		`{"username":"bob","modules":{"inexistant":{"x":"1"}}}`, s.handleUsers)

	if rec.Code != 400 {
		t.Fatalf("attendu 400 pour un module inconnu, obtenu %d: %s", rec.Code, rec.Body)
	}
}

// TestUneNouvelleTentativeAcheveLaCreation: the retry after a partial failure
// must converge on the same account instead of failing on a conflict.
func TestUneNouvelleTentativeAcheveLaCreation(t *testing.T) {
	ordre := []string{}
	kc, s := newKcFaux(t)
	avecOcc(t, &ordre)
	avecModules(t, &moduleFauxComptes{id: "mail", journal: &ordre})

	// The account already exists (a previous attempt created it, then failed).
	kc.users["u-bob"] = map[string]any{"id": "u-bob", "username": "bob", "enabled": true}

	rec := poster(t, s, "/api/users", `{"username":"bob","password":"x"}`, s.handleUsers)

	if rec.Code != 201 {
		t.Fatalf("une nouvelle tentative doit aboutir, obtenu %d: %s", rec.Code, rec.Body)
	}
	if kc.users["u-bob"] == nil {
		t.Fatal("le compte existant a été perdu")
	}
}

// ---------------------------------------------------------------------------
// page

// TestLaPageRendLesChampsDesModulesInstalles: the page is served what the
// installed modules declare, and nothing for the others.
func TestLaPageRendLesChampsDesModulesInstalles(t *testing.T) {
	ordre := []string{}
	_, s := newKcFaux(t)
	avecOcc(t, &ordre)
	installe := &moduleFauxComptes{id: "mail", journal: &ordre,
		champs: []module.AccountField{{Field: module.Field{Key: "boite", Type: module.Bool, Default: "true"}, ReplacesEmail: true}},
		infos: func(users []module.User) (map[string]module.AccountInfo, error) {
			return map[string]module.AccountInfo{
				"u-alice": {Present: true, Summary: "boîte alice@exemple.test"},
			}, nil
		}}
	absent := &moduleFauxComptes{id: "absent", journal: &ordre, etat: module.Absent}
	avecModules(t, installe, absent)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rec := httptest.NewRecorder()
	s.handleUsers(rec, req)

	if rec.Code != 200 {
		t.Fatalf("attendu 200, obtenu %d: %s", rec.Code, rec.Body)
	}
	var reponse struct {
		Users    []KCUser                                 `json:"users"`
		Fields   map[string][]module.AccountField         `json:"fields"`
		Accounts map[string]map[string]module.AccountInfo `json:"accounts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reponse); err != nil {
		t.Fatalf("réponse illisible: %v (%s)", err, rec.Body)
	}
	if len(reponse.Fields["mail"]) != 1 || reponse.Fields["mail"][0].Key != "boite" {
		t.Fatalf("les champs du module installé manquent: %v", reponse.Fields)
	}
	if !reponse.Fields["mail"][0].ReplacesEmail {
		t.Fatal("replaces_email doit être transmis: la page en a besoin pour masquer le champ adresse")
	}
	if _, ok := reponse.Fields["absent"]; ok {
		t.Fatalf("un module non installé expose des champs: %v", reponse.Fields)
	}
	if !reponse.Accounts["mail"]["u-alice"].Present {
		t.Fatalf("l'état du compte n'est pas transmis: %v", reponse.Accounts)
	}
}

// TestUneErreurDeCompteNeCassePasLaPage: one module down must not hide the
// user list (the page's primary data).
func TestUneErreurDeCompteNeCassePasLaPage(t *testing.T) {
	ordre := []string{}
	_, s := newKcFaux(t)
	avecOcc(t, &ordre)
	casse := &moduleFauxComptes{id: "mail", journal: &ordre,
		infos: func([]module.User) (map[string]module.AccountInfo, error) {
			return nil, errFaux("JMAP injoignable")
		}}
	avecModules(t, casse)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rec := httptest.NewRecorder()
	s.handleUsers(rec, req)

	if rec.Code != 200 {
		t.Fatalf("la liste des utilisateurs doit rester servie, obtenu %d: %s", rec.Code, rec.Body)
	}
	var reponse struct {
		Users  []KCUser          `json:"users"`
		Errors map[string]string `json:"account_errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &reponse)
	if len(reponse.Users) == 0 {
		t.Fatal("aucun utilisateur renvoyé alors que seule une colonne a échoué")
	}
	if !strings.Contains(reponse.Errors["mail"], "JMAP") {
		t.Fatalf("l'erreur du module doit être remontée: %v", reponse.Errors)
	}
}

// ---------------------------------------------------------------------------
// lifecycle

// TestLaDesactivationSuspendLesModules: a deactivated user's mailbox must stop
// answering, and the order is Keycloak then modules.
func TestLaDesactivationSuspendLesModules(t *testing.T) {
	ordre := []string{}
	kc, s := newKcFaux(t)
	kc.ordre = &ordre
	avecOcc(t, &ordre)
	m := &moduleFauxComptes{id: "mail", journal: &ordre}
	avecModules(t, m)

	rec := poster(t, s, "/api/users/u-alice/deactivate", `{}`, s.handleUsersByID)

	if rec.Code != 200 {
		t.Fatalf("attendu 200, obtenu %d: %s", rec.Code, rec.Body)
	}
	if kc.users["u-alice"]["enabled"] != false {
		t.Fatalf("le compte Keycloak n'est pas désactivé: %v", kc.users["u-alice"])
	}
	joint := strings.Join(ordre, " ")
	if !strings.Contains(joint, "mail:suspend") {
		t.Fatalf("le module n'a pas suspendu son compte: %v", ordre)
	}
	if !strings.Contains(joint, "occ:php occ user:disable") {
		t.Fatalf("le compte Nextcloud n'a pas été désactivé: %v", ordre)
	}
}

// TestLaSuppressionExigeLeNomTape pins the typed confirmation and the order
// modules → Nextcloud → Keycloak.
func TestLaSuppressionExigeLeNomTape(t *testing.T) {
	ordre := []string{}
	kc, s := newKcFaux(t)
	kc.ordre = &ordre
	avecOcc(t, &ordre)
	m := &moduleFauxComptes{id: "mail", journal: &ordre}
	avecModules(t, m)

	// 1. A wrong confirmation changes NOTHING.
	rec := poster(t, s, "/api/users/u-alice/delete", `{"confirm":"bob"}`, s.handleUsersByID)
	if rec.Code != 400 {
		t.Fatalf("une confirmation erronée doit être refusée, obtenu %d: %s", rec.Code, rec.Body)
	}
	// Only reads were allowed to happen for the confirmation check: nothing
	// that removes anything may have run.
	for _, appel := range ordre {
		if strings.Contains(appel, ":delete") || strings.Contains(appel, "user:delete") {
			t.Fatalf("une confirmation erronée a lancé une suppression: %v", ordre)
		}
	}

	// 2. The right one removes the module objects BEFORE the platform account.
	rec = poster(t, s, "/api/users/u-alice/delete", `{"confirm":"alice"}`, s.handleUsersByID)
	if rec.Code != 200 {
		t.Fatalf("attendu 200, obtenu %d: %s", rec.Code, rec.Body)
	}
	indice := func(motif string) int {
		for i, appel := range ordre {
			if strings.Contains(appel, motif) {
				return i
			}
		}
		t.Fatalf("appel %q absent: %v", motif, ordre)
		return -1
	}
	if !(indice("mail:delete") < indice("occ:php occ user:delete") && indice("occ:php occ user:delete") < indice("keycloak:delete")) {
		t.Fatalf("ordre de suppression incorrect (modules → Nextcloud → Keycloak): %v", ordre)
	}
	if kc.users["u-alice"] != nil {
		t.Fatal("le compte Keycloak existe encore après la suppression")
	}
}

// TestLaSuppressionRefuseLeCompteAdministrateur: protection must be a SERVER
// rule, not a hidden button on the page.
func TestLaSuppressionRefuseLeCompteAdministrateur(t *testing.T) {
	ordre := []string{}
	_, s := newKcFaux(t)
	avecOcc(t, &ordre)
	avecModules(t, &moduleFauxComptes{id: "mail", journal: &ordre})

	rec := poster(t, s, "/api/users/u-admin/delete", `{"confirm":"adminceffio"}`, s.handleUsersByID)

	if rec.Code != 403 {
		t.Fatalf("attendu 403 pour le compte d'administration, obtenu %d: %s", rec.Code, rec.Body)
	}
	if len(ordre) != 0 {
		t.Fatalf("le compte d'administration a été touché: %v", ordre)
	}
}

// TestUneActionInconnueEstRefusee: the action must come from the module's own
// declaration for this user, otherwise the page and the module disagree.
func TestUneActionInconnueEstRefusee(t *testing.T) {
	ordre := []string{}
	_, s := newKcFaux(t)
	avecOcc(t, &ordre)
	m := &moduleFauxComptes{id: "mail", journal: &ordre,
		infos: func([]module.User) (map[string]module.AccountInfo, error) {
			return map[string]module.AccountInfo{"u-alice": {Present: true,
				Actions: []module.AccountAction{{ID: "suspend", Label: "Suspendre", Confirm: "alice"}}}}, nil
		}}
	avecModules(t, m)

	rec := poster(t, s, "/api/users/u-alice/accounts/mail/efface-tout", `{"confirm":"alice"}`, s.handleUsersByID)

	if rec.Code != 404 {
		t.Fatalf("attendu 404 pour une action non déclarée, obtenu %d: %s", rec.Code, rec.Body)
	}
	for _, appel := range ordre {
		if strings.Contains(appel, "action:") {
			t.Fatalf("une action non déclarée a été transmise au module: %v", ordre)
		}
	}
}

// TestUneActionDeModuleExigeSaConfirmation: the module says what to type, the
// server enforces it.
func TestUneActionDeModuleExigeSaConfirmation(t *testing.T) {
	ordre := []string{}
	_, s := newKcFaux(t)
	avecOcc(t, &ordre)
	m := &moduleFauxComptes{id: "mail", journal: &ordre,
		infos: func([]module.User) (map[string]module.AccountInfo, error) {
			return map[string]module.AccountInfo{"u-alice": {Present: true,
				Actions: []module.AccountAction{{ID: "delete-mailbox", Label: "Supprimer", Confirm: "alice"}}}}, nil
		}}
	avecModules(t, m)

	rec := poster(t, s, "/api/users/u-alice/accounts/mail/delete-mailbox",
		`{"confirm":"alice" }`, s.handleUsersByID)
	if rec.Code != 200 {
		t.Fatalf("la confirmation correcte doit être acceptée, obtenu %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(strings.Join(ordre, " "), "mail:action:delete-mailbox") {
		t.Fatalf("l'action n'a pas été transmise: %v", ordre)
	}
}

// errFaux is a plain error for the fakes (avoids importing errors twice).
type errFaux string

func (e errFaux) Error() string { return string(e) }
