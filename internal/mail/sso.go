// Configuration de l'authentification unique de Stalwart (SSO Keycloak).
//
// POURQUOI CE FICHIER EXISTE : tout ce qui suit a été établi à la main, sur un
// serveur en service, en cherchant pourquoi l'interface d'administration
// refusait l'accès. Chaque réglage correspond à un échec réel, souvent
// silencieux. Les reproduire ici évite de refaire la même chasse.
//
// LA PANNE QUI A COÛTÉ LE PLUS : l'objet Authentication de Stalwart avait ses
// quatre tables de rôles VIDES. Ces tables sont ce qui traduit un rôle
// (User/Admin) en permissions effectives. Vides, tout compte authentifié par
// l'annuaire externe reçoit zéro permission — donc pas « authenticate » — et
// l'interface répond « 403 Forbidden » après une connexion pourtant réussie.
// Le jeton était valide, le compte résolu, le rôle correct : seule la
// correspondance rôle → permissions manquait.
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// compteGestion est l'identifiant du compte d'administration interne de
// Stalwart, celui que porte STALWART_RECOVERY_ADMIN. Il contourne l'annuaire :
// c'est ce qui permet de configurer le serveur même quand l'OIDC est cassé.
const compteGestion = "d333333"

// rôlesParDéfaut décrit, pour chaque table de l'objet Authentication, les rôles
// qu'elle doit référencer.
//
// POURQUOI PAR LIBELLÉ ET NON PAR IDENTIFIANT : les identifiants courts (« b »,
// « e »…) ne sont pas garantis stables d'une version ou d'une installation à
// l'autre. Le libellé, lui, est stable. On lit donc les rôles réellement
// présents et on les apparie sur leur description.
//
// POURQUOI L'ADMIN PORTE AUSSI « User » : c'est la composition du défaut
// d'usine de Stalwart. Un administrateur est d'abord un utilisateur — il doit
// conserver l'accès aux services ordinaires (boîte, envoi). Ne référencer que
// le rôle d'administration le prive de ces permissions.
var rôlesParDéfaut = []struct {
	champ        string
	descriptions []string
}{
	{"defaultUserRoleIds", []string{"User"}},
	{"defaultGroupRoleIds", []string{"Group"}},
	{"defaultTenantRoleIds", []string{"Tenant Administrator", "User"}},
	{"defaultAdminRoleIds", []string{"System Administrator", "User"}},
}

// SSO décrit l'authentification unique à mettre en place.
type SSO struct {
	Hote         string // hôte public, ex. « mail.ceffio.mandem-it.com »
	Issuer       string // URL du realm, ex. « https://keycloak.…/realms/ceffio »
	ClientID     string // client OIDC du WebUI, ex. « stalwart-webui »
	DomaineAdmin string // domaine des comptes d'admin, HORS messagerie, ex. « ceffio.local »
	CompteAdmin  string // nom du compte d'administration, ex. « adminceffio »
}

// ConfigurerSSO applique l'authentification déléguée à Stalwart.
//
// Idempotent : chaque objet est créé s'il manque, mis à jour sinon. Rejouer la
// fonction sur une installation déjà configurée ne casse rien.
func ConfigurerSSO(ctx context.Context, domaineMessagerie string, o SSO) error {
	if o.Issuer == "" || o.ClientID == "" || o.DomaineAdmin == "" || o.CompteAdmin == "" {
		return fmt.Errorf("SSO incomplet : issuer, clientID, domaineAdmin et compteAdmin sont requis")
	}
	fmt.Println("∙ authentification unique (Keycloak)")

	// --- 1. l'annuaire OIDC -------------------------------------------------
	// Il doit exister AVANT les domaines : chacun le référence.
	idAnnuaire, err := assurerAnnuaireOIDC(ctx, o)
	if err != nil {
		return err
	}

	// --- 2. les domaines ---------------------------------------------------
	// Le domaine de messagerie reçoit le courrier ; le domaine d'administration
	// n'en reçoit pas. Les séparer évite que le compte d'admin soit une adresse
	// de courrier ordinaire — il n'a pas à être joignable depuis l'extérieur.
	//
	// CHAQUE DOMAINE PORTE SON PROPRE directoryId, en plus du réglage global :
	// c'est par lui que Stalwart sait quel annuaire interroger pour un domaine
	// donné. Resté vide, le compte n'est jamais résolu (discussion
	// stalwartlabs/stalwart#3049).
	idMessagerie, err := assurerDomaine(ctx, domaineMessagerie, idAnnuaire)
	if err != nil {
		return err
	}
	idAdmin, err := assurerDomaine(ctx, o.DomaineAdmin, idAnnuaire)
	if err != nil {
		return err
	}

	// --- 3. les rôles : c'est ICI que se jouait le 403 ---------------------
	if err := assurerRoles(ctx); err != nil {
		return err
	}

	// --- 4. l'annuaire actif ------------------------------------------------
	// Sans ce réglage, Stalwart continue d'utiliser son annuaire interne.
	if err := majJMAP(ctx, "x:Authentication/set", map[string]any{
		"update": map[string]any{"singleton": map[string]any{"directoryId": idAnnuaire}},
	}); err != nil {
		return fmt.Errorf("annuaire actif : %w", err)
	}

	// --- 5. domaine par défaut ---------------------------------------------
	// Le WebUI interroge l'API SANS nom d'utilisateur. Stalwart retombe alors
	// sur le domaine par défaut pour savoir quel annuaire consulter. S'il vaut
	// le domaine intégré (sans annuaire), le compte n'est jamais résolu.
	// defaultHostname est obligatoire dès qu'on écrit dans cet objet.
	if err := majJMAP(ctx, "x:SystemSettings/set", map[string]any{
		"update": map[string]any{"singleton": map[string]any{
			"defaultHostname": o.Hote,
			"defaultDomainId": idMessagerie,
		}},
	}); err != nil {
		return fmt.Errorf("domaine par défaut : %w", err)
	}

	// --- 6. le compte d'administration -------------------------------------
	// OIDC ne provisionne RIEN : un compte absent de Stalwart est inconnu du
	// serveur, et le courrier qui lui est adressé est refusé.
	if err := assurerCompteAdmin(ctx, o.CompteAdmin, idAdmin); err != nil {
		return err
	}

	// --- 7. le client OIDC du WebUI ----------------------------------------
	// Sans oauthClientId, la page /admin n'annonce aucun client et n'affiche
	// que son formulaire interne : pas de bouton SSO.
	if err := assurerClientWebUI(ctx, o.ClientID); err != nil {
		return err
	}

	// --- 8. redémarrage : OBLIGATOIRE --------------------------------------
	// Les annuaires et les tables de rôles sont lus UNE FOIS au démarrage dans
	// un instantané mémoire. Écrire la configuration ne suffit pas : sans
	// redémarrage, /api/discover renvoie encore les endpoints internes de
	// Stalwart et les permissions restent vides.
	fmt.Println("      redémarrage (la configuration est lue au démarrage)")
	if out, err := k8s.Command(ctx, "kubectl", "-n", ns, "rollout", "restart",
		"deployment/stalwart").CombinedOutput(); err != nil {
		return fmt.Errorf("redémarrage : %w: %s", err, tronquer(string(out), 200))
	}
	// On attend la FIN du redémarrage, et pas seulement qu'un pod soit prêt :
	// pendant la transition, l'ancien pod répond encore et `kubectl exec
	// deploy/stalwart` peut s'adresser à lui — la vérification ci-dessous
	// échouait alors sur une connexion refusée.
	if out, err := k8s.Command(ctx, "kubectl", "-n", ns, "rollout", "status",
		"deployment/stalwart", "--timeout=240s").CombinedOutput(); err != nil {
		return fmt.Errorf("attente du redémarrage : %w: %s", err, tronquer(string(out), 200))
	}
	if err := waitReady(ctx); err != nil {
		return err
	}

	// --- 9. vérification : la découverte doit pointer vers le fournisseur ---
	// C'est le seul contrôle qui distingue « configuré » de « actif ». On
	// réessaie quelques fois : juste après un redémarrage, le service peut
	// n'avoir pas encore réouvert son port.
	compte := o.CompteAdmin + "@" + o.DomaineAdmin
	var dernier string
	for essai := 0; essai < 6; essai++ {
		out, err := k8s.Command(ctx, "kubectl", "-n", ns, "exec", "deploy/stalwart", "--",
			"sh", "-c", `curl -s --max-time 15 -u "$STALWART_RECOVERY_ADMIN" `+
				`"http://localhost:8080/api/discover/`+compte+`"`).CombinedOutput()
		if err == nil {
			dernier = string(out)
			if strings.Contains(dernier, o.Issuer) {
				fmt.Printf("  ✓ SSO actif : %s renvoie vers %s\n", compte, o.Issuer)
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("la découverte ne renvoie pas le fournisseur attendu (%s) : %s",
		o.Issuer, tronquer(dernier, 200))
}

// assurerDomaine crée le domaine s'il manque et renvoie son identifiant.
//
// Le domaine est rattaché à l'annuaire OIDC : c'est ce lien qui permet à
// Stalwart de savoir où résoudre les comptes de ce domaine.
func assurerDomaine(ctx context.Context, nom, idAnnuaire string) (string, error) {
	existant, err := chercherID(ctx, "x:Domain/get", "name", nom)
	if err != nil {
		return "", fmt.Errorf("lecture des domaines : %w", err)
	}
	if existant != "" {
		if err := majJMAPObjet(ctx, "x:Domain/set", existant, map[string]any{
			"directoryId": idAnnuaire,
		}); err != nil {
			return "", fmt.Errorf("rattachement du domaine %s : %w", nom, err)
		}
		return existant, nil
	}
	fmt.Printf("  ∙ domaine créé : %s\n", nom)
	créé, err := créerObjet(ctx, "x:Domain/set", map[string]any{
		"name":        nom,
		"directoryId": idAnnuaire,
	})
	if err != nil {
		return "", fmt.Errorf("création du domaine %s : %w", nom, err)
	}
	return créé, nil
}

// assurerAnnuaireOIDC crée ou met à jour l'annuaire OIDC et renvoie son id.
//
// TROIS RÉGLAGES QUI ONT CHACUN PROVOQUÉ UN ÉCHEC :
//
//   - requireAudience : sa valeur par défaut est « stalwart ». Keycloak
//     n'émet jamais cette valeur, donc TOUS les jetons étaient rejetés et la
//     session retombait en anonyme. On l'aligne sur l'identifiant du client,
//     qu'un mapper d'audience ajoute au jeton côté Keycloak.
//   - requireScopes : le WebUI n'envoie pas la liste attendue par défaut
//     (openid+email) ; on n'exige donc rien. La valeur vide s'écrit {} — « null »
//     est refusé par l'API.
//   - usernameDomain : le domaine ajouté au nom d'utilisateur du jeton pour
//     former le compte complet (utilisateur@domaine).
func assurerAnnuaireOIDC(ctx context.Context, o SSO) (string, error) {
	corps := map[string]any{
		"@type":           "Oidc",
		"description":     "Annuaire OIDC de la plateforme",
		"issuerUrl":       o.Issuer,
		"requireAudience": o.ClientID,
		"requireScopes":   map[string]any{},
		"claimUsername":   "preferred_username",
		"usernameDomain":  o.DomaineAdmin,
		"claimName":       "name",
		"claimGroups":     "groups",
	}
	// L'annuaire se reconnaît à son URL d'émetteur, pas à sa description.
	id, err := chercherIDParIssuer(ctx, o.Issuer)
	if err != nil {
		return "", err
	}
	if id == "" {
		créé, err := créerObjet(ctx, "x:Directory/set", corps)
		if err != nil {
			return "", fmt.Errorf("création de l'annuaire OIDC : %w", err)
		}
		fmt.Printf("  ∙ annuaire OIDC créé : %s\n", o.Issuer)
		return créé, nil
	}
	if err := majJMAPObjet(ctx, "x:Directory/set", id, corps); err != nil {
		return "", fmt.Errorf("mise à jour de l'annuaire OIDC : %w", err)
	}
	return id, nil
}

// assurerRoles renseigne les quatre tables de rôles de l'objet Authentication.
//
// C'est LE correctif du « 403 après une connexion réussie ». Les tables sont
// lues depuis les rôles réellement présents, appariés sur leur description.
func assurerRoles(ctx context.Context) error {
	roles, err := lireChamps(ctx, "x:Role/get", "description")
	if err != nil {
		return fmt.Errorf("lecture des rôles : %w", err)
	}
	if len(roles) == 0 {
		return fmt.Errorf("aucun rôle déclaré : le serveur n'est pas initialisé")
	}
	maj := map[string]any{}
	for _, table := range rôlesParDéfaut {
		composition := map[string]any{}
		for _, description := range table.descriptions {
			id, ok := roles[description]
			if !ok {
				return fmt.Errorf("rôle « %s » introuvable : l'installation est incomplète", description)
			}
			composition[id] = true
		}
		maj[table.champ] = composition
	}
	if err := majJMAP(ctx, "x:Authentication/set", map[string]any{
		"update": map[string]any{"singleton": maj},
	}); err != nil {
		return fmt.Errorf("tables de rôles : %w", err)
	}
	fmt.Println("  ✓ rôles → permissions (User, Group, Tenant Admin, System Admin)")
	return nil
}

// assurerCompteAdmin crée le compte d'administration s'il manque.
func assurerCompteAdmin(ctx context.Context, nom, idDomaine string) error {
	id, err := chercherID(ctx, "x:Account/get", "name", nom)
	if err != nil {
		return fmt.Errorf("lecture des comptes : %w", err)
	}
	corps := map[string]any{
		"@type":    "User",
		"name":     nom,
		"domainId": idDomaine,
		"roles":    map[string]any{"@type": "Admin"},
	}
	if id == "" {
		if _, err := créerObjet(ctx, "x:Account/set", corps); err != nil {
			return fmt.Errorf("création du compte %s : %w", nom, err)
		}
		fmt.Printf("  ∙ compte d'administration créé : %s\n", nom)
		return nil
	}
	// Le compte existe : on s'assure qu'il porte bien le rôle d'admin et qu'il
	// est rattaché au domaine d'administration.
	if err := majJMAPObjet(ctx, "x:Account/set", id, map[string]any{
		"domainId": idDomaine,
		"roles":    map[string]any{"@type": "Admin"},
	}); err != nil {
		return fmt.Errorf("mise à jour du compte %s : %w", nom, err)
	}
	return nil
}

// assurerClientWebUI déclare le client OIDC utilisé par l'interface d'admin.
//
// Sans lui, la page /admin n'expose aucun client : le bouton SSO n'apparaît
// pas et seul le formulaire interne est proposé.
func assurerClientWebUI(ctx context.Context, clientID string) error {
	existants, err := lireChamps(ctx, "x:Application/get", "oauthClientId")
	if err != nil {
		return fmt.Errorf("lecture des applications : %w", err)
	}
	if _, ok := existants[clientID]; ok {
		return nil
	}
	// Une seule application sert le WebUI : on complète la première déclarée
	// plutôt que d'en ajouter une seconde, qui ne serait jamais servie.
	ids, err := lireIDs(ctx, "x:Application/get")
	if err != nil || len(ids) == 0 {
		return fmt.Errorf("aucune application WebUI déclarée : %v", err)
	}
	if err := majJMAPObjet(ctx, "x:Application/set", ids[0], map[string]any{
		"oauthClientId": clientID,
	}); err != nil {
		return fmt.Errorf("client OIDC du WebUI : %w", err)
	}
	fmt.Printf("  ∙ client OIDC du WebUI : %s\n", clientID)
	return nil
}

// ---------------------------------------------------------------------------
// Accès JMAP
//
// FORMAT : toute la configuration de Stalwart v0.16 est un objet JMAP. On passe
// par le pod (et non par l'Ingress) : l'appel reste sur le réseau interne et
// STALWART_RECOVERY_ADMIN est déjà dans l'environnement du conteneur — le secret
// ne transite donc jamais par une ligne de commande.
// ---------------------------------------------------------------------------

// appelJMAP envoie une requête JMAP et renvoie le premier corps de réponse.
func appelJMAP(ctx context.Context, méthode string, args map[string]any) (map[string]any, error) {
	enveloppe := map[string]any{
		"using":       []string{},
		"methodCalls": []any{[]any{méthode, args, "c1"}},
	}
	brut, err := json.Marshal(enveloppe)
	if err != nil {
		return nil, err
	}
	script := `curl -s --max-time 20 -u "$STALWART_RECOVERY_ADMIN" ` +
		`-H "Content-Type: application/json" -X POST http://localhost:8080/jmap --data @-`
	cmd := k8s.Command(ctx, "kubectl", "-n", ns, "exec", "-i", "deploy/stalwart", "--",
		"sh", "-c", script)
	cmd.Stdin = strings.NewReader(string(brut))
	sortie, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("appel JMAP %s : %w: %s", méthode, err, tronquer(string(sortie), 200))
	}

	var réponse struct {
		MethodResponses []json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(sortie, &réponse); err != nil {
		return nil, fmt.Errorf("réponse JMAP illisible (%s) : %w", tronquer(string(sortie), 200), err)
	}
	if len(réponse.MethodResponses) == 0 {
		return nil, fmt.Errorf("réponse JMAP vide : %s", tronquer(string(sortie), 200))
	}
	var couple []json.RawMessage
	if err := json.Unmarshal(réponse.MethodResponses[0], &couple); err != nil || len(couple) < 2 {
		return nil, fmt.Errorf("réponse JMAP inattendue : %s", tronquer(string(sortie), 200))
	}
	var nom string
	_ = json.Unmarshal(couple[0], &nom)
	var corps map[string]any
	if err := json.Unmarshal(couple[1], &corps); err != nil {
		return nil, fmt.Errorf("corps JMAP illisible : %w", err)
	}
	// L'API signale ses refus dans le corps, pas par un code HTTP.
	if _, estErreur := corps["type"]; estErreur && nom == "error" {
		return nil, fmt.Errorf("refus de Stalwart : %s", tronquer(string(couple[1]), 300))
	}
	for _, clé := range []string{"notCreated", "notUpdated", "notDestroyed"} {
		if v, ok := corps[clé]; ok {
			return nil, fmt.Errorf("Stalwart a refusé (%s) : %v", clé, tronquer(fmt.Sprint(v), 300))
		}
	}
	return corps, nil
}

// majJMAP envoie une modification et ne renvoie rien.
func majJMAP(ctx context.Context, méthode string, args map[string]any) error {
	args["accountId"] = compteGestion
	_, err := appelJMAP(ctx, méthode, args)
	return err
}

// majJMAPObjet met à jour un objet précis.
func majJMAPObjet(ctx context.Context, méthode, id string, champs map[string]any) error {
	return majJMAP(ctx, méthode, map[string]any{"update": map[string]any{id: champs}})
}

// créerObjet crée un objet et renvoie son identifiant.
func créerObjet(ctx context.Context, méthode string, champs map[string]any) (string, error) {
	corps, err := appelJMAP(ctx, méthode, map[string]any{
		"accountId": compteGestion,
		"create":    map[string]any{"n1": champs},
	})
	if err != nil {
		return "", err
	}
	créés, ok := corps["created"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("création sans identifiant renvoyé")
	}
	for _, v := range créés {
		if m, ok := v.(map[string]any); ok {
			if id, ok := m["id"].(string); ok {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("création sans identifiant renvoyé")
}

// chercherID renvoie l'identifiant du premier objet dont le champ vaut valeur.
func chercherID(ctx context.Context, méthode, champ, valeur string) (string, error) {
	trouvés, err := lireChamps(ctx, méthode, champ)
	if err != nil {
		return "", err
	}
	return trouvés[valeur], nil
}

// lireChamps renvoie, pour chaque objet, la valeur de champ associée à son id.
func lireChamps(ctx context.Context, méthode, champ string) (map[string]string, error) {
	corps, err := appelJMAP(ctx, méthode, map[string]any{
		"accountId":  compteGestion,
		"properties": []string{"id", champ},
	})
	if err != nil {
		return nil, err
	}
	liste, _ := corps["list"].([]any)
	résultat := map[string]string{}
	for _, e := range liste {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		val, _ := m[champ].(string)
		if id != "" && val != "" {
			résultat[val] = id
		}
	}
	return résultat, nil
}

// lireIDs renvoie tous les identifiants d'un type d'objet.
func lireIDs(ctx context.Context, méthode string) ([]string, error) {
	corps, err := appelJMAP(ctx, méthode, map[string]any{
		"accountId":  compteGestion,
		"properties": []string{"id"},
	})
	if err != nil {
		return nil, err
	}
	liste, _ := corps["list"].([]any)
	var ids []string
	for _, e := range liste {
		if m, ok := e.(map[string]any); ok {
			if id, ok := m["id"].(string); ok {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// chercherIDParIssuer retrouve l'annuaire OIDC par son URL d'émetteur.
//
// On ne se fie pas à la description : elle est libre, et la modifier ferait
// croire à un annuaire manquant — donc à un doublon.
func chercherIDParIssuer(ctx context.Context, issuer string) (string, error) {
	corps, err := appelJMAP(ctx, "x:Directory/get", map[string]any{
		"accountId":  compteGestion,
		"properties": []string{"id", "issuerUrl"},
	})
	if err != nil {
		return "", fmt.Errorf("lecture des annuaires : %w", err)
	}
	liste, _ := corps["list"].([]any)
	for _, e := range liste {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if u, _ := m["issuerUrl"].(string); u == issuer {
			id, _ := m["id"].(string)
			return id, nil
		}
	}
	return "", nil
}

// attendreStabilité laisse à Stalwart le temps de recharger sa configuration.
func attendreStabilité(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(3 * time.Second):
		return nil
	}
}
