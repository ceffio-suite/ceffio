// Package console — gestion des applications Nextcloud via l'API OCS.
//
// POURQUOI L'API ET PAS DES JOBS KUBERNETES :
//
// Nextcloud expose une API officielle pour exactement ce besoin :
//
//	GET    /ocs/v2.php/cloud/apps?filter=enabled   → applications actives
//	POST   /ocs/v2.php/cloud/apps/{id}             → activer une application
//	DELETE /ocs/v2.php/cloud/apps/{id}             → désactiver une application
//
// Une première version passait par des Jobs Kubernetes exécutant `occ` dans le
// pod Nextcloud. Cela imposait beaucoup de pièces mobiles : un ServiceAccount
// d'exécution, un montage du PVC (qui ne traverse pas les namespaces), un pod
// par opération, la lecture de logs. Le tout pour un résultat que l'API donne en
// un seul appel HTTP.
//
// L'approche retenue : des appels HTTP avec un compte de service Nextcloud dédié
// (`ceffio-console`) et un mot de passe d'application révocable. Aucun droit
// supplémentaire dans le cluster, aucune exécution de commande.
package console

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AppDecrite décrit une application telle que l'interface la présente.
type AppDecrite struct {
	ID        string `json:"id"`
	Nom       string `json:"nom"`
	Role      string `json:"role"`
	Licence   string `json:"licence"`
	Categorie string `json:"categorie"`
	Docs      string `json:"docs"`
	Installee bool   `json:"installee"`
	EnAttente string `json:"en_attente,omitempty"` // dépendance non fournie
}

// catalogueApps : l'inventaire présenté par la console. Il reprend celui du
// module internal/apps (source de vérité du déploiement), enrichi de ce dont
// l'INTERFACE a besoin : catégorie, lien de documentation, dépendance.
var catalogueApps = []AppDecrite{
	// ── Page 1 : sans dépendance, installables ──────────────────────────
	{ID: "deck", Nom: "Deck", Categorie: "Collaboration", Licence: "AGPL-3.0",
		Role: "Tableaux Kanban partagés (gestion de projet)",
		Docs: "https://github.com/nextcloud/deck"},
	{ID: "collectives", Nom: "Collectives", Categorie: "Collaboration", Licence: "AGPL-3.0",
		Role: "Wiki et documentation d'équipe",
		Docs: "https://github.com/nextcloud/collectives"},
	{ID: "forms", Nom: "Forms", Categorie: "Communication", Licence: "AGPL-3.0",
		Role: "Formulaires et sondages",
		Docs: "https://github.com/nextcloud/forms"},
	{ID: "polls", Nom: "Polls", Categorie: "Communication", Licence: "AGPL-3.0",
		Role: "Sondages de disponibilité",
		Docs: "https://github.com/nextcloud/polls"},
	{ID: "calendar", Nom: "Calendar", Categorie: "Organisation", Licence: "AGPL-3.0",
		Role: "Calendrier partagé",
		Docs: "https://github.com/nextcloud/calendar"},
	{ID: "contacts", Nom: "Contacts", Categorie: "Organisation", Licence: "AGPL-3.0",
		Role: "Carnet de contacts partagé",
		Docs: "https://github.com/nextcloud/contacts"},
	{ID: "tasks", Nom: "Tasks", Categorie: "Organisation", Licence: "AGPL-3.0",
		Role: "Tâches et listes partagées",
		Docs: "https://github.com/nextcloud/tasks"},
	{ID: "appointments", Nom: "Rendez-vous", Categorie: "Organisation", Licence: "AGPL-3.0",
		Role: "Prise de rendez-vous avec lien public",
		Docs: "https://github.com/nextcloud/appointments"},
	{ID: "notes", Nom: "Notes", Categorie: "Documents", Licence: "AGPL-3.0",
		Role: "Prise de notes (markdown)",
		Docs: "https://github.com/nextcloud/notes"},
	{ID: "tables", Nom: "Tables", Categorie: "Documents", Licence: "AGPL-3.0",
		Role: "Tableaux structurés (base de données légère)",
		Docs: "https://github.com/nextcloud/tables"},
	{ID: "groupfolders", Nom: "Dossiers d'équipe", Categorie: "Documents", Licence: "AGPL-3.0",
		Role: "Dossiers partagés par groupe (et non utilisateur à utilisateur)",
		Docs: "https://github.com/nextcloud/groupfolders"},
	{ID: "files_retention", Nom: "Rétention", Categorie: "Documents", Licence: "AGPL-3.0",
		Role: "Suppression automatique des fichiers après une durée",
		Docs: "https://github.com/nextcloud/files_retention"},
	{ID: "files_accesscontrol", Nom: "Contrôle d'accès", Categorie: "Documents", Licence: "AGPL-3.0",
		Role: "Règles d'accès aux fichiers (interdire un type, un groupe…)",
		Docs: "https://github.com/nextcloud/files_accesscontrol"},
	{ID: "bookmarks", Nom: "Signets", Categorie: "Organisation", Licence: "AGPL-3.0",
		Role: "Signets partagés",
		Docs: "https://github.com/nextcloud/bookmarks"},
	{ID: "announcementcenter", Nom: "Annonces", Categorie: "Communication", Licence: "AGPL-3.0",
		Role: "Annonces d'administration à tous les utilisateurs",
		Docs: "https://github.com/nextcloud/announcementcenter"},
	{ID: "external", Nom: "Sites externes", Categorie: "Organisation", Licence: "AGPL-3.0",
		Role: "Liens vers des sites externes dans l'interface",
		Docs: "https://github.com/nextcloud/external"},
	{ID: "group_everyone", Nom: "Groupe « tous »", Categorie: "Organisation", Licence: "AGPL-3.0",
		Role: "Groupe automatique contenant tous les utilisateurs",
		Docs: "https://github.com/nextcloud/group_everyone"},

	// ── Page 2 : dépendance externe, lecture seule ─────────────────────
	//
	// Ces applications ne se gèrent PAS d'un clic : chacune dépend de services
	// déployés séparément. Les rendre cochables laisserait croire le contraire,
	// et décocher l'une d'elles casserait un composant que la console ne saurait
	// pas remettre en place.
	//
	// Talk en particulier n'est PAS une app Nextcloud : c'est toute une pile
	// (janus + signaling + coturn + nats, avec leurs ingress et leurs règles de
	// pare-feu). Il est déployé par `ceffio install`, jamais par cette page.
	{ID: "spreed", Nom: "Talk — messagerie et visio", Categorie: "Communication",
		Licence: "AGPL-3.0",
		Role:      "Messagerie, appels et visioconférence dans Nextcloud",
		Docs:      "https://github.com/nextcloud/spreed",
		EnAttente: "pile complète déployée par Ceffio (4 services : SFU, signaling, TURN, NATS)"},
	{ID: "whiteboard", Nom: "Whiteboard", Categorie: "Collaboration", Licence: "AGPL-3.0",
		Role:      "Tableau blanc collaboratif (temps réel)",
		Docs:      "https://github.com/nextcloud/whiteboard",
		EnAttente: "serveur WebSocket à déployer (port 3002)"},
	{ID: "recognize", Nom: "Recognize", Categorie: "Documents", Licence: "AGPL-3.0",
		Role:      "Recherche et classification par IA",
		Docs:      "https://github.com/nextcloud/recognize",
		EnAttente: "modèles IA à télécharger (plusieurs centaines de Mo)"},
	{ID: "files_antivirus", Nom: "Antivirus", Categorie: "Sécurité", Licence: "AGPL-3.0",
		Role:      "Analyse antivirus des fichiers déposés",
		Docs:      "https://github.com/nextcloud/files_antivirus",
		EnAttente: "serveur ClamAV à déployer séparément"},
	{ID: "encryption", Nom: "Chiffrement du stockage", Categorie: "Sécurité", Licence: "AGPL-3.0",
		Role:      "Chiffrement des fichiers au repos",
		Docs:      "https://docs.nextcloud.com/server/stable/admin_manual/configuration_files/encryption_configuration.html",
		EnAttente: "irréversible : tout déchiffrer ensuite est très lourd"},

}

// handleApps rend l'état des applications : ce que le catalogue propose, et ce
// qui est réellement actif sur l'instance.
func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiErr(w, 405, "méthode non autorisée")
		return
	}

	// Ce qui est actif : lu depuis Nextcloud, jamais depuis un cache.
	installes, err := s.appsInstallees()
	if err != nil {
		// On ne masque pas l'erreur : si Nextcloud est injoignable, l'interface
		// doit le dire plutôt que d'afficher un catalogue vide.
		apiErr(w, 502, "Nextcloud injoignable : "+err.Error())
		return
	}

	// On ne compte que les applications DU CATALOGUE : `installes` contient
	// toutes les apps de l'instance (64 sur ce Nextcloud), dont la grande
	// majorité ne fait pas partie de la sélection Ceffio. Compter le total
	// donnerait « 64 actives » alors que 12 sont présentées.
	out := make([]AppDecrite, 0, len(catalogueApps))
	actives := 0
	for _, a := range catalogueApps {
		if _, ok := installes[a.ID]; ok {
			a.Installee = true
			// On ne compte que les apps SANS dépendance : les autres ne sont
			// pas activables ici, les compter donnerait un total trompeur.
			if a.EnAttente == "" {
				actives++
			}
		}
		out = append(out, a)
	}

	writeJSON(w, 200, map[string]any{
		"apps":     out,
		"total":    len(out),
		"installe": actives,
	})
}

// handleAppsAction active ou désactive une application, via l'API OCS.
//
// POST /api/apps/{id}/install    → active
// POST /api/apps/{id}/uninstall  → désactive
//
// Deux points à connaître sur ce que l'API permet vraiment :
//   - « install » signifie ici ACTIVER une application déjà présente dans
//     custom_apps — c'est le cas de tout le catalogue, posé par la phase 12.
//     Télécharger depuis l'app store est une autre opération, que Ceffio ne
//     fait pas : le catalogue est maîtrisé, pas ouvert.
//   - « uninstall » DÉSACTIVE l'application ; elle reste sur le disque et peut
//     être réactivée. La suppression définitive n'est pas exposée : elle
//     détruirait des données utilisateur.
func (s *Server) handleAppsAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiErr(w, 405, "méthode non autorisée")
		return
	}

	chemin := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/apps/"), "/")
	parties := strings.Split(chemin, "/")
	if len(parties) != 2 {
		apiErr(w, 400, "chemin attendu : /api/apps/{id}/{install|uninstall}")
		return
	}
	id, action := parties[0], parties[1]

	// Valider l'identifiant CONTRE LE CATALOGUE : sans ce contrôle, le
	// paramètre entrerait dans une URL d'API.
	var cible *AppDecrite
	for i := range catalogueApps {
		if catalogueApps[i].ID == id {
			cible = &catalogueApps[i]
			break
		}
	}
	if cible == nil {
		apiErr(w, 404, "application inconnue : "+id)
		return
	}

	var methode string
	switch action {
	case "install":
		methode = http.MethodPost
	case "uninstall":
		methode = http.MethodDelete
	default:
		apiErr(w, 400, "action inconnue : "+action+" (attendu : install ou uninstall)")
		return
	}

	req, err := http.NewRequest(methode, s.urlOCS()+"/cloud/apps/"+id, nil)
	if err != nil {
		apiErr(w, 500, err.Error())
		return
	}
	req.Header.Set("OCS-APIRequest", "true")
	req.SetBasicAuth(s.ncUser, s.ncPass)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		apiErr(w, 502, "Nextcloud injoignable : "+err.Error())
		return
	}
	defer resp.Body.Close()

	var corps struct {
		OCS struct {
			Meta struct {
				Status     string `json:"status"`
				StatusCode int    `json:"statuscode"`
				Message    string `json:"message"`
			} `json:"meta"`
		} `json:"ocs"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&corps)

	if corps.OCS.Meta.Status != "ok" {
		apiErr(w, 500, fmt.Sprintf("Nextcloud a refusé : %s (code %d)",
			corps.OCS.Meta.Message, corps.OCS.Meta.StatusCode))
		return
	}

	verbe := "activée"
	if action == "uninstall" {
		verbe = "désactivée"
	}
	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"app":     cible.Nom,
		"message": fmt.Sprintf("%s %s", cible.Nom, verbe),
	})
}

// urlOCS rend la base de l'API OCS de Nextcloud (service interne du cluster).
//
// Le service interne est utilisé plutôt que l'URL publique : la console tourne
// dans le cluster, inutile de sortir par Internet pour joindre un service du
// même cluster.
func (s *Server) urlOCS() string {
	return "http://nextcloud.ceffio-files.svc:80/ocs/v2.php"
}

// appsInstallees lit la liste des applications ACTIVES via l'API OCS.
//
// Les identifiants viennent du compte de service `ceffio-console`, créé pour cet
// usage avec un mot de passe d'application dédié et révocable. On n'utilise PAS
// le compte admin : son secret est trop large, et un changement de son mot de
// passe casserait la console.
func (s *Server) appsInstallees() (map[string]string, error) {
	// `filter=enabled` : on ne veut que les apps ACTIVES. Sans ce filtre, l'API
	// renvoie aussi les apps présentes mais désactivées, ce qui ferait
	// apparaître comme actif tout ce qui est téléchargé.
	req, err := http.NewRequest("GET",
		s.urlOCS()+"/cloud/apps?format=json&filter=enabled", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("OCS-APIRequest", "true")
	req.SetBasicAuth(s.ncUser, s.ncPass)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// On lit le corps ENTIER d'abord : le message d'erreur de Go ne dit pas ce
	// qui a ete recu, et sans le corps on ne peut que deviner.
	brut, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var corps struct {
		OCS struct {
			Data struct {
				Apps []string `json:"apps"`
			} `json:"data"`
		} `json:"ocs"`
	}
	if err := json.Unmarshal(brut, &corps); err != nil {
		return nil, fmt.Errorf("reponse inattendue (HTTP %d) : %.200s",
			resp.StatusCode, string(brut))
	}

	// La réponse est une simple liste d'identifiants : c'est tout ce dont on a
	// besoin pour savoir « active » ou pas.
	out := map[string]string{}
	for _, a := range corps.OCS.Data.Apps {
		out[a] = ""
	}
	return out, nil
}