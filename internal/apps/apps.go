// Package apps installe et configure les applications Nextcloud retenues pour
// Ceffio.
//
// POURQUOI CE MODULE EXISTE : une app Nextcloud installée à la main ne fait
// partie d'aucune installation. Elle vit dans /var/www/html/custom_apps — donc
// dans le conteneur, sur un volume persistant : elle survit aux redémarrages,
// mais disparaît dès qu'on déploie sur une machine neuve. Sans ce module, une
// installation Ceffio n'aurait AUCUNE de ces apps, et le travail de sélection
// serait à refaire à chaque fois.
//
// CE QUI DÉCIDE DU CONTENU DE LA LISTE :
//   - licence LIBRE sans restriction d'usage commercial (AGPL-3.0, jamais de
//     quota d'utilisateurs ni de licence propriétaire) ;
//   - version STABLE publiée (pas de beta) ;
//   - apport réel à un travail à plusieurs.
//
// Ce qui est VOLONTAIREMENT EXCLU :
//   - richdocuments (Collabora) : ONLYOFFICE est déjà déployé, un second
//     serveur d'édition bureautique doublerait charge et maintenance pour la
//     même fonction ;
//   - les apps de thème/décor : elles n'apportent rien à la collaboration.
package apps

import (
	"context"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// categorie distingue les apps selon ce qu'elles exigent en plus d'elles-mêmes.
// C'est la distinction qui compte pour un déploiement : une app de catégorie
// serveur ne fonctionnera pas après un simple `app:install`.
type categorie int

const (
	// simple : l'app vit dans custom_apps et fonctionne dès l'activation.
	simple categorie = iota
	// serveur : l'app a besoin d'un service séparé pour être pleinement
	// fonctionnelle (temps réel, calcul lourd). Installée sans lui, elle
	// s'active mais reste limitée.
	serveur
)

// App décrit une application installée par Ceffio.
type App struct {
	ID        string    // identifiant app store (= nom du dossier custom_apps)
	Nom       string    // nom lisible
	Role      string    // à quoi elle sert, en une ligne
	Licence   string    // licence constatée sur l'app store
	Cat       categorie //
	DependsOn string    // service requis, vide si aucun
}

// Catalogue : l'inventaire retenu, vérifié sur l'app store officiel pour
// Nextcloud 34. TOUTES les entrées sont en licence libre (AGPL-3.0), sans
// restriction d'usage commercial ni quota d'utilisateurs.
//
// La catégorie sépare deux choses que l'utilisateur ne doit PAS confondre :
//   simple  → l'app fonctionne dès l'activation (page 1, installable)
//   serveur → l'app a besoin d'un service séparé (page 2, lecture seule)
//
// Les deux listes sont DISJOINTES : une app apparaît sur une seule page.
var Catalogue = []App{
	// ── Page 1 : sans dépendance, installables ──────────────────────────
	{ID: "deck", Nom: "Deck", Cat: simple, Licence: "AGPL-3.0",
		Role: "tableaux Kanban partagés (gestion de projet)"},
	{ID: "collectives", Nom: "Collectives", Cat: simple, Licence: "AGPL-3.0",
		Role: "wiki et documentation d'équipe"},
	{ID: "forms", Nom: "Forms", Cat: simple, Licence: "AGPL-3.0",
		Role: "formulaires et sondages"},
	{ID: "polls", Nom: "Polls", Cat: simple, Licence: "AGPL-3.0",
		Role: "sondages de disponibilité (planifier une réunion)"},
	{ID: "tasks", Nom: "Tasks", Cat: simple, Licence: "AGPL-3.0",
		Role: "tâches et listes partagées"},
	{ID: "calendar", Nom: "Calendar", Cat: simple, Licence: "AGPL-3.0",
		Role: "calendrier partagé"},
	{ID: "contacts", Nom: "Contacts", Cat: simple, Licence: "AGPL-3.0",
		Role: "carnet de contacts partagé"},
	{ID: "tables", Nom: "Tables", Cat: simple, Licence: "AGPL-3.0",
		Role: "tableaux structurés (base de données légère)"},
	{ID: "notes", Nom: "Notes", Cat: simple, Licence: "AGPL-3.0",
		Role: "prise de notes (markdown)"},
	{ID: "groupfolders", Nom: "Dossiers d'équipe", Cat: simple, Licence: "AGPL-3.0",
		Role: "dossiers partagés par groupe (et non utilisateur à utilisateur)"},
	{ID: "appointments", Nom: "Rendez-vous", Cat: simple, Licence: "AGPL-3.0",
		Role: "prise de rendez-vous avec lien public"},
	{ID: "mail", Nom: "Mail", Cat: simple, Licence: "AGPL-3.0",
		Role: "client mail intégré"},
	{ID: "announcementcenter", Nom: "Annonces", Cat: simple, Licence: "AGPL-3.0",
		Role: "annonces d'administration à tous les utilisateurs"},
	{ID: "files_retention", Nom: "Rétention", Cat: simple, Licence: "AGPL-3.0",
		Role: "suppression automatique des fichiers après une durée"},
	{ID: "files_accesscontrol", Nom: "Contrôle d'accès", Cat: simple, Licence: "AGPL-3.0",
		Role: "règles d'accès aux fichiers (interdire un type, un groupe…)"},
	{ID: "bookmarks", Nom: "Signets", Cat: simple, Licence: "AGPL-3.0",
		Role: "signets partagés"},
	{ID: "external", Nom: "Sites externes", Cat: simple, Licence: "AGPL-3.0",
		Role: "liens vers des sites externes dans l'interface"},
	{ID: "group_everyone", Nom: "Groupe « tous »", Cat: simple, Licence: "AGPL-3.0",
		Role: "groupe automatique contenant tous les utilisateurs"},

	// ── Page 2 : dépendance externe, NON installables ───────────────────
	{
		ID: "whiteboard", Nom: "Whiteboard", Cat: serveur, Licence: "AGPL-3.0",
		Role:      "tableau blanc collaboratif (temps réel)",
		DependsOn: "serveur WebSocket à déployer (port 3002)",
	},
	{
		ID: "recognize", Nom: "Recognize", Cat: serveur, Licence: "AGPL-3.0",
		Role:      "recherche et classification par IA dans les documents",
		DependsOn: "modèles IA à télécharger (plusieurs centaines de Mo)",
	},
	{
		ID: "files_antivirus", Nom: "Antivirus", Cat: serveur, Licence: "AGPL-3.0",
		Role:      "analyse antivirus des fichiers déposés",
		DependsOn: "serveur ClamAV à déployer séparément",
	},
	{
		ID: "encryption", Nom: "Chiffrement du stockage", Cat: serveur, Licence: "AGPL-3.0",
		Role:      "chiffrement des fichiers au repos",
		DependsOn: "irréversible : une fois activé, tout déchiffrer est très lourd",
	},
}

// Deploy installe et active les applications retenues, de façon idempotente.
//
// Idempotent au sens strict : `app:install` échoue si l'app est déjà là et
// `app:enable` réussit sans rien faire. On NE traite donc PAS l'échec de
// l'installation comme une erreur — sinon un second passage signalerait une
// panne là où tout va bien.
func Deploy(ctx context.Context) error {
	fmt.Println("\nInstallation des applications Nextcloud (Phase 12)...")

	// 1. État initial : savoir ce qui est déjà là évite de rejouer inutilement.
	deja := appsInstallees(ctx)

	var actives, nouvelles []string
	for _, a := range Catalogue {
		if _, ok := deja[a.ID]; !ok {
			nouvelles = append(nouvelles, a.Nom)
		}
		// 2. Installer si absent, puis activer dans tous les cas.
		if err := occ(ctx, "app:install", a.ID); err != nil &&
			!strings.Contains(err.Error(), "already installed") {
			// Un échec réel : on le signale et on continue. Une app
			// indisponible ne doit pas empêcher les autres de s'installer.
			fmt.Printf("  ! %s : installation impossible (%v)\n", a.Nom, err)
			continue
		}
		if err := occ(ctx, "app:enable", a.ID); err != nil {
			fmt.Printf("  ! %s : activation impossible (%v)\n", a.Nom, err)
			continue
		}
		actives = append(actives, a.Nom)
	}

	if len(nouvelles) > 0 {
		fmt.Printf("  ∙ %d nouvelle(s) : %s\n",
			len(nouvelles), strings.Join(nouvelles, ", "))
	} else {
		fmt.Println("  ∙ toutes les applications étaient déjà installées")
	}
	fmt.Printf("  ✓ %d applications actives : %s\n",
		len(actives), strings.Join(actives, ", "))

	// 3. Signaler les apps qui exigent une dépendance non fournie ici. C'est
	//    un point de transparence : sans lui, l'utilisateur croirait que tout
	//    fonctionne alors que deux apps attendent un service.
	var enAttente []string
	for _, a := range Catalogue {
		if a.Cat == serveur {
			enAttente = append(enAttente, fmt.Sprintf("%s (requiert %s)", a.Nom, a.DependsOn))
		}
	}
	if len(enAttente) > 0 {
		fmt.Println("  ∙ fonctionnalité complète en attente :")
		for _, e := range enAttente {
			fmt.Println("      " + e)
		}
	}

	// 4. Nettoyer le cache d'applications : sans ça, Nextcloud peut continuer
	//    à servir une liste d'apps périmée après une installation.
	if err := occ(ctx, "maintenance:repair", "--include-expensive"); err != nil {
		// Non bloquant : le réparateur peut échouer sur des détails sans
		// conséquence, et l'installation des apps est déjà faite.
		fmt.Printf("  (réparation du cache ignorée : %v)\n", err)
	}

	fmt.Println("✓ Applications Nextcloud installées")
	return nil
}

// appsInstallees rend l'ensemble des identifiants d'apps déjà présents.
func appsInstallees(ctx context.Context) map[string]struct{} {
	out, err := occSortie(ctx, "app:list", "--output=json")
	if err != nil {
		return map[string]struct{}{}
	}
	// On ne parse pas le JSON : on cherche simplement les identifiants connus
	// dans la sortie. Un parsing strict serait fragile, et il ne sert à rien
	// ici — on veut seulement savoir « déjà là » ou pas.
	connus := map[string]struct{}{}
	for _, a := range Catalogue {
		if strings.Contains(out, `"`+a.ID+`"`) {
			connus[a.ID] = struct{}{}
		}
	}
	return connus
}

// occ exécute une commande occ dans le pod Nextcloud.
func occ(ctx context.Context, args ...string) error {
	_, err := occSortie(ctx, args...)
	return err
}

// occSortie exécute occ et rend la sortie standard.
func occSortie(ctx context.Context, args ...string) (string, error) {
	complet := append([]string{
		"exec", "-n", "ceffio-files", "deploy/nextcloud", "--",
		"php", "occ",
	}, args...)
	cmd := k8s.Command(ctx, "kubectl", complet...)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}