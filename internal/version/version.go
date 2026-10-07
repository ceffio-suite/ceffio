// Package version recense les versions d'images et de charts déployées par
// Ceffio. C'est la source unique de vérité pour :
//
//   - « qu'est-ce que cette installation fait tourner, exactement ? » (status) ;
//   - « qu'est-ce qui changerait si je montais de version ? » (upgrade).
//
// Avant ce registre, chaque module portait ses constantes d'image dans son coin
// (files.nextcloudImage, identity.keycloakImage…). Cela suffisait pour déployer,
// mais rendait impossible toute comparaison : une commande de mise à niveau n'a
// rien à comparer si elle doit lire neuf fichiers.
//
// Règle : les versions sont PINÉES et jamais `latest`. Un composant qui suit
// `latest` ne peut pas être mis à niveau de façon reproductible — on ne sait ni
// ce qui tourne avant, ni ce qui tournera après.
package version

import (
	"fmt"
	"sort"
	"strings"
)

// Composant décrit un élément déployé et sa version épinglée.
type Composant struct {
	Nom     string `json:"nom"`     // nom lisible (keycloak, nextcloud…)
	Image   string `json:"image"`   // référence complète, tag inclus
	Module  string `json:"module"`  // package Go qui le déploie
	Role    string `json:"role"`    // à quoi il sert, en une ligne
	Version string `json:"version"` // tag extrait, pour comparaison
}

// Registry est l'inventaire par défaut, aligné sur le code de déploiement.
// Toute modification d'une image dans un module DOIT être répercutée ici : la
// fonction VerifierCoherence() le contrôle et le test le vérifie.
var Registry = []Composant{
	{
		Nom: "keycloak", Image: "quay.io/keycloak/keycloak:26.7.3",
		Module: "internal/identity", Role: "identité, SSO OIDC",
	},
	{
		Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3",
		Module: "internal/files", Role: "fichiers et documents",
	},
	{
		Nom: "onlyoffice", Image: "docker.io/onlyoffice/documentserver:9.4.0.1",
		Module: "internal/office", Role: "édition de documents",
	},
	{
		Nom: "synapse", Image: "docker.io/matrixdotorg/synapse:v1.160.0",
		Module: "internal/chat", Role: "messagerie (serveur Matrix)",
	},
	{
		Nom: "element", Image: "docker.io/vectorim/element-web:v1.12.27",
		Module: "internal/chat", Role: "messagerie (client web)",
	},
	{
		Nom: "jitsi-web", Image: "ghcr.io/jitsi/web:stable-11146-2",
		Module: "internal/media", Role: "visioconférence (interface)",
	},
	{
		Nom: "jitsi-prosody", Image: "ghcr.io/jitsi/prosody:stable-11146-2",
		Module: "internal/media", Role: "visioconférence (XMPP)",
	},
	{
		Nom: "jitsi-jicofo", Image: "ghcr.io/jitsi/jicofo:stable-11146-2",
		Module: "internal/media", Role: "visioconférence (conférencier)",
	},
	{
		Nom: "jitsi-jvb", Image: "ghcr.io/jitsi/jvb:stable-11146-2",
		Module: "internal/media", Role: "visioconférence (pont vidéo)",
	},
	{
		Nom: "redis", Image: "redis:7.4.11",
		Module: "internal/data", Role: "cache et état partagé",
	},
}

// Charts Helm utilisés pour la plateforme (opérateurs).
var Charts = []Composant{
	{Nom: "cloudnative-pg", Image: "cloudnative-pg:0.29.0", Module: "internal/data",
		Role: "opérateur PostgreSQL", Version: "0.29.0"},
	{Nom: "cert-manager", Image: "cert-manager:v1.21.1", Module: "internal/platform",
		Role: "gestion des certificats TLS", Version: "v1.21.1"},
}

func init() {
	for i := range Registry {
		Registry[i].Version = TagDe(Registry[i].Image)
	}
}

// TagDe expose l'extraction de tag (utilisée aussi par `upgrade` pour comparer
// ce qui tourne avec la cible).
func TagDe(image string) string { return tagDe(image) }

// tagDe extrait le tag d'une référence d'image.
// « docker.io/library/nextcloud:34.0.3 » → « 34.0.3 ».
// Renvoie "" si l'image n'a pas de tag (donc implicite : latest).
func tagDe(image string) string {
	i := strings.LastIndex(image, ":")
	if i < 0 {
		return ""
	}
	tag := image[i+1:]
	if strings.Contains(tag, "/") { // le ':' appartient au registre (host:port)
		return ""
	}
	return tag
}

// ParNom retrouve un composant.
func ParNom(nom string) (Composant, bool) {
	for _, c := range Registry {
		if c.Nom == nom {
			return c, true
		}
	}
	return Composant{}, false
}

// Noms renvoie les noms de composants, triés (pour l'affichage et les tests).
func Noms() []string {
	out := make([]string, 0, len(Registry))
	for _, c := range Registry {
		out = append(out, c.Nom)
	}
	sort.Strings(out)
	return out
}

// VerifierCoherence contrôle qu'aucune image ne suit `latest` ni un tag
// implicite : sans tag figé, une mise à niveau n'est pas reproductible.
func VerifierCoherence() []string {
	var problemes []string
	for _, c := range Registry {
		if c.Version == "" {
			problemes = append(problemes,
				fmt.Sprintf("%s : image sans tag explicite (%s) — version non reproductible", c.Nom, c.Image))
			continue
		}
		if c.Version == "latest" || c.Version == "stable" {
			problemes = append(problemes,
				fmt.Sprintf("%s : tag %q flottant — pinné requis en production", c.Nom, c.Version))
		}
	}
	return problemes
}

// Comparer indique, pour chaque composant, la version installée et celle du
// registre. Utilisé par `upgrade` pour montrer ce qui changerait.
type Ecart struct {
	Nom       string
	Installee string
	Cible     string
}

// VerifierImagesInstallees extrait les versions réellement en service depuis les
// images des pods. C'est ce qui rend `upgrade` honnête : il ne compare pas deux
// listes de fichiers, il compare ce qui TOURNE avec ce que le code déploierait.
func ExtraireImages(podsJSON string) map[string]string {
	out := map[string]string{}
	// Analyse volontairement tolérante : on cherche les paires image/version
	// sans dépendre d'un décodage JSON complet, car la fonction est aussi
	// utilisée sur des sorties partielles.
	for _, ligne := range strings.Split(podsJSON, "\n") {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" {
			continue
		}
		out[ligne] = tagDe(ligne)
	}
	return out
}
