// Package secrets centralise la gestion des secrets des composants Ceffio.
//
// POURQUOI CE MODULE : aujourd'hui chaque composant génère ses secrets et les
// pose dans un Secret Kubernetes, dans son coin. Cela fonctionne, mais l'exploitant
// n'a aucun point unique pour les voir, les faire tourner, ou les sauvegarder
// autrement qu'en sauvegardant tout le cluster. OpenBao apporte ce point unique.
//
// CONTRAINTE DE CONCEPTION — OpenBao est OPTIONNEL, jamais obligatoire.
// Ceffio doit rester « auto-portant en une commande » : une PME qui n'a pas
// d'OpenBao doit pouvoir déployer la suite complète. Le coffre est donc un
// AMÉLIORATION, pas un prérequis :
//
//	coffre configuré  → les secrets sont lus depuis le coffre, avec repli sur
//	                    le Secret Kubernetes si le coffre est injoignable ;
//	coffre absent     → on génère et pose les secrets dans Kubernetes, comme avant.
//
// Cette règle vient d'une contrainte réelle : un produit qu'on ne peut pas
// installer sans une brique supplémentaire n'est pas auto-portant.
//
// Ce que le coffre porte, et ce qu'il ne porte PAS :
//   - il porte ce que les composants CONSOMMENT (mots de passe de base, clés
//     d'API, secrets de session) ;
//   - il ne porte PAS ce que Ceffio FABRIQUE pour ses utilisateurs (jetons
//     d'API créés à la volée) : ceux-là vivent dans la base de l'application,
//     idéalement sous forme d'empreinte ;
//   - il ne peut pas porter sa propre clé de descellement — c'est le secret-zéro,
//     à documenter comme tel.
package secrets

import (
	"fmt"
	"os"
	"strings"
)

// Coffre décrit un coffre OpenBao joignable.
//
// Les identifiants viennent de l'ENVIRONNEMENT, jamais d'un fichier de
// configuration versionné : c'est la seule façon d'utiliser le même module avec
// des coffres différents selon le déploiement.
type Coffre struct {
	Adresse   string // BAO_ADDR (ex. https://bao.example.com)
	Jeton     string // BAO_TOKEN (jeton ou token d'AppRole)
	Namespace string // BAO_NAMESPACE, vide si le moteur est à la racine
	Moteur    string // nom du moteur KV (kv, secret…)
}

// DepuisEnvironnement construit la configuration du coffre depuis BAO_*.
//
// On ne cherche PAS à deviner : si l'adresse manque, on rend nil et l'appelant
// se rabat sur Kubernetes. Un coffre mal configuré ne doit jamais faire échouer
// un déploiement — c'est la règle qui garantit qu'OpenBao reste optionnel.
func DepuisEnvironnement() *Coffre {
	adresse := strings.TrimSpace(os.Getenv("BAO_ADDR"))
	if adresse == "" {
		return nil
	}
	// Le nom du moteur : `kv` est la convention de Ceffio (et d'OpenBao), mais
	// il est configurable car le nom RÉEL décide du chemin — un coffre peut
	// exposer `secret/` à la racine et `kv/` dans un namespace.
	moteur := strings.TrimSpace(os.Getenv("BAO_MOTEUR"))
	if moteur == "" {
		moteur = "kv"
	}
	return &Coffre{
		Adresse: adresse,
		Jeton:   strings.TrimSpace(os.Getenv("BAO_TOKEN")),
		// Un jeton lu depuis un fichier peut porter un \r final : l'entête
		// serait alors silencieusement corrompu et l'API répondrait « permission
		// denied » comme si le jeton était mauvais.
		Namespace: strings.TrimSpace(os.Getenv("BAO_NAMESPACE")),
		Moteur:    moteur,
	}
}

// Prefixe rend le préfixe de chemin des secrets Ceffio dans le coffre.
//
// Un préfixe dédié (« ceffio/ ») plutôt qu'un namespace : l'isolation par
// namespace coûte cher (authentification et politiques à recréer dans chacun) et
// n'est que logique, pas cryptographique — tous partagent la même clé de
// descellement. Un préfixe par application donne la même propriété pour bien
// moins cher, et suffit tant qu'il n'y a pas de vrai domaine de confiance séparé.
func (c *Coffre) Prefixe() string {
	return "ceffio"
}

// Chemin rend le chemin complet d'un secret dans le coffre.
//
// La convention : ceffio/<composant>/<nom>. Elle se lit de gauche à droite et
// répond à « d'où vient ce secret » sans documentation.
func (c *Coffre) Chemin(composant, nom string) string {
	return fmt.Sprintf("%s/%s/%s", c.Prefixe(), composant, nom)
}

// Dispo dit si un coffre est configuré, pour que l'appelant n'ait pas à tester
// nil lui-même. Un coffre absent n'est PAS une erreur : c'est le cas nominal
// d'une installation sans OpenBao.
func (c *Coffre) Dispo() bool {
	return c != nil && c.Adresse != ""
}

// Description rend une description lisible du coffre, SANS jamais exposer le
// jeton. Une valeur de secret ne doit apparaître nulle part, pas même dans un
// log de démarrage : n'imprimer que ce qui identifie le coffre.
func (c *Coffre) Description() string {
	if !c.Dispo() {
		return "aucun coffre configuré (secrets gérés dans Kubernetes)"
	}
	ns := c.Namespace
	if ns == "" {
		ns = "(racine)"
	}
	return fmt.Sprintf("%s, moteur « %s », namespace %s", c.Adresse, c.Moteur, ns)
}
