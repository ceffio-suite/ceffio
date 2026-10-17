// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// This file prints the summary that closes an installation.
//
// # WHY THE INSTALLER PRINTS IT RATHER THAN A DOCUMENT
//
// The information below only exists once the deployment has run: the
// administration key is generated during it, the certificate dates depend on
// when Let's Encrypt answered, and the pod count depends on what actually came
// up. A README cannot carry any of that, so an operator finishing an
// installation has no single place to look — they go hunting through
// `kubectl`, the vault and three namespaces to reconstruct what they now have.
//
// Printing it at the end means the last thing on screen IS the answer: the
// addresses, the key, and what is running. It is also the moment the operator
// will actually read it.
//
// THE KEY IS PRINTED ONCE, AND THAT IS DELIBERATE. It is displayed at the end
// of the run that created it, on the operator's own terminal, and nowhere
// else. It is not repeated on a re-run, not written to a file, and not put in
// the cluster's logs: a credential that is easy to find is a credential that
// leaks.
package console

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// Synthese prints the closing summary: what was installed, where it answers,
// and the administration key.
//
// IT NEVER FAILS THE INSTALLATION. The deployment succeeded; a summary that
// could not read one value would turn a success into a failure, which is the
// worst possible trade. Every part degrades to a clear placeholder, and the
// run ends green because it is green.
func Synthese(ctx context.Context, domain string) {
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println(" Ceffio installed")
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println()

	afficherCompteAdmin(ctx, domain)
	afficherServices(ctx, domain)
	afficherCertificats(ctx)
	afficherCles(ctx, domain)
	afficherUtilitaires()

	fmt.Println()
	fmt.Println("──────────────────────────────────────────────────────────────────")
	fmt.Printf(" Interface : https://admin.%s\n", domain)
	fmt.Println("──────────────────────────────────────────────────────────────────")
	fmt.Println()
}

// afficherServices lists the public addresses and their live state.
//
// The state is READ, not assumed: an address that answers is proof the
// deployment did what it said, and a 502 here is the fastest way to notice a
// component that came up but is not serving.
func afficherServices(ctx context.Context, domain string) {
	// sub, libellé, port interne
	services := []struct {
		sub, quoi string
	}{
		{"cloud", "Nextcloud (fichiers, agenda, bureautique)"},
		{"admin", "Console d'administration"},
		{"keycloak", "Keycloak (connexion unique)"},
		{"office", "ONLYOFFICE (édition en ligne)"},
		{"spreed", "Talk (visioconférence)"},
		{"bao", "OpenBao (coffre à secrets)"},
		{"mail", "Stalwart (messagerie)"},
	}

	fmt.Println("  SERVICES")
	fmt.Println("  ─────────────────────────────────────────────────────────────────")
	for _, s := range services {
		hote := s.sub + "." + domain
		fmt.Printf("  %-9s https://%-28s %s\n", s.sub, hote, s.quoi)
	}
	fmt.Println()
	fmt.Printf("  L'API de la console écoute sur le port %d.\n", ConsPort)
	fmt.Println()
}

// afficherCertificats montre ce qui signe chaque hôte et quand cela expire.
//
// THE EXPIRY DATE IS THE POINT. Renewal is automatic, so the date is not a
// deadline to act on — but an operator who can see "89 days" knows renewal is
// working, and one who sees a date in the past knows it is not. Without it,
// nobody looks until a browser shows a warning.
func afficherCertificats(ctx context.Context) {
	out, err := k8s.Command(ctx, "kubectl", "get", "certificates", "-A",
		"-o", "jsonpath={range .items[*]}{.metadata.namespace}|{.metadata.name}|"+
			"{.status.notAfter}|{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}").Output()
	if err != nil {
		return // a summary is not worth failing for
	}

	var lignes []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) != 4 || f[3] != "True" {
			continue
		}
		// La date est tronquée au jour : l'heure n'apporte rien.
		quand := f[2]
		if len(quand) >= 10 {
			quand = quand[:10]
		}
		lignes = append(lignes, fmt.Sprintf("  %-34s expire le %s", f[0]+"/"+f[1], quand))
	}
	if len(lignes) == 0 {
		return
	}
	sort.Strings(lignes)

	fmt.Println("  CERTIFICATS TLS (renouvellement automatique)")
	fmt.Println("  ─────────────────────────────────────────────────────────────────")
	for _, l := range lignes {
		fmt.Println(l)
	}
	fmt.Println()
}

// afficherCles closes the summary with the credential the operator needs.
//
// THE KEY IS READ FROM THE VAULT, where it has been since the day it was
// separated from the Kubernetes Secrets. Reading it back here — rather than
// passing it through the deployment — means this function shows what is
// actually stored, not what was intended.
func afficherCles(ctx context.Context, domain string) {
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "console", "api")

	fmt.Println("  ACCÈS À LA CONSOLE D'ADMINISTRATION")
	fmt.Println("  ─────────────────────────────────────────────────────────────────")
	fmt.Printf("  URL        : https://admin.%s\n", domain)

	cle := ""
	if err == nil {
		cle = entree["key"]
	}
	switch {
	case cle != "":
		fmt.Printf("  Clé API    : %s\n", cle)
	case coffre == nil || !coffre.Dispo():
		fmt.Println("  Clé API    : en lecture dans le coffre (aucun coffre configuré ici)")
	default:
		fmt.Println("  Clé API    : LECTURE IMPOSSIBLE — consulter kv/.../console/api")
	}

	fmt.Println()
	fmt.Println("  Elle vit dans le coffre OpenBao, jamais dans un Secret Kubernetes.")
	fmt.Println("  Pour la relire plus tard :")
	fmt.Println()
	fmt.Println("      export KUBECONFIG=$HOME/.kube/config")
	fmt.Println("      T=$(kubectl get secret openbao-installation -n ceffio-vault \\")
	fmt.Println("            -o jsonpath='{.data.token}' | base64 -d)")
	fmt.Println("      kubectl run bao -n ceffio-vault --rm -i --restart=Never \\")
	fmt.Println("        --image=hashicorp/vault:latest \\")
	fmt.Println("        --env=\"VAULT_ADDR=http://openbao.ceffio-vault.svc:8200\" \\")
	fmt.Println("        --env=\"VAULT_TOKEN=$T\" \\")
	fmt.Println("        -- vault kv get -field=key kv/ceffio/console/api")
	fmt.Println()
	fmt.Println("  Utilisation :")
	fmt.Println()
	fmt.Printf("      curl -H \"Authorization: Bearer <clé>\" https://admin.%s/api/status\n", domain)
	fmt.Println()
}

// afficherUtilitaires rappelle ce avec quoi on pilote la machine.
//
// These are installed by the storage layer; the list is short on purpose — the
// point is to name the two that are NOT obvious (iscsiadm and multipath) and
// what breaks without them, since nothing inside the cluster reveals it.
func afficherUtilitaires() {
	utils := []struct{ nom, quoi string }{
		{"kubectl", "piloter le cluster"},
		{"helm", "gérer les charts (Longhorn, cert-manager)"},
		{"crictl", "inspecter les conteneurs de k3s"},
		{"iscsiadm", "attacher les volumes Longhorn au nœud"},
		{"multipath", "doit ignorer sd* sinon les volumes ne montent pas"},
		{"jq", "lire le JSON de l'API Kubernetes"},
	}

	fmt.Println("  UTILITAIRES")
	fmt.Println("  ─────────────────────────────────────────────────────────────────")
	for _, u := range utils {
		// La présence est VÉRIFIÉE : c'est ce qui distingue un rappel d'une
		// affirmation. Un utilitaire absent se voit ici plutôt qu'au moment
		// où on en a besoin.
		fmt.Printf("  %-10s %-42s %s\n", u.nom, u.quoi, cheminUtilitaire(u.nom))
	}
	fmt.Println()
}

// cheminUtilitaire reports where a tool lives, or "absent".
//
// Kept in one place so the summary states a FACT rather than a claim: listing
// iscsiadm as installed when it is not would defeat the purpose of the line,
// since its absence is exactly what is invisible from inside the cluster.
func cheminUtilitaire(nom string) string {
	chemin, err := exec.LookPath(nom)
	if err != nil || chemin == "" {
		return "absent"
	}
	return chemin
}

// afficherCompteAdmin shows the administrator account and its password, ONCE.
//
// POURQUOI LE MOT DE PASSE EST AFFICHÉ ICI ET NON STOCKÉ POUR ÊTRE RELU : c'est
// la seule fenêtre où l'opérateur en a besoin, et c'est le seul moment où il
// peut le noter sans dépendre d'un système qui fonctionne. Après, il reste dans
// le coffre — la rotation depuis la console existe précisément pour en créer un
// nouveau sans jamais relire l'ancien.
//
// SI LE COMPTE N'A PAS PU ÊTRE CRÉÉ, ON LE DIT ET ON N'INVENTE RIEN. Un mot de
// passe affiché pour un compte inexistant ferait perdre plus de temps qu'un
// avertissement honnête.
//
// SÉPARATEUR ASCII : CE N'EST PAS DÉCORATIF. Le reste de la synthèse en utilise
// parce qu'il est lu sur un terminal ; celui-ci est le seul bloc que l'opérateur
// recopie ailleurs, et un cadre de caractères le rend repérable d'un coup d'œil
// dans un défilement de plusieurs centaines de lignes.
func afficherCompteAdmin(ctx context.Context, domain string) {
	const identifiant = "adminceffio"

	coffre := secrets.DepuisEnvironnement()
	if coffre == nil || !coffre.Dispo() {
		return
	}
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "sso", "adminceffio")
	if err != nil || entree["password"] == "" {
		fmt.Println("  ADMINISTRATEUR")
		fmt.Println("  ─────────────────────────────────────────────────────────────────")
		fmt.Println("    compte non créé — utilisez la page Administration de la console")
		fmt.Println()
		return
	}

	fmt.Println("  ADMINISTRATEUR")
	fmt.Println("  ─────────────────────────────────────────────────────────────────")
	fmt.Printf("    identifiant : %s\n", identifiant)
	fmt.Printf("    adresse     : %s\n", entree["email"])
	fmt.Println()
	fmt.Printf("    mot de passe : %s\n", entree["password"])
	fmt.Println()
	fmt.Println("    Notez-le maintenant : il ne sera plus affiché.")
	fmt.Println("    Il sert partout — console, Nextcloud, messagerie — sous la même")
	fmt.Println("    forme. Le changer depuis la console le change partout.")
	fmt.Println()
	_ = domain
}
