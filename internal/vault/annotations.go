package vault

import (
	"fmt"
	"strings"
)

// Ce fichier produit les annotations qui font poser les secrets par l'injecteur
// d'OpenBao.
//
// POURQUOI L'INJECTEUR PLUTÔT QU'UN INIT-CONTAINER ÉCRIT À LA MAIN. Un
// init-container maison oblige à composer soi-même le HCL de l'agent, la ConfigMap
// qui le porte, le volume partagé, ses montages, et à régler l'utilisateur et le
// groupe — sans quoi le fichier rendu est illisible par le conteneur applicatif, et
// le pod boucle sur « Permission denied ». L'injecteur fait tout cela depuis ces
// quelques annotations : il pose l'agent avec le bon couple utilisateur/groupe, et
// garde les secrets dans un volume EN MÉMOIRE (medium: Memory), jamais sur disque.
// Mesuré sur deux charges : quarante lignes de manifeste remplacées par neuf
// annotations.
//
// CE QUI RESTE À NOTRE CHARGE, et c'est tout :
//   - le ServiceAccount — c'est lui que le rôle du coffre désigne pour authentifier ;
//   - la politique et le rôle, posés une fois par la commande « vault » ;
//   - la ligne qui charge le fichier rendu au démarrage du service :
//     « set -a; . /secrets/env; set +a » — inévitable, ni Stalwart ni ONLYOFFICE ne
//     lisent un fichier d'eux-mêmes.

// AnnotationsAgent rend le bloc YAML à insérer dans les annotations du gabarit de
// pod. indent est l'indentation, en espaces, des lignes produites : elle doit
// correspondre à celle des autres annotations de ce pod.
func AnnotationsAgent(indent int, role, chemin, gabarit string) string {
	marge := strings.Repeat(" ", indent)
	interne := strings.Repeat(" ", indent+2)

	var b strings.Builder
	for _, l := range [][2]string{
		{"vault.hashicorp.com/agent-inject", "true"},
		{"vault.hashicorp.com/role", role},
		// MODE INIT-CONTAINER SEUL : l'agent rend les secrets puis s'arrête, et
		// aucun sidecar ne reste à tourner. C'est le motif qui correspond à ces
		// services, qui lisent leurs variables une fois au démarrage.
		{"vault.hashicorp.com/agent-pre-populate-only", "true"},
		{"vault.hashicorp.com/secret-volume-path", "/secrets"},
		{"vault.hashicorp.com/agent-inject-secret-env", chemin},
		{"vault.hashicorp.com/agent-inject-perms-env", "0644"},
		// ÉCHEC BRUYANT : une clé absente fait échouer le rendu au lieu d'écrire
		// une valeur vide. Un secret vide est pire qu'un pod qui ne démarre pas.
		{"vault.hashicorp.com/error-on-missing-key-env", "true"},
	} {
		fmt.Fprintf(&b, "%s%s: %q\n", marge, l[0], l[1])
	}

	// Le gabarit part en bloc littéral : il contient des sauts de ligne.
	fmt.Fprintf(&b, "%svault.hashicorp.com/agent-inject-template-env: |\n", marge)
	for _, l := range strings.Split(strings.TrimRight(gabarit, "\n"), "\n") {
		fmt.Fprintf(&b, "%s%s\n", interne, l)
	}
	return b.String()
}

// ChampCoffre rend l'accès à un champ d'une entrée KV versionnée.
//
// LE TIRET COMPTE : « .Data.data.hash-key » n'est PAS une expression valide en
// syntaxe Go — le tiret y est un opérateur —, et l'erreur rendue par l'agent parle
// de « gabarit invalide » sans jamais mentionner le tiret. Passer par « index »
// règle le cas, et le point aussi, par précaution.
func ChampCoffre(champ string) string {
	if strings.ContainsAny(champ, "-.") {
		return fmt.Sprintf("{{ index .Data.data %q }}", champ)
	}
	return "{{ .Data.data." + champ + " }}"
}

// GabaritExports rend un gabarit qui écrit des affectations shell, chargeables par
// « set -a; . /secrets/env; set +a » — la façon documentée de servir une
// application qui n'attend que des variables d'environnement.
//
// Chaque paire est {nom de la variable shell, valeur}. La valeur est le plus souvent
// un ChampCoffre, mais elle peut être composée — « admin: » suivi du mot de passe,
// par exemple, car Stalwart attend « utilisateur:motdepasse » dans UNE SEULE chaîne.
func GabaritExports(chemin string, paires ...[2]string) string {
	var b strings.Builder
	b.WriteString("{{- with secret \"" + chemin + "\" -}}\n")
	for _, p := range paires {
		b.WriteString("export " + p[0] + "='" + p[1] + "'\n")
	}
	b.WriteString("{{- end -}}")
	return b.String()
}
