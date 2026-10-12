package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ceffio-suite/ceffio/internal/apps"
	"github.com/ceffio-suite/ceffio/internal/bootstrap"
	"github.com/ceffio-suite/ceffio/internal/cluster"
	"github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/data"
	"github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/platform"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/sso"
	"github.com/ceffio-suite/ceffio/internal/stacks"
	"github.com/ceffio-suite/ceffio/internal/talk"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

type installOptions struct {
	domain          string
	profile         string
	runtime         string
	existingCluster bool
	mail            bool
	office          bool
	monitoring      bool

	// Relais d'expédition sortant. INDISPENSABLE en pratique : le port 25
	// sortant est bloqué chez les FAI grand public (vérifié sur Free), donc
	// Stalwart ne peut pas livrer vers Gmail par lui-même. Le relais authentifié
	// sur 587 contourne ce blocage et endosse le reverse DNS.
	relaisSmtpHote string
	relaisSmtpPort int
	relaisSmtpUser string
	relaisSmtpPass string
}

const devClusterName = "ceffio-dev"

func newInstallCmd() *cobra.Command {
	o := &installOptions{}

	c := &cobra.Command{
		Use:   "install",
		Short: "Installer Ceffio sur une machine ou un cluster Kubernetes",
		Long: `Installe Ceffio de bout en bout : bootstrap Kubernetes (K3s par défaut),
puis déploiement de la plateforme (ingress, TLS, base de données, identité)
et des applications collaboratives.

Exemples :
  ceffio install
  ceffio install --domain company.fr --profile business-50
  ceffio install --runtime rke2
  ceffio install --existing-cluster`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, o)
		},
	}

	f := c.Flags()
	// DÉFAUT DE PRODUCTION : *.ceffio.mandem-it.com est le domaine de reference
	// de l'installation en service (DNS wildcard + certificat + OPNsense câblés).
	// Consigne utilisateur : tout deploiement passe par ce domaine jusqu'a
	// nouvel ordre. Surchargeable avec --domain pour un autre environnement.
	f.StringVar(&o.domain, "domain", "ceffio.mandem-it.com", "Domaine de base (ex. company.fr)")
	f.StringVar(&o.profile, "profile", "small", "Profil de déploiement (small, business-50, business-100, enterprise-ha)")
	f.StringVar(&o.runtime, "runtime", "k3s", "Runtime Kubernetes (k3s, rke2)")
	f.BoolVar(&o.existingCluster, "existing-cluster", false, "Utiliser un cluster Kubernetes existant")
	f.BoolVar(&o.mail, "mail", false, "Activer la messagerie")
	f.BoolVar(&o.office, "office", true, "Activer ONLYOFFICE")
	f.BoolVar(&o.monitoring, "monitoring", true, "Activer l'observabilité")
	// Relais d'expédition. Par défaut : aucun (Stalwart reçoit mais n'envoie
	// pas vers l'extérieur). Le port 25 sortant étant bloqué chez les FAI, ce
	// relais est ce qui rend la messagerie réellement utilisable.
	f.StringVar(&o.relaisSmtpHote, "smtp-relais", "",
		"Relais SMTP sortant (ex. send.one.com) — nécessaire car le port 25 sortant est souvent bloqué")
	f.IntVar(&o.relaisSmtpPort, "smtp-relais-port", 587, "Port du relais SMTP sortant")
	f.StringVar(&o.relaisSmtpUser, "smtp-relais-user", "", "Utilisateur du relais SMTP sortant")
	f.StringVar(&o.relaisSmtpPass, "smtp-relais-pass", "", "Mot de passe du relais SMTP sortant")

	return c
}

func runInstall(cmd *cobra.Command, o *installOptions) error {
	if o.domain == "" {
		return fmt.Errorf("--domain est requis (ex. --domain company.fr)")
	}

	fmt.Println("Ceffio Installer")
	fmt.Println()
	fmt.Printf("Domain:     %s\n", o.domain)
	fmt.Printf("Profile:    %s\n", o.profile)
	fmt.Printf("Runtime:    %s\n", o.runtime)
	fmt.Printf("Mail:       %s\n", yesNo(o.mail))
	fmt.Printf("Office:     %s\n", yesNo(o.office))
	fmt.Printf("Monitoring: %s\n", yesNo(o.monitoring))
	fmt.Println()

	ctx := cmd.Context()

	// 1. Détection + validation matérielle/OS.
	hw := bootstrap.Detect()
	if err := bootstrap.Validate(hw.OS, hw.Arch); err != nil {
		return err
	}
	mem := "n/a"
	if hw.MemoryTotalMB > 0 {
		mem = fmt.Sprintf("%d MB", hw.MemoryTotalMB)
	}
	fmt.Printf("Machine:    %s/%s · %d vCPU · RAM %s\n", hw.OS, hw.Arch, hw.CPUs, mem)

	// 2. Résolution du runtime.
	rt, err := resolveRuntime(o, hw.OS)
	if err != nil {
		return err
	}

	// 3. Provisionnement du cluster Kubernetes.
	fmt.Printf("\nProvisioning cluster %q (%s)...\n", devClusterName, rt)
	if _, err := cluster.Provision(ctx, rt, devClusterName); err != nil {
		return err
	}

	// 4. Attente + check de santé.
	// 5 min : sur une VM à froid, k3s doit démarrer son API, tirer les images
	// système (Traefik, CoreDNS, local-path) et faire passer le nœud Ready.
	// 120 s échouait systématiquement au premier boot (nœud Ready vers ~3 min).
	if err := cluster.WaitReady(ctx, 5*time.Minute); err != nil {
		return err
	}
	nodes, err := cluster.Health(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("\n✓ Cluster %q prêt (%d nœud(s))\n", devClusterName, len(nodes))
	for _, n := range nodes {
		fmt.Printf("  ✓ node/%s Ready\n", n)
	}

	// 5. Déploiement de la plateforme (Phase 2).
	//
	// Parallélisation : on ne sérialise QUE les dépendances réelles.
	//   platform (namespaces, cert-manager, issuers) et data (PostgreSQL, Redis)
	//   ne dépendent pas l'un de l'autre → menés en parallèle.
	//   identity dépend de data (Keycloak a besoin de sa base) → après.
	fmt.Println("\n∙ phases 2-3 en parallèle (plateforme ‖ données)")
	if err := runParallel(ctx,
		namedTask{"plateforme (Phase 2)", func(ctx context.Context) error { return platform.Deploy(ctx) }},
		namedTask{"données (Phase 3)", func(ctx context.Context) error { return data.Deploy(ctx) }},
	); err != nil {
		return err
	}

	// 6. Coffre de secrets (OpenBao).
	//
	// PLACÉ ICI, ET PAS AILLEURS : avant l'identité et avant toutes les couches
	// applicatives, parce que c'est à partir de là que les composants peuvent
	// LIRE leurs secrets au lieu de les inventer. S'il était déployé plus tard,
	// chaque composant aurait déjà généré les siens et il faudrait les migrer
	// après coup — c'est-à-dire refaire le travail.
	//
	// APRÈS la plateforme, en revanche : le coffre n'a besoin ni de cert-manager
	// ni de PostgreSQL. L'ordre est donc : plateforme → coffre → tout le reste.
	//
	// Rien n'est obligatoire ici : si le coffre échoue, poursuivre avec les
	// Secrets Kubernetes est le comportement attendu (voir internal/secrets).
	//
	// ON PUBLIE L'ADRESSE ET LE JETON DANS L'ENVIRONNEMENT : c'est ainsi que les
	// modules suivants les trouveront, via secrets.DepuisEnvironnement(). Sans
	// cette publication, le coffre serait déployé mais personne ne lirait
	// dedans — un coffre plein que les composants continueraient d'ignorer.
	//
	// Le nom est coffreBao et non coffre : la suite du fichier nomme déjà
	// « coffre » la configuration lue depuis l'environnement.
	coffreBao := vault.Deploy(ctx, o.domain)
	if coffreBao.Pret {
		os.Setenv("BAO_ADDR", coffreBao.Adresse)
		os.Setenv("BAO_TOKEN", coffreBao.Jeton)
		os.Setenv("BAO_MOTEUR", "kv")
		fmt.Printf("∙ coffre publié pour la suite : %s (jeton non affiché)\n", coffreBao.Adresse)
	} else {
		fmt.Println("∙ coffre indisponible : les secrets resteront dans Kubernetes (comportement prévu)")
	}

	// 7. Identité / SSO (Phase 4) — dépend de la base PostgreSQL.
	if err := identity.Deploy(ctx); err != nil {
		return err
	}

	// 8-10. Couches applicatives : fichiers, chat et visio sont INDÉPENDANTES
	// les unes des autres — elles ne dépendent que de la plateforme (namespaces,
	// ingress) et de l'identité (hostAliases → Traefik, CA). On les déploie donc
	// en parallèle, ce qui divise le temps de cette étape par ~3.
	// Sont EXCLUES du parallèle (dépendances réelles, vérifiées dans le code) :
	//   - office : s'active via « occ » DANS Nextcloud → exige Nextcloud Ready ;
	//   - sso/AdoptURLs : écrivent dans Keycloak, Nextcloud et Synapse → après tous.
	fmt.Println("\n∙ phases 5/7/10 en parallèle (fichiers ‖ chat ‖ visio)")
	// Chat et visio sont désormais fournis par Nextcloud Talk (app Nextcloud),
	// déployée avec la couche fichiers : plus de Synapse/Element ni de Jitsi.
	appTasks := []namedTask{
		{"fichiers (Phase 5)", func(ctx context.Context) error { return files.Deploy(ctx) }},
	}
	if err := runParallel(ctx, appTasks...); err != nil {
		return err
	}

	// 11. Office (Phase 6) — APRÈS fichiers : le connecteur ONLYOFFICE est
	// configuré via « occ » dans le pod Nextcloud (il doit être Ready).
	if err := office.Deploy(ctx); err != nil {
		return err
	}

	// 12. SSO (login unique du MVB) : clients OIDC Keycloak + Nextcloud + Synapse.
	if err := sso.EnsureOIDCClients(ctx, o.domain); err != nil {
		return err
	}
	// Retrait de l'ancienne pile (Matrix + Jitsi) : nettoyage idempotent des
	// vestiges sur un cluster existant. Talk remplace chat ET visio.
	if err := stacks.RetirerMatrixEtJitsi(ctx, o.domain); err != nil {
		return err
	}
	// Talk + High Performance Backend : messagerie ET visioconférence, dans
	// Nextcloud. Déployé après le retrait, pour libérer d'abord les ressources.
	if err := talk.Deploy(ctx); err != nil {
		return err
	}
	// Applications Nextcloud (Phase 12) : les apps de collaboration controlees
	// (licence libre, version stable). Sans ce module, une installation neuve
	// n'aurait AUCUNE de ces apps — elles ne vivraient que sur la machine ou
	// elles ont ete installees a la main.
	if err := apps.Deploy(ctx); err != nil {
		return err
	}

	// 12bis. Messagerie (Phase 13) : Stalwart. Nextcloud fournit l'interface
	// (app Mail) mais pas le serveur de courrier. Le relais d'expédition est
	// INDISPENSABLE ici : le port 25 sortant est bloqué chez le FAI (vérifié),
	// donc Stalwart ne peut pas livrer vers Gmail par lui-même.
	if err := mail.Deploy(ctx, o.domain, o.relaisSmtpHote, o.relaisSmtpPort,
		o.relaisSmtpUser, o.relaisSmtpPass); err != nil {
		return err
	}

	// 12ter. Authentification unique de Stalwart. Le serveur de messagerie a sa
	// propre interface d'administration, et elle doit déléguer à Keycloak comme
	// le reste de la plateforme. Ce bloc rejoue exactement la configuration qui
	// a été établie à la main : chaque ligne correspond à un blocage réel, et
	// notamment aux quatre tables de rôles de l'objet Authentication, sans
	// lesquelles une connexion pourtant réussie se solde par un « 403 ».
	//
	// Le domaine des ADRESSES est le domaine de la plateforme, pas l'hôte web
	// « mail.<domaine> » : ce sont deux choses distinctes, et les confondre
	// placerait les enregistrements MX au mauvais endroit.
	if err := mail.ConfigurerSSO(ctx, o.domain, mail.SSO{
		Hote:         mail.DomaineMessagerie(o.domain),
		Issuer:       "https://keycloak." + o.domain + "/realms/ceffio",
		ClientID:     "stalwart-webui",
		DomaineAdmin: "ceffio.local",
		CompteAdmin:  "adminceffio",
	}); err != nil {
		return err
	}

	// Coffre de secrets : OpenBao s'il est configure, Kubernetes sinon.
	// On ne fait que DIRE lequel est utilise — c'est une information
	// d'exploitation, et c'est aussi la preuve que le coffre reste optionnel :
	// aucun deploiement ne doit echouer parce qu'il est absent.
	coffre := secrets.DepuisEnvironnement()
	fmt.Println("\nCoffre de secrets : " + coffre.Description())
	if err := files.ConfigureOIDC(ctx, o.domain); err != nil {
		return err
	}

	fmt.Println("\n✓ SSO OIDC configuré (login unique Keycloak sur Nextcloud).")

	// 13. Ingress / TLS réel (Phase 9).
	if err := ingress.Deploy(ctx, o.domain); err != nil {
		return err
	}

	// 14. Adoption des URLs publiques dans les apps (homeserver, redirects SSO, https).
	if err := ingress.AdoptURLs(ctx, o.domain); err != nil {
		return err
	}

	// 15. Console d'administration (dashboard + utilisateurs SSO).
	if err := console.Deploy(ctx, o.domain); err != nil {
		return err
	}

	// La visioconférence a déjà été déployée dans le lot parallèle ci-dessus
	// (Phase 10, avec fichiers ‖ chat). Ne PAS la rejouer ici : l'appel
	// dupliqué ne faisait que reconfirmer ce qui était fait, en payant une
	// seconde fois l'attente `kubectl rollout status` (240 s au pire) pour un
	// résultat identique. Un déploiement deux fois plus long sans bénéfice.
	return nil
}

func resolveRuntime(o *installOptions, osName string) (cluster.Runtime, error) {
	if o.existingCluster {
		return "", fmt.Errorf("--existing-cluster : pas encore implémenté (BYO Kubernetes)")
	}
	switch o.runtime {
	case "k3s":
		if osName == "darwin" {
			return cluster.RuntimeDev, nil // macOS → k3d (boucle de dev)
		}
		return cluster.RuntimeK3s, nil // Linux → vrai K3s
	case "rke2":
		return "", fmt.Errorf("runtime rke2 : pas encore implémenté (Phase 17)")
	default:
		return "", fmt.Errorf("runtime inconnu %q", o.runtime)
	}
}
