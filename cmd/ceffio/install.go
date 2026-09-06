package main

import (
	"fmt"
	"time"

	"github.com/ceffio-suite/ceffio/internal/bootstrap"
	"github.com/ceffio-suite/ceffio/internal/chat"
	"github.com/ceffio-suite/ceffio/internal/cluster"
	"github.com/ceffio-suite/ceffio/internal/data"
	"github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/platform"
	"github.com/ceffio-suite/ceffio/internal/sso"
	"github.com/spf13/cobra"
)

type installOptions struct {
	domain          string
	profile         string
	runtime         string
	existingCluster bool
	mail            bool
	office          bool
	video           bool
	monitoring      bool
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
	f.StringVar(&o.domain, "domain", "", "Domaine de base (ex. company.fr)")
	f.StringVar(&o.profile, "profile", "small", "Profil de déploiement (small, business-50, business-100, enterprise-ha)")
	f.StringVar(&o.runtime, "runtime", "k3s", "Runtime Kubernetes (k3s, rke2)")
	f.BoolVar(&o.existingCluster, "existing-cluster", false, "Utiliser un cluster Kubernetes existant")
	f.BoolVar(&o.mail, "mail", false, "Activer la messagerie")
	f.BoolVar(&o.office, "office", true, "Activer ONLYOFFICE")
	f.BoolVar(&o.video, "video", false, "Activer la visioconférence (Jitsi)")
	f.BoolVar(&o.monitoring, "monitoring", true, "Activer l'observabilité")

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
	fmt.Printf("Video:      %s\n", yesNo(o.video))
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
	if err := cluster.WaitReady(ctx, 120*time.Second); err != nil {
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
	if err := platform.Deploy(ctx); err != nil {
		return err
	}

	// 6. Couche données (Phase 3).
	if err := data.Deploy(ctx); err != nil {
		return err
	}

	// 7. Identité / SSO (Phase 4).
	if err := identity.Deploy(ctx); err != nil {
		return err
	}

	// 8. Fichiers (Phase 5).
	if err := files.Deploy(ctx); err != nil {
		return err
	}

	// 9. Office (Phase 6).
	if err := office.Deploy(ctx); err != nil {
		return err
	}

	// 10. Chat (Phase 7).
	if err := chat.Deploy(ctx); err != nil {
		return err
	}

	// 11. SSO (login unique du MVB) : clients OIDC Keycloak + Nextcloud + Synapse.
	if err := sso.EnsureOIDCClients(ctx); err != nil {
		return err
	}
	if err := files.ConfigureOIDC(ctx); err != nil {
		return err
	}
	if err := chat.ConfigureOIDC(ctx); err != nil {
		return err
	}

	fmt.Println("\n✓ SSO OIDC configuré (login unique Keycloak sur Nextcloud + Element).")

	// 12. Ingress / TLS réel (Phase 9).
	if err := ingress.Deploy(ctx, o.domain); err != nil {
		return err
	}
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
