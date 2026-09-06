package main

import (
	"fmt"

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
			return runInstall(o)
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

func runInstall(o *installOptions) error {
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

	// TODO(phase-1) : bootstrap Kubernetes + déploiement Helm réel.
	fmt.Println("Le bootstrap Kubernetes et le déploiement Helm arrivent en Phase 1-2.")
	return nil
}
