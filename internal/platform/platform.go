// Package platform orchestre le déploiement de la plateforme de base sur le
// cluster : namespaces (chart umbrella), cert-manager et les issuers TLS.
package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	// certManagerChartVersion est pinnée, pas "latest" (principes du doc §111).
	certManagerChartVersion = "v1.21.1"
	chartPath               = "charts/ceffio"
)

// Deploy installe la plateforme de base (Phase 2) sur le cluster courant,
// de façon idempotente :
//  1. namespaces via le chart umbrella ceffio
//  2. cert-manager (chart officiel jetstack)
//  3. issuers TLS (self-signed, pour le développement)
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de la plateforme (Phase 2)...")

	if err := installUmbrella(ctx); err != nil {
		return err
	}
	if err := installCertManager(ctx); err != nil {
		return err
	}
	if err := waitCertManagerReady(ctx); err != nil {
		return err
	}
	if err := applyClusterIssuers(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Plateforme déployée")
	return nil
}

func installUmbrella(ctx context.Context) error {
	fmt.Println("∙ namespaces (chart ceffio)")
	cmd := exec.CommandContext(ctx, "helm", "upgrade", "--install", "ceffio",
		chartPath,
		"--namespace", "ceffio-system", "--create-namespace")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func installCertManager(ctx context.Context) error {
	fmt.Printf("∙ cert-manager %s\n", certManagerChartVersion)
	if err := ensureRepo(ctx, "jetstack", "https://charts.jetstack.io"); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "helm", "upgrade", "--install", "cert-manager",
		"jetstack/cert-manager",
		"--namespace", "cert-manager", "--create-namespace",
		"--set", "crds.enabled=true",
		"--version", certManagerChartVersion)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitCertManagerReady(ctx context.Context) error {
	fmt.Println("∙ attente cert-manager Ready...")
	for _, d := range []string{"cert-manager", "cert-manager-cainjector", "cert-manager-webhook"} {
		cmd := exec.CommandContext(ctx, "kubectl", "rollout", "status",
			"deployment/"+d, "-n", "cert-manager", "--timeout=180s")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s pas prêt: %w", d, err)
		}
	}
	return nil
}

func applyClusterIssuers(ctx context.Context) error {
	fmt.Println("∙ ClusterIssuer ceffio-selfsigned (dev)")
	issuer := `apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ceffio-selfsigned
spec:
  selfSigned: {}
`
	return apply(ctx, issuer)
}

func ensureRepo(ctx context.Context, name, url string) error {
	cmd := exec.CommandContext(ctx, "helm", "repo", "add", name, url)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already exists") {
		return fmt.Errorf("helm repo add %s: %w: %s", name, err, out)
	}
	return nil
}

func apply(ctx context.Context, manifest string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
