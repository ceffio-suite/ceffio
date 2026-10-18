// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package platform orchestrates the deployment of the base platform on the
// cluster: namespaces (umbrella chart), cert-manager and the TLS issuers.
package platform

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/charts"
	"github.com/ceffio-suite/ceffio/internal/k8s"
)

const (
	// certManagerChartVersion is pinned, not "latest" (doc principles §111).
	certManagerChartVersion = "v1.21.1"
)

// Deploy installs the base platform (Phase 2) on the current cluster,
// idempotently:
//  1. namespaces via the ceffio umbrella chart
//  2. cert-manager (official jetstack chart)
//  3. TLS issuers (self-signed, for development)
func Deploy(ctx context.Context) error {
	fmt.Println("\nDeploying the platform (Phase 2)...")

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

	fmt.Println("✓ Platform deployed")
	return nil
}

func installUmbrella(ctx context.Context) error {
	fmt.Println("∙ namespaces (embedded ceffio chart)")
	chart, err := embeddedChart(ctx)
	if err != nil {
		return err
	}

	// ADOPT THE NAMESPACES THE CHART KNOWS BUT DOES NOT YET OWN.
	//
	// ceffio-vault was created outside the chart: it existed only because the
	// OpenBao Helm release used --create-namespace. Helm refuses to take over a
	// resource it does not own, and the upgrade fails with:
	//
	//   UPGRADE FAILED: Namespace "ceffio-vault" exists and cannot be imported
	//   into the current release: invalid ownership metadata
	//
	// The remedy is the same thing Helm would have written itself: the ownership
	// labels and annotations. Doing it here, before the upgrade, means an
	// EXISTING installation is repaired by the normal `ceffio install` — no
	// manual kubectl, and no need to reinstall to pick up the namespace list.
	//
	// Absence is not an error: on a fresh cluster the namespace does not exist
	// yet, and the chart creates it properly.
	if err := adopterNamespaces(ctx); err != nil {
		return err
	}

	cmd := k8s.Command(ctx, "helm", "upgrade", "--install", "ceffio",
		chart,
		"--namespace", "ceffio-system", "--create-namespace")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// adopterNamespaces gives the chart's namespaces the ownership metadata Helm
// requires, when they already exist without it.
func adopterNamespaces(ctx context.Context) error {
	// The release name and namespace must match the helm upgrade above.
	const (
		release   = "ceffio"
		relNS     = "ceffio-system"
		managedBy = "Helm"
	)
	for _, ns := range []string{"ceffio-vault"} {
		// Only act if it exists: --ignore-not-found makes the check a no-op
		// otherwise, and we must not create it here (the chart does that).
		verif := k8s.Command(ctx, "kubectl", "get", "namespace", ns,
			"--ignore-not-found", "-o", "name")
		out, err := verif.Output()
		if err != nil {
			return fmt.Errorf("checking namespace %s: %w", ns, err)
		}
		if strings.TrimSpace(string(out)) == "" {
			continue // absent: the chart will create it
		}

		lab := "app.kubernetes.io/managed-by=" + managedBy
		ann := "meta.helm.sh/release-name=" + release
		annNS := "meta.helm.sh/release-namespace=" + relNS
		cmd := k8s.Command(ctx, "kubectl", "label", "namespace", ns,
			lab, "--overwrite")
		if o, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("labelling namespace %s: %w: %s", ns, err, o)
		}
		cmd = k8s.Command(ctx, "kubectl", "annotate", "namespace", ns,
			ann, annNS, "--overwrite")
		if o, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("annotating namespace %s: %w: %s", ns, err, o)
		}
		fmt.Printf("  ∙ namespace %s adopted by the Helm release \"%s\"\n", ns, release)
	}
	return nil
}

// embeddedChart extracts the "ceffio" chart from the embedded FS to a
// temporary folder and returns its path. Keeps the deployment self-contained.
func embeddedChart(ctx context.Context) (string, error) {
	dir, err := os.MkdirTemp("", "ceffio-charts-*")
	if err != nil {
		return "", err
	}
	err = fs.WalkDir(charts.FS, "ceffio", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dir, p)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := fs.ReadFile(charts.FS, p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ceffio"), nil
}

func installCertManager(ctx context.Context) error {
	fmt.Printf("∙ cert-manager %s\n", certManagerChartVersion)
	if err := ensureRepo(ctx, "jetstack", "https://charts.jetstack.io"); err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "helm", "upgrade", "--install", "cert-manager",
		"jetstack/cert-manager",
		"--namespace", "cert-manager", "--create-namespace",
		"--set", "crds.enabled=true",
		"--timeout", "15m",
		"--version", certManagerChartVersion)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitCertManagerReady(ctx context.Context) error {
	fmt.Println("∙ waiting for cert-manager Ready...")
	for _, d := range []string{"cert-manager", "cert-manager-cainjector", "cert-manager-webhook"} {
		cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
			"deployment/"+d, "-n", "cert-manager", "--timeout=180s")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s not ready: %w", d, err)
		}
	}
	return nil
}

// applyClusterIssuers creates the self-signed ClusterIssuer that BOOTSTRAPS
// the internal trust chain.
//
// THIS IS NOT A DEVELOPMENT CRUTCH, and the message used to say so wrongly.
//
//	∙ ClusterIssuer ceffio-selfsigned (dev)     ← the old message
//
// That « (dev) » suggested a degraded mode. Verified by reading on: this
// issuer is a MANDATORY LINK. It signs the certificate of the internal CA
// (ceffio-ca), which in turn becomes the ceffio-ca-issuer issuer — and
// that one signs the certificates of private domains and internal
// services. Without it, no ceffio-ca, hence no internal authority at all,
// even on a fully public platform.
//
// It coexists with the Let's Encrypt issuers, which sign the public
// domains. The two chains live together: that is deliberate, because a
// public domain and an internal name are not validated the same way, and
// a platform never has one without the other (spreed.<domain> is public,
// the .svc services are internal).
//
// THE MESSAGE NOW SAYS WHAT THE THING IS: a bootstrap, not a mode.
func applyClusterIssuers(ctx context.Context) error {
	fmt.Println("∙ internal trust anchor (ClusterIssuer ceffio-selfsigned → ceffio-ca)")
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
	cmd := k8s.Command(ctx, "helm", "repo", "add", name, url)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already exists") {
		return fmt.Errorf("helm repo add %s: %w: %s", name, err, out)
	}
	return nil
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
