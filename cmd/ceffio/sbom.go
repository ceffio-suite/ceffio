// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/sbom"
	"github.com/ceffio-suite/ceffio/internal/version"
)

func newSBOMCmd() *cobra.Command {
	var sortie string
	var avecCluster bool

	c := &cobra.Command{
		Use:   "sbom",
		Short: "What an installation runs, as a CycloneDX document",
		Long: `Writes the software bill of materials of an installation.

The document lists the ceffio binary (version, commit, date) and every component
of the version registry: name, version, image with its digest, role, licence and
the module that deploys it.

With --cluster, the registry is compared with the images actually running: an
image that runs and the registry does not describe, a component running with a
different digest, and a component the registry expects but that runs nowhere.
The exit code is non-zero when the comparison finds a difference.

WHAT THE DOCUMENT DOES NOT CONTAIN: the internal dependencies of the third-party
images. Their SBOM belongs to their publisher; guessing one here would be a guess
presented as a proof.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			doc := sbom.Construire(version.Registry)
			// The platform runs here too, and the document must say so — but without
			// claiming a pin Ceffio does not hold.
			sbom.AjouteLaPlateforme(&doc, version.Plateforme)
			sbom.AjouteLeBinaire(&doc)
			doc.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)

			var ecarts []sbom.Ecart
			if avecCluster {
				cli, err := k8sapi.Nouveau()
				if err != nil {
					return fmt.Errorf("Kubernetes client: %w", err)
				}
				pods, err := podsDesNamespaces(c.Context(), cli)
				if err != nil {
					return err
				}
				ecarts = sbom.Comparer(doc, pods, moduleAttendu)
			}

			var flux io.Writer = os.Stdout
			if sortie != "" {
				f, err := os.Create(sortie)
				if err != nil {
					return err
				}
				defer f.Close()
				flux = f
			}
			encodeur := json.NewEncoder(flux)
			encodeur.SetIndent("", "  ")
			if err := encodeur.Encode(doc); err != nil {
				return err
			}
			if sortie != "" {
				fmt.Fprintf(os.Stderr, "SBOM written to %s (%s)\n", sortie, sbom.Decrit(doc))
			}

			if !avecCluster {
				return nil
			}
			if len(ecarts) == 0 {
				fmt.Fprintln(os.Stderr, "The cluster matches the registry.")
				return nil
			}
			fmt.Fprintf(os.Stderr, "\n%d difference(s) between the registry and the cluster:\n\n", len(ecarts))
			for _, e := range ecarts {
				fmt.Fprintln(os.Stderr, "  "+e.String())
			}
			fmt.Fprintln(os.Stderr)
			return fmt.Errorf("%d difference(s) with the registry", len(ecarts))
		},
	}

	c.Flags().StringVarP(&sortie, "output", "o", "", "write the document to this file instead of the standard output")
	c.Flags().BoolVar(&avecCluster, "cluster", false, "compare the registry with the images actually running")
	return c
}

// podsDesNamespaces reads every pod of the namespaces Ceffio manages.
//
// BY THE API, NOT BY `kubectl get pods` IN TEXT: the text output is a format
// that changes between versions, and parsing it is how a diagnostic tool ends up
// lying after an upgrade.
func podsDesNamespaces(ctx context.Context, cli *k8sapi.Client) ([]corev1.Pod, error) {
	ks := cli.Kubernetes()
	ns, err := ks.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	var pods []corev1.Pod
	for _, n := range ns.Items {
		if !namespaceSuivi(n.Name) {
			continue
		}
		l, err := ks.CoreV1().Pods(n.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing pods in %s: %w", n.Name, err)
		}
		pods = append(pods, l.Items...)
	}
	return pods, nil
}

// namespaceSuivi says which namespaces this command looks at. The list is
// explicit: scanning everything would report the CNI, the metrics server and
// kube-system's pods as "not in the registry", which nobody asked for.
func namespaceSuivi(nom string) bool {
	if strings.HasPrefix(nom, "ceffio-") {
		return true
	}
	switch nom {
	case "longhorn-system", "cert-manager", "cnpg-system":
		return true
	}
	return false
}

// moduleAttendu answers whether the module that deploys a component is part of
// what this installation is expected to run.
//
// A CORE MODULE RUNS ON EVERY INSTALLATION: its absence from the cluster is a
// difference. An OPTIONAL module that is not installed is the normal state: the
// document says installed=false, and nothing is reported as an anomaly.
//
// THE PACKAGE PATH IS MATCHED ON ITS LAST ELEMENT, hyphen-insensitive
// ("internal/modules/longhornui" ↔ "longhorn-ui"): a second table of aliases
// would drift from the first.
func moduleAttendu(cheminPaquet string) bool {
	court := cheminPaquet
	if i := strings.LastIndex(court, "/"); i >= 0 {
		court = court[i+1:]
	}
	court = normaliser(court)
	for _, m := range module.All() {
		info := m.Info()
		if normaliser(info.ID) != court {
			continue
		}
		return info.Kind == module.Core || info.Default
	}
	// A MODULE THE REGISTRY DOES NOT KNOW IS NOT "EXPECTED": reporting its
	// absence would invent an expectation nobody expressed.
	return false
}

func normaliser(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
