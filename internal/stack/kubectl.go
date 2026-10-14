// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package stack

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// kubectlJSON runs kubectl and returns its JSON output.
//
// Goes through internal/k8s for the environment: K3s's kubectl is a symlink
// to the k3s binary, which reads /etc/rancher/k3s/k3s.yaml in hardcoded
// fashion before any standard resolution — hence the need to force
// KUBECONFIG explicitly.
func kubectlJSON(ctx context.Context, args ...string) ([]byte, error) {
	kubectl, err := findKubectl()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := k8s.Command(ctx, kubectl, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				msg = strings.TrimSpace(string(ee.Stderr))
			}
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", humanError(msg, err))
	}
	return out, nil
}

// humanError turns kubectl's output into an actionable sentence.
//
// kubectl writes very verbose internal messages to stderr (timestamp, line
// number, Go file path) followed by the actual error. Copied verbatim into a
// diagnostic, they drown the useful information. We therefore keep the cause
// in plain language, and summarize the rest.
func humanError(stderr string, err error) string {
	low := strings.ToLower(stderr)
	switch {
	case strings.Contains(low, "connection refused"):
		return "No Kubernetes server is responding at the kubeconfig address."
	case strings.Contains(low, "permission denied") && strings.Contains(low, "k3s.yaml"):
		return "The K3s kubeconfig (/etc/rancher/k3s/k3s.yaml) is not readable by this user (root, 0600)."
	case strings.Contains(low, "no such file") && strings.Contains(low, "config"):
		return "Kubeconfig not found."
	case strings.Contains(low, "unauthorized"), strings.Contains(low, "forbidden"):
		return "The cluster refuses the request (insufficient permissions)."
	case strings.Contains(low, "no route to host"), strings.Contains(low, "i/o timeout"):
		return "The Kubernetes server is unreachable on the network."
	case strings.Contains(low, "the server could not find the requested resource"):
		return "Resource missing from the cluster (cert-manager or the application is not installed)."
	}
	// Otherwise: the first line that looks like an error, without the
	// kubectl verbosity.
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "E") && strings.Contains(l, "]") {
			if i := strings.Index(l, "err="); i > 0 {
				l = l[i+4:]
			}
		}
		if len(l) > 300 {
			l = l[:300] + "…"
		}
		return l
	}
	return oneLine(err.Error())
}

// findKubectl locates kubectl: PATH first, then the known locations.
func findKubectl() (string, error) {
	if p, err := exec.LookPath("kubectl"); err == nil {
		return p, nil
	}
	for _, p := range []string{
		"/usr/local/bin/kubectl",
		"/usr/bin/kubectl",
		"/snap/bin/kubectl",
		"/var/lib/rancher/k3s/bin/kubectl",
	} {
		if fileExists(p) {
			return p, nil
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		if p := filepath.Join(home, ".k3d", "bin", "kubectl"); fileExists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("kubectl not found — Ceffio must be installed on this machine, or kubectl must be in the PATH")
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// deriveDomain infers the base domain from an ingress host.
// "cloud.demo.local" → "demo.local": we drop the first label.
func deriveDomain(host string) string {
	parts := strings.SplitN(host, ".", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return strings.TrimSpace(s)
}
