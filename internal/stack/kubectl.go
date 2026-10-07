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

// kubectlJSON exécute kubectl et renvoie sa sortie JSON.
//
// Passe par internal/k8s pour l'environnement : le kubectl de K3s est un symlink
// vers le binaire k3s, qui lit /etc/rancher/k3s/k3s.yaml en dur avant toute
// résolution standard — d'où la nécessité de forcer KUBECONFIG explicitement.
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

// humanError transforme la sortie de kubectl en une phrase exploitable.
//
// kubectl écrit sur stderr des messages internes très verbeux (horodatage,
// numéro de ligne, chemin de fichier Go) suivis de l'erreur réelle. Recopiés
// tels quels dans un diagnostic, ils noient l'information utile. On garde donc
// la cause en langage clair, et on résume le reste.
func humanError(stderr string, err error) string {
	low := strings.ToLower(stderr)
	switch {
	case strings.Contains(low, "connection refused"):
		return "Aucun serveur Kubernetes ne répond à l'adresse du kubeconfig."
	case strings.Contains(low, "permission denied") && strings.Contains(low, "k3s.yaml"):
		return "Le kubeconfig K3s (/etc/rancher/k3s/k3s.yaml) n'est pas lisible par cet utilisateur (root, 0600)."
	case strings.Contains(low, "no such file") && strings.Contains(low, "config"):
		return "Kubeconfig introuvable."
	case strings.Contains(low, "unauthorized"), strings.Contains(low, "forbidden"):
		return "Le cluster refuse la requête (droits insuffisants)."
	case strings.Contains(low, "no route to host"), strings.Contains(low, "i/o timeout"):
		return "Le serveur Kubernetes est injoignable sur le réseau."
	case strings.Contains(low, "the server could not find the requested resource"):
		return "Ressource absente du cluster (cert-manager ou l'application ne sont pas installés)."
	}
	// Sinon : première ligne qui ressemble à une erreur, sans le verbiage kubectl.
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

// findKubectl localise kubectl : PATH, puis les emplacements connus.
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
	return "", fmt.Errorf("kubectl introuvable — Ceffio doit être installé sur cette machine, ou kubectl présent dans le PATH")
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// deriveDomain déduit le domaine de base depuis un hôte d'ingress.
// « cloud.demo.local » → « demo.local » : on retire le premier label.
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
