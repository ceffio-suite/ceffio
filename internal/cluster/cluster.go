// Package cluster gère le provisionnement du runtime Kubernetes (K3s réel sur
// Linux, k3d en environnement de dev) et la santé du cluster.
package cluster

import (
	"context"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runtime identifie le mode de provisionnement.
type Runtime string

const (
	RuntimeK3s Runtime = "k3s" // Linux : vrai K3s (single-node / appliance)
	RuntimeDev Runtime = "dev" // environnement de dev : k3d (K3s dans Docker)
)

// Cluster décrit un cluster provisionné.
type Cluster struct {
	Runtime Runtime
	Name    string
}

// Provision crée (ou réutilise, de façon idempotente) le cluster demandé.
func Provision(ctx context.Context, rt Runtime, name string) (*Cluster, error) {
	c := &Cluster{Runtime: rt, Name: name}
	switch rt {
	case RuntimeK3s:
		if err := provisionK3s(ctx); err != nil {
			return nil, err
		}
	case RuntimeDev:
		if err := provisionK3d(ctx, name); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("runtime de cluster inconnu %q", rt)
	}
	return c, nil
}

func provisionK3d(ctx context.Context, name string) error {
	if k3dExists(ctx, name) {
		fmt.Printf("cluster k3d %q existe déjà, réutilisation\n", name)
		return nil
	}
	cmd := exec.CommandContext(ctx, "k3d", "cluster", "create", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func k3dExists(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, "k3d", "cluster", "list", "--no-headers").CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, name) {
			return true
		}
	}
	return false
}

// provisionK3s installe un vrai cluster K3s via le script officiel (Linux),
// plus helm (prérequis de la pile) et le kubeconfig par défaut de l'utilisateur.
func provisionK3s(ctx context.Context) error {
	// TODO(phase-1) : flags HA (--cluster-init), version pin, options servi-extra.
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_START=false sh -")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("get.k3s.io: %w", err)
	}
	// helm : prérequis (charts jetstack, umbrella). Auto-install si absent.
	if _, err := exec.LookPath("helm"); err != nil {
		fmt.Println("∙ helm absent → installation via get-helm-3")
		hcmd := exec.CommandContext(ctx, "sh", "-c",
			"curl -sfL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sh")
		hcmd.Stdout = os.Stdout
		hcmd.Stderr = os.Stderr
		if err := hcmd.Run(); err != nil {
			return fmt.Errorf("install helm: %w", err)
		}
	}
	// Kubeconfig : le script K3s démarre le service en arrière-plan et écrit
	// /etc/rancher/k3s/k3s.yaml seulement quelques secondes APRÈS le retour du
	// script (K3s génère sa CA/certificats au premier boot). On l'attend donc
	// activement : une lecture immédiate échoue et, comme elle est non bloquante,
	// laisse la machine sans kubeconfig → kubectl/helm échouent ensuite en
	// « permission denied » sur k3s.yaml, et le cluster paraît non-Ready.
	// TOUJOURS réécrit : un ~/.kube/config périmé d'un précédent k3s (autre CA)
	// ferait échouer helm/kubectl en « x509: certificate signed by unknown
	// authority ». Les erreurs ne sont JAMAIS avalées.
	const k3sCfg = "/etc/rancher/k3s/k3s.yaml"
	// Le CLI tourne en root (installer.sh → sudo) : lecture directe. En mode
	// « sudo sans root » (ex. binaire lancé par un user), on retombe sur sudo cat.
	readCfg := func() ([]byte, error) {
		if data, err := os.ReadFile(k3sCfg); err == nil {
			return data, nil
		}
		out, err := exec.CommandContext(ctx, "sudo", "cat", k3sCfg).Output()
		if err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s vide", k3sCfg)
		}
		return out, nil
	}
	var data []byte
	deadline := time.Now().Add(90 * time.Second)
	for {
		var err error
		if data, err = readCfg(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("kubeconfig %s indisponible après 90s: %w "+
				"(k3s a-t-il démarré ? vérifier: systemctl status k3s)", k3sCfg, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return fmt.Errorf("HOME introuvable pour écrire ~/.kube/config: %w", err)
	}
	kc := filepath.Join(home, ".kube")
	if err := os.MkdirAll(kc, 0o700); err != nil {
		return fmt.Errorf("création %s: %w", kc, err)
	}
	if err := os.WriteFile(filepath.Join(kc, "config"), data, 0o600); err != nil {
		return fmt.Errorf("écriture ~/.kube/config: %w", err)
	}
	return nil
}

// Destroy démonte le cluster provisionné et nettoie l'état local de Ceffio.
// La dérivation des consommateurs est le reflet de Provision (même switch).
func Destroy(ctx context.Context, rt Runtime, name string) error {
	switch rt {
	case RuntimeK3s:
		// k3s-uninstall.sh arrête le service et purge /etc/rancher, /var/lib/rancher,
		// les binaires et le service systemd (données/volumes local-path inclus). Leur
		// trace (set -x) est redirigée vers un log : on n'affiche rien en cas de succès.
		cmd := exec.CommandContext(ctx, "sh", "-c",
			"systemctl stop k3s 2>/dev/null; if [ -x /usr/local/bin/k3s-uninstall.sh ]; then /usr/local/bin/k3s-uninstall.sh >/tmp/ceffio-k3s-uninstall.log 2>&1; else echo 'k3s-uninstall.sh absent (k3s non installé via le script officiel)'; fi")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("k3s-uninstall: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		fmt.Println("✓ K3s démonté (k3s-uninstall.sh)")
	case RuntimeDev:
		if !k3dExists(ctx, name) {
			fmt.Printf("cluster k3d %q absent, rien à supprimer\n", name)
		} else {
			cmd := exec.CommandContext(ctx, "k3d", "cluster", "delete", name)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("k3d cluster delete: %w", err)
			}
			fmt.Printf("✓ cluster k3d %q supprimé\n", name)
		}
	default:
		return fmt.Errorf("runtime de cluster inconnu %q", rt)
	}
	return cleanupLocal(ctx, rt, name)
}

// cleanupLocal supprime l'état local de Ceffio. Le kubeconfig (~/.kube/config) est
// laissé en place : il peut contenir d'autres clusters ; on ne touche pas d'un revers.
func cleanupLocal(ctx context.Context, rt Runtime, name string) error {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		ce := filepath.Join(home, ".ceffio")
		if _, err := os.Stat(ce); err == nil {
			_ = os.RemoveAll(ce)
			fmt.Println("✓ état local ~/.ceffio supprimé")
		}
	}
	return nil
}

// Health liste les nœuds du cluster courant (via kubectl).
func Health(ctx context.Context) ([]string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "nodes", "-o", "name").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl get nodes: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	var nodes []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			nodes = append(nodes, strings.TrimPrefix(l, "node/"))
		}
	}
	return nodes, nil
}

// WaitReady attend que tous les nœuds soient Ready, avec un timeout.
func WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if allNodesReady(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("cluster non Ready après %s", timeout)
}

func allNodesReady(ctx context.Context) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "nodes", "-o",
		`jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{" "}{end}`).Output()
	if err != nil {
		return false
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if f != "True" {
			return false
		}
	}
	return true
}
