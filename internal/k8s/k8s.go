// Package k8s centralise l'exécution des outils Kubernetes (kubectl, helm) avec
// un environnement explicite.
//
// Pourquoi ce package existe — bug de reproductibilité découvert par le
// test from-scratch du 2026-09-25 :
//
// Le script d'installation K3s expose `kubectl` comme un SYMLINK vers le binaire
// `k3s` (/usr/local/bin/kubectl -> k3s). Invoqué sous le nom « kubectl », ce
// binaire applique la logique « bundled kubectl » de K3s : il lit
// /etc/rancher/k3s/k3s.yaml EN DUR, AVANT toute résolution standard. Or ce
// fichier appartient à root en 0600 → un CLI lancé par un utilisateur non-root
// (ou tout appel hérité d'un tel env) échoue en :
//
//	error loading config file "/etc/rancher/k3s/k3s.yaml": permission denied
//
// …même quand ~/.kube/config existe, est correct et lisible. Conséquence : tout
// le déploiement échoue (WaitReady ne voit jamais le nœud, chaque Deploy casse),
// et l'erreur affichée ne mentionne jamais le kubeconfig, ce qui rend le
// diagnostic très coûteux.
//
// La parade : ne jamais dépendre de la résolution implicite du kubeconfig —
// toujours passer KUBECONFIG explicitement dans l'environnement du processus.
package k8s

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

// Env retourne l'environnement du processus courant enrichi de KUBECONFIG
// (et, pour K3s, K3S_* utiles), afin que kubectl et helm visent le même
// kubeconfig de façon déterministe.
//
// Si KUBECONFIG est déjà défini par l'appelant, il est respecté : on ne
// l'écrase pas.
func Env() []string {
	env := os.Environ()
	if os.Getenv("KUBECONFIG") != "" {
		return env
	}
	if p := defaultKubeconfig(); p != "" {
		env = append(env, "KUBECONFIG="+p)
	}
	return env
}

// defaultKubeconfig résout le kubeconfig par défaut de l'utilisateur
// (~/.kube/config). Retourne "" si HOME est introuvable.
func defaultKubeconfig() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}

// Command est un exec.CommandContext qui applique Env() automatiquement.
// À utiliser pour TOUT appel à kubectl ou helm.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = Env()
	return cmd
}
