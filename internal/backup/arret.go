// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package backup

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// This file holds the ONE thing that separates a copy from a backup on a
// single-writer store: stopping the application before reading its files.
//
// WHY IT EXISTS — measured on the mail volume (POC K of docs/plan-mail.md).
// Stalwart 1.0 keeps its state in RocksDB, plus a local blob store, under
// /var/lib/stalwart. RocksDB has no online-backup command reachable from the
// API, and copying its files while the server writes them yields an archive
// that LOOKS complete (tar exits 0) and fails to open later. The only correct
// method is the one used here: scale the Deployment to zero, copy from a
// temporary pod that mounts the same PVC, scale back up. Restart happens even
// when the copy fails, because a failed backup must not turn into an outage.

const (
	// Prefix and label of the temporary pod. The prefix is what makes the pod
	// recognisable at a glance in `kubectl get pods`, and the label is what
	// lets a cleanup find it after an interrupted run.
	prefixePodCopie      = "ceffio-backup-"
	etiquetteRoleCopie   = "ceffio.fr/role=backup"
	etiquettePodTemporai = "app=ceffio-backup"

	// Image used when the Deployment's own image cannot be read. It must be an
	// image with a shell and tar, present on the node already: reusing the
	// application's image guarantees both properties without a pull.
	imageSecoursStalwart = "docker.io/stalwartlabs/stalwart:v1.0.3"

	intervalleAttente  = 2 * time.Second
	delaiArretPods     = 3 * time.Minute
	delaiDemarragePod  = 3 * time.Minute
	delaiRedemarrage   = 5 * time.Minute
	delaiCommandeCorte = 7 * time.Minute
)

// executerKubectl is THE SEAM of the new code paths in this package: every
// kubectl invocation added for the mail volume and the vault goes through it,
// so the tests can drive them without a cluster.
//
// The legacy paths keep their own kubectlOut; they are exercised by the
// integration test on a real cluster, and rewriting them would add risk
// without adding coverage.
var executerKubectl = func(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	cmd := k8s.Command(ctx, "kubectl", args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	var stderr strings.Builder
	cmd.Stderr = &stderr
	ctx, annuler := context.WithTimeout(ctx, delaiCommandeCorte)
	defer annuler()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl %s : %w : %s", args[0], err, oneLine(stderr.String()))
	}
	return nil
}

// sortieKubectl runs a kubectl command and returns its standard output.
func sortieKubectl(ctx context.Context, args ...string) (string, error) {
	var b strings.Builder
	if err := executerKubectl(ctx, nil, &b, args...); err != nil {
		return "", err
	}
	return b.String(), nil
}

// sauvegarderVolume copies a volume into dst, stopping its workload first when
// the volume declares one.
func sauvegarderVolume(ctx context.Context, v Volume, dst string, progress func(string)) error {
	if v.StopWorkload == "" {
		pod := podFor(ctx, v.Namespace, v.PodLabel)
		if pod == "" {
			return fmt.Errorf("no pod %s in %s", v.PodLabel, v.Namespace)
		}
		return tarVolume(ctx, v.Namespace, pod, v.Path, dst)
	}
	return avecVolumeArrete(ctx, v, progress, func(pod string) error {
		return tarVolume(ctx, v.Namespace, pod, v.Path, dst)
	})
}

// restaurerVolume re-injects a tar into the volume, stopping its workload
// first when the volume declares one.
func restaurerVolume(ctx context.Context, v Volume, tarPath string, progress func(string)) error {
	if v.StopWorkload == "" {
		pod := podFor(ctx, v.Namespace, v.PodLabel)
		if pod == "" {
			return fmt.Errorf("no pod %s", v.PodLabel)
		}
		return restoreVolume(ctx, v, pod, tarPath)
	}
	return avecVolumeArrete(ctx, v, progress, func(pod string) error {
		return restoreVolume(ctx, v, pod, tarPath)
	})
}

// avecVolumeArrete runs copie against a temporary pod that mounts the volume,
// after shutting the workload down, and restarts the workload WHATEVER happens.
//
// The order of the defers is the whole point: the temporary pod is deleted
// BEFORE the workload is restarted (defers run last-in, first-out), because the
// PVC is ReadWriteOnce — the application cannot mount it while the helper still
// holds it.
func avecVolumeArrete(ctx context.Context, v Volume, progress func(string), copie func(pod string) error) (err error) {
	if progress == nil {
		progress = func(string) {}
	}
	if err := arreterCharge(ctx, v); err != nil {
		return err
	}
	defer func() {
		if rerr := redemarrerCharge(ctx, v); rerr != nil {
			if err == nil {
				err = rerr
				return
			}
			// The copy failed AND the restart failed: both must be said. The
			// restart one is the emergency; hiding it behind the copy error
			// would send the operator looking at the wrong problem.
			err = fmt.Errorf("%w ; AND the workload %s was NOT restarted: %v", err, v.StopWorkload, rerr)
		}
	}()

	progress("volume " + v.PVC + ": workload " + v.StopWorkload + " stopped")
	pod, err := demarrerPodCopie(ctx, v)
	if err != nil {
		return err
	}
	defer func() {
		if derr := supprimerPodCopie(ctx, pod); derr != nil && err == nil {
			err = derr
		}
	}()
	return copie(pod)
}

// arreterCharge scales the workload to zero and waits until its pods are gone.
//
// Waiting is not politeness: the PVC is ReadWriteOnce, so a helper pod created
// while the old pod still holds the volume would stay Pending — and the
// symptom (a timeout on pod start) would not name the real cause.
func arreterCharge(ctx context.Context, v Volume) error {
	if _, err := sortieKubectl(ctx, "scale", "deployment", v.StopWorkload,
		"-n", v.Namespace, "--replicas=0"); err != nil {
		return fmt.Errorf("stopping %s: %w", v.StopWorkload, err)
	}
	limite := time.Now().Add(delaiArretPods)
	for {
		out, err := sortieKubectl(ctx, "get", "pods", "-n", v.Namespace,
			"-l", v.PodLabel, "--no-headers")
		if err == nil && strings.TrimSpace(out) == "" {
			return nil
		}
		if time.Now().After(limite) {
			return fmt.Errorf("stopping %s: its pods are still present after %s",
				v.StopWorkload, delaiArretPods)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(intervalleAttente):
		}
	}
}

// redemarrerCharge scales the workload back to one and waits for the rollout.
func redemarrerCharge(ctx context.Context, v Volume) error {
	if _, err := sortieKubectl(ctx, "scale", "deployment", v.StopWorkload,
		"-n", v.Namespace, "--replicas=1"); err != nil {
		return fmt.Errorf("restarting %s: %w", v.StopWorkload, err)
	}
	if _, err := sortieKubectl(ctx, "rollout", "status", "deployment/"+v.StopWorkload,
		"-n", v.Namespace, "--timeout="+delaiRedemarrage.String()); err != nil {
		return fmt.Errorf("restarting %s: %w", v.StopWorkload, err)
	}
	return nil
}

// demarrerPodCopie creates a temporary pod mounting the volume and waits until
// it is ready.
func demarrerPodCopie(ctx context.Context, v Volume) (string, error) {
	image := imageDuDeploiement(ctx, v.Namespace, v.StopWorkload)
	nom := prefixePodCopie + v.PVC
	if err := appliquerManifeste(ctx, manifestePodCopie(nom, v, image)); err != nil {
		return "", fmt.Errorf("creating the temporary pod: %w", err)
	}
	if _, err := sortieKubectl(ctx, "wait", "--for=condition=Ready", "pod/"+nom,
		"-n", v.Namespace, "--timeout="+delaiDemarragePod.String()); err != nil {
		// Leave nothing behind: the caller's defer on the pod name has not been
		// registered yet, so this failure would otherwise leak the pod — and the
		// restart would then fail on the busy PVC.
		_ = supprimerPodCopie(ctx, nom)
		return "", fmt.Errorf("the temporary pod does not become ready: %w", err)
	}
	return nom, nil
}

func supprimerPodCopie(ctx context.Context, nom string) error {
	if _, err := sortieKubectl(ctx, "delete", "pod", nom, "-n", nsVolumeCopie(nom),
		"--ignore-not-found", "--wait=true"); err != nil {
		return fmt.Errorf("deleting the temporary pod %s: %w", nom, err)
	}
	return nil
}

// nsVolumeCopie recovers the namespace of a temporary pod from its name.
//
// The name is built from the PVC, and the PVC is unique to one namespace in
// this platform (stalwart-data lives in ceffio-mail and nowhere else). Rather
// than thread the namespace through every call, which invites a mismatch, the
// volume table is the source of truth.
func nsVolumeCopie(nom string) string {
	base := strings.TrimPrefix(nom, prefixePodCopie)
	for _, v := range Volumes {
		if v.PVC == base {
			return v.Namespace
		}
	}
	return "ceffio-mail"
}

func imageDuDeploiement(ctx context.Context, ns, deploiement string) string {
	out, err := sortieKubectl(ctx, "get", "deployment", deploiement, "-n", ns,
		"-o", "jsonpath={.spec.template.spec.containers[0].image}")
	if err == nil && strings.TrimSpace(out) != "" {
		return strings.TrimSpace(out)
	}
	return imageSecoursStalwart
}

func appliquerManifeste(ctx context.Context, manifeste string) error {
	_, err := sortieKubectlStdin(ctx, manifeste, "apply", "-f", "-")
	return err
}

func sortieKubectlStdin(ctx context.Context, entree string, args ...string) (string, error) {
	var b strings.Builder
	if err := executerKubectl(ctx, strings.NewReader(entree), &b, args...); err != nil {
		return b.String(), err
	}
	return b.String(), nil
}

// manifestePodCopie renders the temporary pod.
//
// It runs with the application's own UID/GID: files created by the copy (and,
// on restore, by the extraction) then belong to the account that will use
// them, without a chown a non-root process could not perform.
func manifestePodCopie(nom string, v Volume, image string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: ceffio-backup
    ceffio.fr/pour: %[3]s
spec:
  restartPolicy: Never
  securityContext:
    fsGroup: %[6]d
  containers:
    - name: copie
      image: %[4]s
      command: ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]
      securityContext:
        runAsUser: %[5]d
        runAsGroup: %[6]d
        allowPrivilegeEscalation: false
      volumeMounts:
        - name: data
          mountPath: %[7]s
      resources:
        requests:
          cpu: 10m
          memory: 32Mi
        limits:
          cpu: "1"
          memory: 512Mi
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: %[3]s
`, nom, v.Namespace, v.PVC, image, v.UID, v.GID, v.Path)
}

// citerShell quotes a value for a shell command line.
//
// The paths and keys come from tables written in this repository, so they
// cannot carry a hostile value today. The quoting exists so that the day one
// comes from a manifest or an archive, the failure stays a quoting artefact
// instead of a command injection.
func citerShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
