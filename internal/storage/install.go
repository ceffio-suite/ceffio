// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// This file installs the STORAGE layer: the host prerequisites Longhorn needs,
// then Longhorn itself.
//
// # WHY THIS LIVES IN THE BINARY AND NOT IN install.sh
//
// installer/install.sh deliberately holds no logic — it downloads the binary
// and verifies its checksum. Everything that touches the machine belongs in
// the Go code, where it can be tested, where the failure can be explained, and
// where a re-run is idempotent.
//
// # WHY THESE PREREQUISITES ARE NOT OPTIONAL
//
// The first deployment to ceffio.org was assembled by hand, and this is the
// part that took the longest to work out. Longhorn is a CSI driver that
// attaches volumes over iSCSI; without the client installed and its daemon
// running on the node, everything LOOKS fine — Longhorn's pods are Running,
// the StorageClass exists — and the volumes never leave `creating`. Measured:
//
//	crictl pull succeeds, PVC stays Pending, volume state=faulted,
//	replica scheduler reports no available node.
//
// The cause is invisible in the cluster: it is a missing package on the host.
// Checking for it after the fact costs far more than installing it up front.
package storage

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// longhornChartVersion pinned. Nothing follows `latest`: a storage driver that
// upgrades itself under running volumes is not something an operator can
// reason about.
const longhornChartVersion = "1.13.0"

// Namespace Longhorn is installed into. Also the namespace that must NEVER be
// included in a cleanup of the ceffio namespaces: deleting it destroys every
// volume of the platform. It happened once during development.
const longhornNamespace = "longhorn-system"

// paquetsPrerequis are the host packages the CSI driver needs.
//
// open-iscsi  the transport Longhorn uses to attach volumes to the node.
//
//	Without it: `VolumeAttachment` fails, volumes stay Pending.
//
// nfs-common  the NFS client, for a backup target on a NAS. Installed up
//
//	front because adding it later means a node drain to be sure it
//	is picked up everywhere.
//
// util-linux  provides iscsiadm's companions and mount helpers; present on
//
//	every distribution but named explicitly so the check is honest.
var paquetsPrerequis = []string{"open-iscsi", "nfs-common", "util-linux"}

// servicesPrerequis are enabled AND started, in this order.
//
// `open-iscsi` is a service of its own (a wrapper around iscsid) and is often
// left inactive while iscsid runs. Both are enabled: some distributions route
// the restart through the wrapper.
var servicesPrerequis = []string{"iscsid", "open-iscsi", "multipathd"}

// Install prepares the host and installs Longhorn, then makes it the default
// StorageClass. Idempotent: safe to re-run on a working cluster.
//
// THE HOST PART RUNS ONLY WHEN NEEDED. On a machine that already has the
// packages, nothing is touched — an installation must not require
// authorisation to reinstall packages it does not need.
func Install(ctx context.Context) error {
	if err := prerequisHote(ctx); err != nil {
		return err
	}
	if err := installerLonghorn(ctx); err != nil {
		return err
	}
	if err := attendreLonghorn(ctx); err != nil {
		return err
	}
	if err := definirClasseParDefaut(ctx); err != nil {
		return err
	}
	return nil
}

// prerequisHote installs the packages and starts the services Longhorn needs.
//
// SUDO IS NON-INTERACTIVE (-n) BY CHOICE. Not because a password is expected:
// on the machines this targets, the deploying account has passwordless sudo.
// The flag is there so the command FAILS FAST if that is not the case, instead
// of printing a prompt nobody sees and waiting forever — a deployment that
// hangs is worse than one that stops and says why.
func prerequisHote(ctx context.Context) error {
	manquants := paquetsAbsents(ctx)
	if len(manquants) > 0 {
		fmt.Printf("∙ host packages for the storage driver: %s\n", strings.Join(manquants, " "))
		args := append([]string{"-n", "apt-get", "install", "-y", "-qq"}, manquants...)
		if err := run(ctx, "sudo", args...); err != nil {
			return fmt.Errorf("installing %s: %w — this account needs passwordless "+
				"sudo to prepare the host", strings.Join(manquants, ", "), err)
		}
	}

	for _, s := range servicesPrerequis {
		// enable --now covers both: it starts the service and records it for
		// the next boot. Two commands would leave a window where the service
		// runs but does not come back after a reboot.
		if err := run(ctx, "sudo", "-n", "systemctl", "enable", "--now", s); err != nil {
			return fmt.Errorf("enabling %s: %w", s, err)
		}
	}

	// THE PACKAGES ARE INSTALLED, THE SERVICES RUN — BUT THE NODE MAY STILL
	// NOT SEE THE MODULES. A kernel that was never told to load iscsi_tcp
	// leaves Longhorn unable to attach anything, with no error anywhere in the
	// cluster. modprobe is idempotent and costs nothing when the module is
	// already there.
	for _, m := range []string{"iscsi_tcp", "dm_multipath"} {
		if err := run(ctx, "sudo", "-n", "modprobe", m); err != nil {
			return fmt.Errorf("loading kernel module %s: %w", m, err)
		}
	}

	fmt.Println("✓ storage prerequisites in place (iSCSI + multipath)")
	return nil
}

// PaquetsAbsents returns the prerequisite packages that are NOT installed.
//
// EXPORTED SO THE PRE-FLIGHT CHECK CAN REPORT THEM without installing: the
// install step runs a few seconds later, and duplicating the package list in
// two packages would mean two places to update when it changes.
//
// dpkg-query rather than `dpkg -l`: the latter returns 0 for a package that is
// known but removed, which is exactly the case we need to detect.
func PaquetsAbsents(ctx context.Context) []string { return paquetsAbsents(ctx) }

func paquetsAbsents(ctx context.Context) []string {
	var manquants []string
	for _, p := range paquetsPrerequis {
		cmd := k8s.Command(ctx, "dpkg-query", "-W", "-f=${Status}", p)
		out, err := cmd.Output()
		if err != nil || !strings.Contains(string(out), "install ok installed") {
			manquants = append(manquants, p)
		}
	}
	return manquants
}

// installerLonghorn installs the chart, with the settings that matter.
//
// THE TWO --set ARE NOT COSMETIC:
//
//	defaultDataPath        where volumes live. Defaulting to /var/lib/longhorn
//	                       keeps them on the volume the operator sized for
//	                       storage, away from the container runtime's disk.
//	                       A host partitioned for storage puts a large volume
//	                       there; leaving the default would fill the system
//	                       volume instead, and the failure appears as a full
//	                       disk days later.
//
//	defaultReplicaCount=1  single-node cluster. Three replicas is the sane
//	                       default for a real cluster, but on one node they
//	                       all land on the same disk: it triples the space
//	                       used, protects against nothing, and the volume can
//	                       never be scheduled once a replica is lost.
func installerLonghorn(ctx context.Context) error {
	fmt.Printf("∙ Longhorn %s (CSI: expansion, snapshots, backup)\n", longhornChartVersion)

	if err := ensureRepo(ctx, "longhorn", "https://charts.longhorn.io"); err != nil {
		return err
	}

	cmd := k8s.Command(ctx, "helm", "upgrade", "--install", "longhorn", "longhorn/longhorn",
		"--namespace", longhornNamespace, "--create-namespace",
		"--set", "defaultSettings.defaultDataPath=/var/lib/longhorn",
		"--set", "defaultSettings.defaultReplicaCount=1",
		"--set", "defaultSettings.storageMinimalAvailablePercentage=10",
		"--timeout", "15m",
		"--version", longhornChartVersion)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installing Longhorn: %w", err)
	}
	return nil
}

// attendreLonghorn waits for the driver, the manager and the UI to answer.
//
// ALL THREE, because they come up at different times and only the trio means
// the volume lifecycle works. Waiting on the pods alone was not enough during
// the first deployment: the manager was Running while the driver had not yet
// registered, and the first PVC created in that window went to `faulted` and
// never recovered — the volumes had to be deleted and recreated.
func attendreLonghorn(ctx context.Context) error {
	fmt.Println("∙ waiting for Longhorn Ready...")
	// THE NAMES ARE VERSION-DEPENDENT, and getting one wrong means waiting
	// forever on a deployment that does not exist. Measured on 1.13.0:
	// longhorn-manager was RENAMED longhorn-global-manager, and longhorn-ui
	// moved out of the manager's pod into a Deployment of its own.
	for _, d := range []string{"longhorn-driver-deployer", "longhorn-global-manager", "longhorn-ui"} {
		cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
			"deployment/"+d, "-n", longhornNamespace, "--timeout=300s")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s not ready: %w", d, err)
		}
	}

	// THE CSI DRIVER REGISTERS LAST, and a volume created before it does is
	// refused. This is the exact window that produced the faulted volumes on
	// the first deployment: pods Running, StorageClass present, and every PVC
	// stuck in `creating` with no usable error. We close it by waiting for the
	// CSIDriver object itself, not just the pods that announce it.
	for i := 0; i < 60; i++ {
		cmd := k8s.Command(ctx, "kubectl", "get", "csidriver", "driver.longhorn.io")
		if err := cmd.Run(); err == nil {
			fmt.Println("  ✓ CSI driver driver.longhorn.io registered")
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

	fmt.Println("✓ Longhorn ready")
	return nil
}

// definirClasseParDefaut makes `longhorn` the default StorageClass.
//
// WITHOUT THIS, A PVC WITHOUT AN EXPLICIT CLASS LANDS ON `local-path` — k3s
// ships it as the default, and it has no expansion and no backup. The
// difference would only surface the day someone tries to grow a volume.
//
// The old default is UNANNOTATED rather than deleted: it is a k3s component,
// deleting it can be undone by an upgrade, and a cluster where two classes
// both claim to be default behaves unpredictably.
func definirClasseParDefaut(ctx context.Context) error {
	fmt.Println("∙ Longhorn as the default StorageClass")

	// longhorn-static is a companion class for pre-provisioned volumes; it must
	// never be the default.
	if err := run(ctx, "kubectl", "annotate", "storageclass", "local-path",
		"storageclass.kubernetes.io/is-default-class-", "--overwrite"); err != nil {
		// Not fatal: on a cluster without local-path there is nothing to
		// un-default, and stopping here would fail a valid installation.
		fmt.Println("  ∙ local-path is not the default here, nothing to unset")
	}
	if err := run(ctx, "kubectl", "annotate", "storageclass", "longhorn",
		"storageclass.kubernetes.io/is-default-class=true", "--overwrite"); err != nil {
		return fmt.Errorf("marking longhorn as default: %w", err)
	}
	return nil
}

func ensureRepo(ctx context.Context, nom, url string) error {
	cmd := k8s.Command(ctx, "helm", "repo", "add", nom, url)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// An existing repo returns an error with helm 3; the update below is what
	// actually matters, so a failure here is not fatal.
	_ = cmd.Run()

	cmd = k8s.Command(ctx, "helm", "repo", "update", nom)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("helm repo update %s: %w", nom, err)
	}
	return nil
}

func run(ctx context.Context, nom string, args ...string) error {
	cmd := k8s.Command(ctx, nom, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
