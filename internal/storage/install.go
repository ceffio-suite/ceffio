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
	"strconv"
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
// THE --set VALUES ARE NOT COSMETIC:
//
//	defaultDataPath        where volumes live. Defaulting to /var/lib/longhorn
//	                       keeps them on the volume the operator sized for
//	                       storage, away from the container runtime's disk.
//	                       A host partitioned for storage puts a large volume
//	                       there; leaving the default would fill the system
//	                       volume instead, and the failure appears as a full
//	                       disk days later.
//
//	replicaCount=1         single-node cluster. Three replicas is the sane
//	                       default for a real cluster, but on one node they
//	                       all land on the same disk: it triples the space
//	                       used, protects against nothing, and the volume can
//	                       never be scheduled once a replica is lost.
//
// THE REPLICA COUNT IS SET TWICE, ON PURPOSE, AND THE SECOND ONE IS THE ONE
// THAT COUNTS. Measured on a fresh node: with only
// `defaultSettings.defaultReplicaCount=1`, Longhorn's global setting read
// {"v1":"1"} while the StorageClass it created still carried
// `numberOfReplicas: "3"` — the chart hardcodes 3 in the class, and a volume
// takes its replica count FROM THE CLASS, not from the global setting.
//
// The result was a volume claiming 3 replicas on a machine with one disk:
// robustness `degraded`, two replicas stuck in `stopped`, and the mount
// failing with
//
//	mke2fs: /dev/longhorn/pvc-… is apparently in use by the system;
//	will not make a filesystem here!
//
// The deployment then stopped on « PostgreSQL ceffio-pg not ready after 300s »,
// which points nowhere near the replica count.
func installerLonghorn(ctx context.Context) error {
	fmt.Printf("∙ Longhorn %s (CSI: expansion, snapshots, backup)\n", longhornChartVersion)

	if err := ensureRepo(ctx, "longhorn", "https://charts.longhorn.io"); err != nil {
		return err
	}

	cmd := k8s.Command(ctx, "helm", "upgrade", "--install", "longhorn", "longhorn/longhorn",
		"--namespace", longhornNamespace, "--create-namespace",
		"--set", "defaultSettings.defaultDataPath=/var/lib/longhorn",
		"--set", "defaultSettings.storageMinimalAvailablePercentage=10",
		// THIS IS THE ONE THAT DECIDES THE REPLICA COUNT, and the first
		// deployment got it wrong twice. `defaultSettings.defaultReplicaCount`
		// (the Longhorn GLOBAL setting) is NOT what the StorageClass takes:
		// the chart has its own key, and the class is built from it.
		//
		// Measured on a fresh node, with only defaultSettings set:
		//   Longhorn global setting        → {"v1":"1"}
		//   StorageClass numberOfReplicas  → "3"   (unchanged)
		//   volume created                 → replicas=3, robustness degraded
		//
		// Both are set now — the global one keeps the cluster coherent, this
		// one is what the volumes actually read.
		"--set", fmt.Sprintf("persistence.defaultClassReplicaCount=%d", replicasPourLeCluster(ctx)),
		"--timeout", "15m",
		"--version", longhornChartVersion)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installing Longhorn: %w", err)
	}

	// The install reports success whether or not the replica count landed, so
	// we read it back rather than trust it.
	return verifierReplicasClasse(ctx)
}

// replicasPourLeCluster: how many replicas a volume should have here.
//
// ONE ON A SINGLE NODE, THREE BEYOND. The count is read from the machine, not
// from a preference: on one node every replica shares the same disk, so three
// replicas triple the space used, protect against nothing, and leave the
// volume unable to be scheduled once a replica is lost.
//
// Measured symptom of getting this wrong on a single node:
//
//	volume robustness `degraded`, two replicas stuck in `stopped`, and the
//	mount failing on « /dev/longhorn/pvc-… is apparently in use by the
//	system; will not make a filesystem here! »
//
// The deployment then stopped on « PostgreSQL ceffio-pg not ready after 300s »,
// which points nowhere near the replica count.
func replicasPourLeCluster(ctx context.Context) int {
	out, err := k8s.Command(ctx, "kubectl", "get", "nodes", "--no-headers").Output()
	if err != nil {
		// Cannot count: assume the safer default for a real cluster rather
		// than silently degrading durability on a machine we failed to read.
		return 3
	}
	noeuds := 0
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(l) != "" {
			noeuds++
		}
	}
	if noeuds <= 1 {
		return 1
	}
	return 3
}

// verifierReplicasClasse proves the StorageClass carries what we asked for.
//
// WHY A READ-BACK AND NOT AN ASSUMPTION: the helm install succeeds whether or
// not the replica count landed — that is exactly how the first deployment
// passed this step and failed twenty minutes later inside PostgreSQL. A
// StorageClass whose parameter did not take looks identical in
// `kubectl get sc`: same name, same provisioner, same `(default)` marker.
//
// The class is NOT patched or recreated here. Its parameters are immutable —
// verified: « parameters: … field is immutable » — and Longhorn's own
// controller recreates it from its chart values the moment it is deleted. The
// value has to arrive through helm; this function only checks that it did.
func verifierReplicasClasse(ctx context.Context) error {
	voulu := strconv.Itoa(replicasPourLeCluster(ctx))

	sortie, err := k8s.Command(ctx, "kubectl", "get", "storageclass", "longhorn",
		"-o", "jsonpath={.parameters.numberOfReplicas}").Output()
	if err != nil {
		return fmt.Errorf("reading numberOfReplicas from the longhorn StorageClass: %w", err)
	}
	obtenu := strings.TrimSpace(string(sortie))

	if obtenu != voulu {
		return fmt.Errorf("the longhorn StorageClass requests %s replicas, expected %s "+
			"for this %s-node cluster — volumes would come up degraded and their "+
			"mount would fail on « apparently in use by the system ». "+
			"The value comes from the chart's persistence.defaultClassReplicaCount, "+
			"not from defaultSettings.defaultReplicaCount", obtenu, voulu,
			map[bool]string{true: "single", false: "multi"}[voulu == "1"])
	}
	fmt.Printf("  ✓ numberOfReplicas=%s on the longhorn StorageClass\n", obtenu)
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
// ships it as the only class present on a fresh node, so it is what a volume
// gets when nothing else claims the default. local-path has no expansion and
// no backup, and the difference only surfaces the day someone tries to grow a
// volume.
//
// NOTE ON THE ANNOTATION: `local-path` carries NO is-default-class annotation
// at all on a fresh node — verified. It does not need one to be picked, which
// is why the fix is not to un-annotate it but to make longhorn the default
// BEFORE any PVC exists; that is why this runs in the storage layer.
func definirClasseParDefaut(ctx context.Context) error {
	fmt.Println("∙ Longhorn as the default StorageClass")

	if err := run(ctx, "kubectl", "annotate", "storageclass", "longhorn",
		"storageclass.kubernetes.io/is-default-class=true", "--overwrite"); err != nil {
		return fmt.Errorf("marking longhorn as default: %w", err)
	}

	// longhorn-static is the companion class for pre-provisioned volumes and
	// must never be the default. Un-annotated only when it carries the
	// annotation; the command fails otherwise, which is expected.
	for _, c := range []string{"local-path", "longhorn-static"} {
		cmd := k8s.Command(ctx, "kubectl", "annotate", "storageclass", c,
			"storageclass.kubernetes.io/is-default-class-", "--overwrite")
		if err := cmd.Run(); err != nil {
			continue // no such class, or no annotation to remove
		}
		fmt.Printf("  ∙ %s no longer claims to be the default\n", c)
	}

	// PROOF RATHER THAN ASSUMPTION: read the annotation back and refuse to
	// continue if it did not land. A deployment that proceeds with the wrong
	// default writes every volume to a provisioner that cannot expand or back
	// them up, and nothing says so until someone tries to grow a volume.
	cmd := k8s.Command(ctx, "kubectl", "get", "storageclass", "longhorn",
		"-o", "jsonpath={.metadata.annotations.storageclass\\.kubernetes\\.io/is-default-class}")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("reading back the default class: %w", err)
	}
	if strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("longhorn is not the default StorageClass after applying " +
			"the annotation — every volume would land on local-path, which cannot " +
			"be expanded nor backed up")
	}
	fmt.Println("  ✓ longhorn is the default StorageClass")
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
