// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The mail volume: how big Stalwart's mailbox store is, and what happens when
// the operator asks for a different size.
//
// WHY THIS IS NOT A LINE IN THE MANIFEST ANYMORE: the volume was a hard-coded
// `20Gi` in the workload rendered by `Deploy`. A mailbox store that fills up
// stops accepting mail, and the only way to enlarge it was to edit YAML — the
// console's settings page could not do it, so the value the operator changed
// was not the value in effect. The size is now a setting, and the code below
// is where "the value in effect" is decided.
//
// THE TWO RULES, both measured against Kubernetes itself rather than assumed:
//
//  1. A PVC CANNOT SHRINK. Kubernetes refuses the update; pretending otherwise
//     would produce a settings page that accepts a value and does nothing.
//     A smaller value is therefore REFUSED, with an explanation.
//  2. A PVC CANNOT GROW ON EVERY STORAGE CLASS. The StorageClass must declare
//     `allowVolumeExpansion`; Longhorn does, but the code reads the answer
//     instead of trusting the installation it was written on.
package mail

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/storage"
)

const (
	// pvcStalwart is the claim that carries the mailboxes and the index.
	pvcStalwart = "stalwart-data"

	// TailleVolumeDefautGio is the size used when the setting is absent: the
	// value the manifest hard-coded, kept so that an existing installation does
	// not move when this code lands.
	TailleVolumeDefautGio = 20
)

// ErrReduction is returned when a smaller size is asked for. It is a sentinel
// because the two callers must react differently: a SAVE refuses the value and
// tells the operator, while a DEPLOYMENT keeps the size in place and says so —
// an installation whose claim was enlarged by hand must not stop deploying.
var ErrReduction = errors.New("a volume cannot shrink")

// clientK8s is a variable so a test can read volumes without a cluster.
//
// SAME IDIOM AS internal/modules/ingress: the default talks to the real
// cluster, the test substitutes `k8sapi.PourTest(fake.NewSimpleClientset())`.
// A decision about refusing a smaller volume is a decision nobody has checked
// unless a test can present a claim of a known size.
var clientK8s = k8sapi.Nouveau

// appliquerVolume is the write path, isolated for the same reason.
//
// IT APPLIES A MANIFEST rather than patching the object through the typed
// client, because `apply` is what every other component of this package uses:
// a second write path would be a second way to get the same object wrong
// (server-side defaults, last-applied annotation, and so on).
var appliquerVolume = func(ctx context.Context, manifeste string) error {
	return apply(ctx, manifeste)
}

// TailleVolume returns the size in GiB requested by Stalwart's claim, and
// whether the claim exists at all.
//
// THE UNIT IS GIB AND THE VALUE IS ROUNDED UP: a claim of 21474836480 bytes is
// 20 GiB, and a value that is not a round number (edited by hand, or converted
// from another unit by Kubernetes) must never read as smaller than it is — the
// anti-shrink check below compares against this number.
func TailleVolume(ctx context.Context) (int, bool, error) {
	pvc, err := lirePVC(ctx)
	if err != nil {
		return 0, false, err
	}
	if pvc == nil {
		return 0, false, nil
	}
	return gioDe(pvc), true, nil
}

// assurerVolume creates or enlarges the claim, and returns the size in effect.
//
// THE ORDER OF THE REFUSALS IS THE POINT: the size is checked BEFORE the
// workload is touched, so a refused value leaves the cluster exactly as it was
// — no rollout, no partial configuration.
func assurerVolume(ctx context.Context, voulueGio int) (int, error) {
	if voulueGio <= 0 {
		voulueGio = TailleVolumeDefautGio
	}

	pvc, err := lirePVC(ctx)
	if err != nil {
		return 0, err
	}

	// 1. Nothing in place: create it at the requested size.
	if pvc == nil {
		if err := appliquerVolume(ctx, manifesteVolume(voulueGio, storage.Classe())); err != nil {
			return 0, fmt.Errorf("creating the mail volume (%dGi): %w", voulueGio, err)
		}
		return voulueGio, nil
	}

	// 2. The claim exists: compare, and refuse a smaller value instead of
	//    silently keeping the old size. A settings page that accepts 10 and
	//    keeps 20 is lying to whoever reads it back.
	actuelleGio := gioDe(pvc)
	if voulueGio < actuelleGio {
		return 0, fmt.Errorf("%w: the mail volume is %d GiB and Kubernetes cannot shrink a "+
			"PersistentVolumeClaim; ask for %d GiB or more (the current size is what is in effect)",
			ErrReduction, actuelleGio, actuelleGio)
	}
	if voulueGio == actuelleGio {
		return actuelleGio, nil
	}

	// 3. Growth: the StorageClass must allow it. The answer is read from the
	//    object in place, never assumed.
	classe, err := classeDuPVC(ctx, pvc)
	if err != nil {
		return 0, err
	}
	autorise, err := extensionAutorisee(ctx, classe)
	if err != nil {
		return 0, err
	}
	if !autorise {
		return 0, fmt.Errorf("refused: storage class %q does not allow volume expansion, so the "+
			"mail volume cannot grow from %d GiB to %d GiB", classe, actuelleGio, voulueGio)
	}

	if err := appliquerVolume(ctx, manifesteVolume(voulueGio, classe)); err != nil {
		return 0, fmt.Errorf("enlarging the mail volume from %dGi to %dGi: %w", actuelleGio, voulueGio, err)
	}

	// 4. Read back: the request is what was asked, and it did not shrink the
	//    claim it was written on.
	relue, err := lirePVC(ctx)
	if err != nil {
		return 0, err
	}
	if relue == nil {
		return 0, fmt.Errorf("the mail volume is absent after it was enlarged")
	}
	if taille := gioDe(relue); taille < voulueGio {
		return 0, fmt.Errorf("the mail volume reads back %d GiB after asking for %d GiB", taille, voulueGio)
	}
	return tailleUtile(voulueGio, relue), nil
}

// assurerVolumeConservant is `assurerVolume` for the deployment path: a size
// smaller than the claim is KEPT at the claim's size rather than refused.
//
// WHY THE DEPLOYMENT MUST NOT FAIL ON IT: the stored value can be older than the
// claim (an operator enlarged it by hand, or an earlier install asked for more).
// Refusing to deploy over that would take a working mail server down to
// complain about a number, which is the opposite of what a deployment is for.
// The reduced value is reported so the cause is visible.
func assurerVolumeConservant(ctx context.Context, voulueGio int) (int, error) {
	taille, err := assurerVolume(ctx, voulueGio)
	if err == nil {
		return taille, nil
	}
	if !errors.Is(err, ErrReduction) {
		return 0, err
	}
	actuelle, present, lerr := TailleVolume(ctx)
	if lerr != nil || !present {
		return 0, err
	}
	fmt.Printf("  ! the settings ask for %d GiB but the volume in place is %d GiB "+
		"(Kubernetes cannot shrink it): keeping %d GiB\n", voulueGio, actuelle, actuelle)
	return actuelle, nil
}

// tailleUtile returns the size to report: the request, or the claim's own value
// when a server-side default made it larger (some storage classes round up to a
// minimum).
func tailleUtile(voulueGio int, pvc *corev1.PersistentVolumeClaim) int {
	if taille := gioDe(pvc); taille > voulueGio {
		return taille
	}
	return voulueGio
}

// lirePVC returns the claim, or nil when it does not exist.
func lirePVC(ctx context.Context) (*corev1.PersistentVolumeClaim, error) {
	client, err := clientK8s()
	if err != nil {
		return nil, fmt.Errorf("mail volume: %w", err)
	}
	pvc, err := client.Kubernetes().CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcStalwart, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the mail volume %s/%s: %w", ns, pvcStalwart, err)
	}
	return pvc, nil
}

// gioDe converts the claim's requested size to GiB, rounded up.
func gioDe(pvc *corev1.PersistentVolumeClaim) int {
	q, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	if !ok {
		return 0
	}
	const gio = int64(1024 * 1024 * 1024)
	octets := q.Value()
	if octets <= 0 {
		return 0
	}
	return int((octets + gio - 1) / gio)
}

// classeDuPVC returns the storage class in effect for the claim.
//
// AN EMPTY FIELD MEANS THE DEFAULT CLASS, which is a cluster-level setting: it
// is resolved here rather than reported as "" — the error messages have to name
// the class that actually decides.
func classeDuPVC(ctx context.Context, pvc *corev1.PersistentVolumeClaim) (string, error) {
	if pvc.Spec.StorageClassName != nil && *pvc.Spec.StorageClassName != "" {
		return *pvc.Spec.StorageClassName, nil
	}
	client, err := clientK8s()
	if err != nil {
		return "", fmt.Errorf("mail volume: %w", err)
	}
	classes, err := client.Kubernetes().StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("listing storage classes: %w", err)
	}
	for _, c := range classes.Items {
		if c.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
			return c.Name, nil
		}
	}
	return "", fmt.Errorf("the mail volume has no storage class and the cluster declares no default one")
}

// extensionAutorisee reads the StorageClass's own declaration.
func extensionAutorisee(ctx context.Context, classe string) (bool, error) {
	if classe == "" {
		return false, nil
	}
	client, err := clientK8s()
	if err != nil {
		return false, fmt.Errorf("mail volume: %w", err)
	}
	sc, err := client.Kubernetes().StorageV1().StorageClasses().Get(ctx, classe, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, fmt.Errorf("storage class %q no longer exists", classe)
	}
	if err != nil {
		return false, fmt.Errorf("reading storage class %q: %w", classe, err)
	}
	return sc.AllowVolumeExpansion != nil && *sc.AllowVolumeExpansion, nil
}

// manifesteVolume renders the claim at a given size.
//
// `storageClassName` IS THE CLASS ALREADY IN EFFECT, not `storage.Classe()`:
// applying a different class to an existing claim is an immutable-field error,
// and the class of a claim that exists is a fact, not a preference.
func manifesteVolume(tailleGio int, classe string) string {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n")
	b.WriteString("  name: " + pvcStalwart + "\n  namespace: " + ns + "\n")
	b.WriteString("spec:\n  accessModes: [ReadWriteOnce]\n")
	if classe != "" {
		b.WriteString("  storageClassName: " + classe + "\n")
	}
	fmt.Fprintf(&b, "  resources:\n    requests:\n      storage: %dGi\n", tailleGio)
	return b.String()
}
