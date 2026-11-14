// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the mailbox volume: the size in place, the two refusals, and the
// difference between saving a value and deploying one.
//
// WHY THEY EXIST: the volume was a `20Gi` literal in the rendered workload, so
// the only way to enlarge a mailbox store that filled up was to edit YAML. It is
// now a setting — which makes "what happens when the value is smaller than the
// claim" a decision that must be provable, not described: Kubernetes refuses a
// shrinking update, and a settings page that accepted 10 GiB over a 20 GiB claim
// would be lying to whoever read it back.
package mail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// installerCluster makes a fake cluster the client for the duration of one test,
// and records what the write path would apply.
func installerCluster(t *testing.T, objets ...runtime.Object) (*k8sfake.Clientset, *[]string) {
	t.Helper()
	cs := k8sfake.NewSimpleClientset(objets...)

	ancienClient := clientK8s
	clientK8s = func() (*k8sapi.Client, error) { return k8sapi.PourTest(cs, nil), nil }

	ecrits := &[]string{}
	ancienApply := appliquerVolume
	appliquerVolume = func(_ context.Context, manifeste string) error {
		*ecrits = append(*ecrits, manifeste)
		return nil
	}

	t.Cleanup(func() {
		clientK8s = ancienClient
		appliquerVolume = ancienApply
	})
	return cs, ecrits
}

// claim construit the claim Stalwart has, at a given size and class.
func claim(tailleGio int, classe string) *corev1.PersistentVolumeClaim {
	nomClasse := classe
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: pvcStalwart, Namespace: ns},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: &nomClasse,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(fmt.Sprintf("%dGi", tailleGio)),
				},
			},
		},
	}
}

// classe construit a StorageClass, expansion allowed or not.
func classe(nom string, expansion bool) *storagev1.StorageClass {
	autorise := expansion
	return &storagev1.StorageClass{
		ObjectMeta:           metav1.ObjectMeta{Name: nom},
		AllowVolumeExpansion: &autorise,
	}
}

// TestTailleVolumeLitLaTailleDuClaim: the reported size is the claim's, not the
// default.
func TestTailleVolumeLitLaTailleDuClaim(t *testing.T) {
	installerCluster(t, claim(30, "longhorn"))

	taille, present, err := TailleVolume(context.Background())
	if err != nil {
		t.Fatalf("TailleVolume() = %v", err)
	}
	if !present || taille != 30 {
		t.Errorf("TailleVolume() = (%d, %v), want (30, true)", taille, present)
	}
}

// TestTailleVolumeAbsentDUCluster: an installation without a claim is reported
// as absent rather than as a size, which is what lets the deployment create it.
func TestTailleVolumeAbsentDuCluster(t *testing.T) {
	installerCluster(t)

	taille, present, err := TailleVolume(context.Background())
	if err != nil {
		t.Fatalf("TailleVolume() = %v", err)
	}
	if present || taille != 0 {
		t.Errorf("TailleVolume() = (%d, %v), want (0, false)", taille, present)
	}
}

// TestAssurerVolumeRefuseUneReduction: a smaller value is refused, nothing is
// applied, and the error says which size is in effect.
func TestAssurerVolumeRefuseUneReduction(t *testing.T) {
	_, ecrits := installerCluster(t, claim(20, "longhorn"))

	_, err := assurerVolume(context.Background(), 10)
	if !errors.Is(err, ErrReduction) {
		t.Fatalf("assurerVolume(10) = %v, want ErrReduction", err)
	}
	if !strings.Contains(err.Error(), "20 GiB") {
		t.Errorf("the error does not name the size in effect: %v", err)
	}
	if len(*ecrits) != 0 {
		t.Errorf("a refused reduction was still applied: %v", *ecrits)
	}
}

// TestAssurerVolumeConservantGardeLaTaille: the DEPLOYMENT path keeps the claim's
// size instead of failing — a working mail server must not go down over a number
// written before someone enlarged the volume by hand.
func TestAssurerVolumeConservantGardeLaTaille(t *testing.T) {
	_, ecrits := installerCluster(t, claim(20, "longhorn"))

	taille, err := assurerVolumeConservant(context.Background(), 10)
	if err != nil {
		t.Fatalf("assurerVolumeConservant(10) = %v, want nil", err)
	}
	if taille != 20 {
		t.Errorf("assurerVolumeConservant(10) = %d, want the claim's 20", taille)
	}
	if len(*ecrits) != 0 {
		t.Errorf("keeping the size still wrote to the cluster: %v", *ecrits)
	}
}

// TestAssurerVolumeGrandit: growth applies the claim at the requested size, with
// the class already in effect — applying a different class would be an immutable
// field error.
func TestAssurerVolumeGrandit(t *testing.T) {
	cs, ecrits := installerCluster(t, claim(20, "longhorn"), classe("longhorn", true))

	// The write path of a fake cluster is not applied, so the test makes the
	// write visible: the read-back must see the enlarged claim.
	ancienApply := appliquerVolume
	appliquerVolume = func(ctx context.Context, manifeste string) error {
		if err := ancienApply(ctx, manifeste); err != nil {
			return err
		}
		maj, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcStalwart, metav1.GetOptions{})
		if err != nil {
			return err
		}
		maj.Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("30Gi")
		_, err = cs.CoreV1().PersistentVolumeClaims(ns).Update(ctx, maj, metav1.UpdateOptions{})
		return err
	}

	taille, err := assurerVolume(context.Background(), 30)
	if err != nil {
		t.Fatalf("assurerVolume(30) = %v", err)
	}
	if taille != 30 {
		t.Errorf("assurerVolume(30) = %d, want 30", taille)
	}
	if len(*ecrits) != 1 {
		t.Fatalf("the enlargement was applied %d times, want 1", len(*ecrits))
	}
	manifeste := (*ecrits)[0]
	for _, attendu := range []string{"storage: 30Gi", "storageClassName: longhorn", "name: " + pvcStalwart} {
		if !strings.Contains(manifeste, attendu) {
			t.Errorf("the applied claim does not contain %q:\n%s", attendu, manifeste)
		}
	}
}

// TestAssurerVolumeRefuseSansExtension: the storage class decides whether a claim
// can grow, and the answer is read from the object. Longhorn allows it, but the
// code must not assume the installation it was written on.
func TestAssurerVolumeRefuseSansExtension(t *testing.T) {
	_, ecrits := installerCluster(t, claim(20, "fixe"), classe("fixe", false))

	_, err := assurerVolume(context.Background(), 30)
	if err == nil {
		t.Fatal("assurerVolume(30) accepted a storage class that cannot expand")
	}
	if !strings.Contains(err.Error(), "does not allow volume expansion") {
		t.Errorf("the error does not explain the refusal: %v", err)
	}
	if len(*ecrits) != 0 {
		t.Errorf("a refused enlargement was still applied: %v", *ecrits)
	}
}

// TestAssurerVolumeRefuseUneClasseDisparue: a claim whose storage class no longer
// exists is a refusal that names the class, not a silent no-op.
func TestAssurerVolumeRefuseUneClasseDisparue(t *testing.T) {
	installerCluster(t, claim(20, "disparue"))

	_, err := assurerVolume(context.Background(), 30)
	if err == nil || !strings.Contains(err.Error(), "disparue") {
		t.Fatalf("assurerVolume(30) = %v, want a refusal naming the missing class", err)
	}
}

// TestAssurerVolumeCree: with no claim, the volume is created at the requested
// size — or at the default when nothing was asked.
func TestAssurerVolumeCree(t *testing.T) {
	_, ecrits := installerCluster(t)

	taille, err := assurerVolume(context.Background(), 0)
	if err != nil {
		t.Fatalf("assurerVolume(0) = %v", err)
	}
	if taille != TailleVolumeDefautGio {
		t.Errorf("assurerVolume(0) = %d, want the default %d", taille, TailleVolumeDefautGio)
	}
	if len(*ecrits) != 1 {
		t.Fatalf("the claim was applied %d times, want 1", len(*ecrits))
	}
	if !strings.Contains((*ecrits)[0], fmt.Sprintf("storage: %dGi", TailleVolumeDefautGio)) {
		t.Errorf("the created claim is not at the default size:\n%s", (*ecrits)[0])
	}
}

// TestAssurerVolumeAUneTailleEgalNeEcritPas: asking for the size already in place
// writes nothing — a redeploy must not touch a claim for no reason.
func TestAssurerVolumeAUneTailleEgalNeEcritPas(t *testing.T) {
	_, ecrits := installerCluster(t, claim(20, "longhorn"), classe("longhorn", true))

	taille, err := assurerVolume(context.Background(), 20)
	if err != nil {
		t.Fatalf("assurerVolume(20) = %v", err)
	}
	if taille != 20 {
		t.Errorf("assurerVolume(20) = %d, want 20", taille)
	}
	if len(*ecrits) != 0 {
		t.Errorf("an unchanged size was written anyway: %v", *ecrits)
	}
}
