// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards the mail module's State: what a real cluster looks like from here, and
// therefore what the upgrade path decides to replay.
//
// WHY THEY EXIST: RejouerInstalles replays a module whose state is Installed or
// Degraded, and a 0.10.x cluster has Stalwart deployed but the mail module was
// Core back then — the module must recognize that deployment instead of
// answering Absent and skipping the replay. These tests pin the three shapes
// that matter: absent, deployed and ready, deployed and not ready.
package mail

import (
	"context"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// clusterAvecDeploiement builds an Env whose cluster holds the Stalwart
// Deployment with the given number of ready replicas.
func clusterAvecDeploiement(prets int32) module.Env {
	return module.Env{
		Domain: "example.com",
		Kube: fake.NewSimpleClientset(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "stalwart", Namespace: "ceffio-mail"},
			Status:     appsv1.DeploymentStatus{ReadyReplicas: prets},
		}),
	}
}

// TestEtatDetecteLInstallationExistante: a cluster shaped like a 0.10.x one
// (Stalwart deployed and ready) reads as Installed.
func TestEtatDetecteLInstallationExistante(t *testing.T) {
	etat := (&mailModule{}).State(context.Background(), clusterAvecDeploiement(1))
	if etat.Status != module.Installed {
		t.Fatalf("status = %q, expected %q: the deployment exists and is ready",
			etat.Status, module.Installed)
	}
}

// TestEtatDetecteUnDeploiementQuiNeDemarrePas: a deployment with no ready
// replica is Degraded, not Absent — the difference decides whether the upgrade
// replays it (it does) and whether the console shows it (it does).
func TestEtatDetecteUnDeploiementQuiNeDemarrePas(t *testing.T) {
	etat := (&mailModule{}).State(context.Background(), clusterAvecDeploiement(0))
	if etat.Status != module.Degraded {
		t.Fatalf("status = %q, expected %q: the deployment exists but serves nothing",
			etat.Status, module.Degraded)
	}
}

// TestEtatSansDeploiementDitAbsent: nothing deployed reads as Absent, which is
// the only state `ceffio install` treats as "not installed yet".
func TestEtatSansDeploiementDitAbsent(t *testing.T) {
	env := module.Env{Domain: "example.com", Kube: fake.NewSimpleClientset()}
	etat := (&mailModule{}).State(context.Background(), env)
	if etat.Status != module.Absent {
		t.Fatalf("status = %q, expected %q: no deployment means the module was never installed",
			etat.Status, module.Absent)
	}
}
