package vault

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

//go:embed injecteur/rendu.yaml
var manifesteInjecteur string

// VersionChartInjecteur is the version of the OpenBao chart this render comes
// from.
//
// THE RENDER IS VERSIONED WITH THE CODE, not pulled at install time: an
// installer must depend neither on Helm nor on network access to a chart
// repository. To update it, re-render the chart at that version, replace the
// file, and the diff says exactly what changed.
const VersionChartInjecteur = "0.30.3"

// nomWebhookInjecteur is the name of the webhook configuration created by the
// chart. It serves as the readiness witness — see poserInjecteur.
const nomWebhookInjecteur = "ceffio-injector-openbao-agent-injector-cfg"

// poserInjecteur installs OpenBao's agent-injector, and VERIFIES it is ready to
// inject before handing back control.
//
// WHY BEFORE THE ANNOTATED WORKLOADS: migrated pods carry annotations that only
// the injector knows how to read. Its failure policy is "Ignore" — a sound
// choice for the cluster, since a downed injector does not block pod creation —
// but it has one consequence: without the injector, pods start WITHOUT secrets
// and with no admission error at all. Complete silence, exactly the failure mode
// we are trying to eliminate. Because this check is typed and blocks the
// deployment, it cannot pass itself off as success.
//
// THE WITNESS IS THE WEBHOOK'S TRUST SEED, not the pod's state: the injector is
// what writes it, once its certificate is generated. A "Ready" pod may well be
// ready before it has patched its webhook; a populated caBundle cannot.
func poserInjecteur(ctx context.Context, cli *k8sapi.Client) error {
	fmt.Println("∙ OpenBao agent-injector (chart " + VersionChartInjecteur + ")")
	if err := cli.Appliquer(ctx, manifesteInjecteur); err != nil {
		return fmt.Errorf("installing the agent-injector: %w", err)
	}

	fin := time.Now().Add(150 * time.Second)
	for time.Now().Before(fin) {
		pret, err := cli.WebhookEstPret(ctx, nomWebhookInjecteur)
		if err == nil && pret {
			fmt.Println("  ✓ injector ready: webhook trust seed published")
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("the agent-injector did not publish its trust seed within 150 s — " +
		"annotated pods would start WITHOUT secrets, with no admission error")
}
