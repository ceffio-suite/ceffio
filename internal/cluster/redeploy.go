// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package cluster

import (
	"context"
	"time"

	"github.com/ceffio-suite/ceffio/internal/acme"
	"github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/data"
	"github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/platform"
	"github.com/ceffio-suite/ceffio/internal/publicip"
	"github.com/ceffio-suite/ceffio/internal/sso"
	"github.com/ceffio-suite/ceffio/internal/stacks"
)

// Redeployer replays the full deployment of an existing installation.
//
// Used by `ceffio upgrade`: each module targets the pinned version of its
// registry, and each is idempotent (it applies the manifest, replaces images
// if they differ). Replaying the deployment is therefore the correct way to
// upgrade — there is no separate "upgrade path" to maintain, and hence no
// possible drift between the two paths.
//
// The order follows the real dependencies: platform and data first, identity
// next (it needs its database), then the application layers, and finally
// ingress and SSO, which write into all the applications.
func Redeployer(ctx context.Context, domain string) error {
	// 1. Platform and data: independent of each other.
	if err := platform.Deploy(ctx); err != nil {
		return err
	}
	if err := data.Deploy(ctx); err != nil {
		return err
	}

	// 2. Identity: depends on the database.
	//
	// THE DOMAIN IS ANNOUNCED HERE, and its absence is not a detail: the identity
	// layer builds the suite's OIDC redirect_uri from it, and an empty domain
	// makes the whole replay fail at the SSO phase — which is what "ceffio
	// upgrade" did, for every installation, until this line.
	identity.PoserDomaine(domain)
	if err := identity.Deploy(ctx); err != nil {
		return err
	}

	// 3. Application layers: independent of each other.
	if err := files.Deploy(ctx); err != nil {
		return err
	}

	// 4. Office: after files (the connector goes through occ).
	if err := office.Deploy(ctx); err != nil {
		return err
	}

	// 5. SSO then ingress: these steps write into the applications, so they
	//    come last.
	if err := sso.EnsureOIDCClients(ctx, domain); err != nil {
		return err
	}
	// Talk replaces chat AND video: cleanup of the old stack.
	if err := stacks.RetirerMatrixEtJitsi(ctx, domain); err != nil {
		return err
	}
	if err := files.ConfigureOIDC(ctx, domain); err != nil {
		return err
	}
	if domain != "" {
		// The ACME settings are resolved HERE, at the single point that
		// re-deploys the ingress layer: an upgrade must re-apply the same
		// challenge the installation chose, or it would silently rewrite the
		// ClusterIssuers back to HTTP-01 and lose DNS-01 (and with it the
		// wildcard) on the first `ceffio upgrade`.
		reglages, err := acme.DepuisEnvironnement()
		if err != nil {
			return err
		}
		if err := ingress.Deploy(ctx, domain, reglages); err != nil {
			return err
		}
		if err := ingress.AdoptURLs(ctx, domain); err != nil {
			return err
		}
		if err := console.Deploy(ctx, domain); err != nil {
			return err
		}
		// THE PUBLIC-IP REPORTER RUNS THE SAME IMAGE, and it was deployed exactly
		// once — at install. Without this line an installation keeps a reporter
		// from the release that created it, forever: the code is idempotent, so
		// replaying it is how it follows the binary.
		cli, err := k8sapi.Nouveau()
		if err != nil {
			return err
		}
		if err := publicip.Deploy(ctx, cli.Kubernetes()); err != nil {
			return err
		}
	}

	// 6. Wait for the application pods to be ready. We do NOT use
	//    WaitReady: it watches NODES, which were already ready before the
	//    operation — it would return immediately, and the re-read that
	//    follows would still see the old pods running, and so would wrongly
	//    conclude that no version changed.
	return attentePodsPrets(ctx, 5*time.Minute)
}

// attentePodsPrets waits until all ceffio-* pods are ready, or expires.
// Expiry is not an error: an upgrade may legitimately leave a pod still
// starting, and it is `ceffio status`'s job to say so.
func attentePodsPrets(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if podsApplicatifsPrets(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}
