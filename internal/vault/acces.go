// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"context"
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// Acces returns the address and token that allow using the vault from the
// installation machine.
//
// WHY THIS FUNCTION EXISTS, AND WHY IT IS INDISPENSABLE: the internal/secrets
// module reads BAO_ADDR and BAO_TOKEN from the environment — that is what lets
// it target any vault without knowing anything about its installation. But a
// command launched ALONE has nobody to set them: `install` sets them for its
// own modules, in its own process. Without this function, a standalone command
// would SILENTLY fall back to Kubernetes Secrets and never read the vault. That
// is the worst kind of failure: everything appears to work, and the source of
// truth is not the one you think it is.
//
// THE ADDRESS IS THE NODEPORT ONE, reachable from the machine. The internal
// service name does not resolve from there — the installation does not run
// inside the cluster.
func Acces(ctx context.Context, cli *k8sapi.Client) (string, string, error) {
	port, err := cli.NodePortDuService(ctx, ns, service, "api")
	if err != nil {
		return "", "", fmt.Errorf("cannot read the vault's external port: %w", err)
	}
	if port == 0 {
		return "", "", fmt.Errorf("the vault service exposes no port: the vault is not deployed")
	}
	// The token lives in a Kubernetes Secret, placed there by the vault's
	// deployment. Copying it into a configuration file would create yet another
	// copy to keep in sync.
	jeton, err := cli.LireSecret(ctx, ns, "openbao-token", "token")
	if err != nil {
		return "", "", fmt.Errorf("cannot read the vault token: %w", err)
	}
	if jeton == "" {
		return "", "", fmt.Errorf("vault token missing (Secret openbao-token is empty)")
	}
	noeud := os.Getenv("CEFFIO_NOEUD")
	if noeud == "" {
		noeud = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s:%d", noeud, port), jeton, nil
}
