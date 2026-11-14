// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Access to the Stalwart pod, THROUGH THE KUBERNETES API.
//
// WHY THIS FILE EXISTS: the whole mail package used to reach its own server by
// launching `kubectl exec`. That works from a workstation and fails everywhere
// else — the console image is built `FROM scratch` and ships no kubectl, so
// every step that needed the mail server was simply unavailable to it. The API
// is the one client every caller has.
//
// NOTHING HERE IS A BEHAVIOUR CHANGE: same script inside the same container,
// same credential read from /secrets/env. Only the intermediary changed, and
// with it the class of defects that came from parsing a shell command's output.
package mail

import (
	"context"
	"fmt"
	"strings"
)

// conteneurStalwart and etiquetteStalwart identify the pod the mail operations
// run in.
//
// THE CONTAINER NAME IS EXPLICIT: a Deployment that grows a sidecar would
// otherwise receive the exec on whichever container the API picks first, and
// the failure would be a "sh: curl: not found" nobody can place.
const (
	conteneurStalwart = "stalwart"
	etiquetteStalwart = "stalwart"
)

// executerDansPod runs a shell script inside the Stalwart pod and returns its
// output.
//
// THE SCRIPT IS PASSED TO `sh -c`, exactly as before: every call site is a
// pipeline of shell commands whose quoting was measured against the live
// server, and rewriting them as argument vectors would change a verified
// behaviour for no gain.
func executerDansPod(ctx context.Context, script string) (string, error) {
	cli, err := clientK8s()
	if err != nil {
		return "", fmt.Errorf("cluster access: %w", err)
	}
	pod, err := cli.PodDuDeploiement(ctx, ns, etiquetteStalwart, etiquetteStalwart)
	if err != nil {
		return "", err
	}
	return cli.Executer(ctx, ns, pod, conteneurStalwart, "sh", "-c", script)
}

// executerDansPodAvecEntree is the same, feeding standard input.
//
// WHY STANDARD INPUT AND NOT A FILE OR AN ARGUMENT: a JMAP request body carries
// the relay password in clear. On the command line it would be visible in the
// pod's process table; in a file it would be readable for as long as the file
// lives. Standard input has neither defect.
func executerDansPodAvecEntree(ctx context.Context, entree, script string) (string, error) {
	cli, err := clientK8s()
	if err != nil {
		return "", fmt.Errorf("cluster access: %w", err)
	}
	pod, err := cli.PodDuDeploiement(ctx, ns, etiquetteStalwart, etiquetteStalwart)
	if err != nil {
		return "", err
	}
	return cli.ExecuterAvecEntree(ctx, ns, pod, conteneurStalwart, entree, "sh", "-c", script)
}

// transportJMAPPod performs one JMAP exchange inside the pod.
//
// A VARIABLE, because every behaviour built on it is a decision about what to
// do with a response, and a decision that cannot be exercised by a test is a
// decision nobody has checked. The test substitutes a fake transport; the
// production path is the one below, unchanged in every respect from the
// `kubectl exec` it replaces.
var transportJMAP = transportJMAPPod

// transportJMAPPod calls /jmap through the pod.
func transportJMAPPod(ctx context.Context, corps []byte) ([]byte, error) {
	sortie, err := executerDansPodAvecEntree(ctx, string(corps),
		scriptAvecSecrets(`curl -s --max-time 20 -u "$STALWART_RECOVERY_ADMIN" `+
			`-H "Content-Type: application/json" -X POST http://localhost:8080/jmap --data-binary @-`))
	if err != nil {
		return nil, fmt.Errorf("JMAP call through the pod: %w", err)
	}
	return []byte(sortie), nil
}

// lireDansPod reads one URL served by the pod itself.
//
// THE POD'S OWN LOOPBACK, not the public address: the call stays on the
// internal network, works even when the ingress or the certificate is broken,
// and asks the server rather than a proxy in front of it.
func lireDansPod(ctx context.Context, url string) ([]byte, error) {
	sortie, err := executerDansPod(ctx, `curl -s --max-time 15 `+entreGuillemets(url))
	if err != nil {
		return nil, err
	}
	return []byte(sortie), nil
}

// entreGuillemets quotes a value for the shell.
//
// A SINGLE QUOTED WORD, because the value is a URL built from an account name:
// without quoting, a name carrying a space or a semicolon would become a second
// command in a shell running next to the mail store.
func entreGuillemets(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
