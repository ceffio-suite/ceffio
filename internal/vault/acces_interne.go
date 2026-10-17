// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// cheminJetonSA is where Kubernetes projects the pod's ServiceAccount token.
// It exists in every pod whose ServiceAccount is automounted — which is the
// default, and which the console does not disable.
const cheminJetonSA = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// roleKubernetesConsole is the vault role the console authenticates with.
// It is ALREADY configured (configurerAuthKubernetes) and bound to the
// ServiceAccount ceffio-admin in ceffio-system — the same identity the
// injector uses to render /secrets/env for the console pod. No new role, no
// new policy, no stored secret: the pod presents the token the cluster
// already gave it.
const roleKubernetesConsole = "console"

// JetonInCluster authenticates the CURRENT POD against OpenBao through the
// Kubernetes auth method, and returns the internal address plus a client
// token.
//
// WHY THIS EXISTS. internal/secrets reads BAO_ADDR/BAO_TOKEN from the
// environment. On the installation machine those are set by vault.Acces
// (NodePort + openbao-token Secret). Inside the console pod, NEITHER is set:
// the injector renders only the application secrets (CEFFIO_KEY, KC_ADMIN,
// NC_USER…), never vault credentials — by design, since a static token in a
// pod would recreate the problem OpenBao solves. The consequence was measured
// in production, on the « Deploy the deployer » button:
//
//	vault unreadable for exapps/harp: no vault configured: cannot read exapps/harp
//
// because secrets.DepuisEnvironnement() returned nil (BAO_ADDR empty).
//
// THE CORRECT SOURCE OF IDENTITY IS THE POD ITSELF. The vault already trusts
// it: the role "console" is bound to sa ceffio-admin / ns ceffio-system, and
// the injector proves the login works every time the pod starts. We perform
// the exact same login (POST auth/kubernetes/login with the projected
// ServiceAccount token) from the process, and obtain a short-lived token
// (1 h TTL, set on the role) instead of a permanent secret.
//
// The address is the INTERNAL service one (openbao.ceffio-vault.svc): from
// inside a pod, unlike the installation machine, the NodePort round-trip is
// useless. BAO_ADDR_INTERNE overrides it, the same way BAO_ADDR overrides
// nothing here — this function is only called in-cluster.
func JetonInCluster(ctx context.Context) (string, string, error) {
	jwt, err := os.ReadFile(cheminJetonSA)
	if err != nil {
		return "", "", fmt.Errorf("no projected ServiceAccount token (%s): not running inside a pod? %w",
			cheminJetonSA, err)
	}

	adresse := os.Getenv("BAO_ADDR_INTERNE")
	if adresse == "" {
		adresse = fmt.Sprintf("http://%s.%s.svc:8200", service, ns)
	}

	payload, err := json.Marshal(map[string]string{
		"role": roleKubernetesConsole,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
	if err != nil {
		return "", "", err
	}

	reqCtx, annuler := context.WithTimeout(ctx, 10*time.Second)
	defer annuler()
	req, err := http.NewRequestWithContext(reqCtx, "POST",
		strings.TrimRight(adresse, "/")+"/v1/auth/kubernetes/login",
		bytes.NewReader(payload))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("vault login at %s: %w", adresse, err)
	}
	defer resp.Body.Close()
	brut, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var corps struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(brut, &corps); err != nil {
		return "", "", fmt.Errorf("vault login answer unreadable (HTTP %d): %.200s",
			resp.StatusCode, string(brut))
	}
	if corps.Auth.ClientToken == "" {
		return "", "", fmt.Errorf("vault login refused (HTTP %d): %s",
			resp.StatusCode, strings.Join(corps.Errors, "; "))
	}
	return adresse, corps.Auth.ClientToken, nil
}

// MaintenirJetonInCluster exports BAO_ADDR/BAO_TOKEN from the pod's own
// identity, and KEEPS them fresh for the life of the process.
//
// WHY A REFRESHER AND NOT A SINGLE LOGIN: the role's token TTL is 1 h
// (configurerAuthKubernetes). The console is a long-lived server — a token
// taken once at startup would die quietly, and the first action taken after
// an hour (a click on « Deploy the deployer ») would fail on an expired
// token. Re-logging in is free and needs no stored secret: the projected
// ServiceAccount token is renewed by the cluster itself.
//
// The refresh interval is half the TTL, so at least one re-login happens
// before any expiry. os.Setenv/os.Getenv are safe to use concurrently, and
// secrets.DepuisEnvironnement re-reads the environment on every call — which
// is what makes this work without touching any consumer.
//
// OUTSIDE A CLUSTER THIS IS A NO-OP: no projected token, no login, no
// error returned. The CLI path (resoudreCoffre → vault.Acces) stays the one
// that sets the environment on the installation machine.
func MaintenirJetonInCluster(ctx context.Context) {
	if _, _, err := resoudreEtExporter(ctx); err != nil {
		// NOT IN A POD, OR THE VAULT IS NOT UP YET — and silence is right for
		// the first case.
		//
		// The CLI runs this same binary on the installation machine, where
		// there is no projected token: printing a warning there would be noise
		// on every command. And a vault that boots a few seconds after the
		// console is picked up by the ticker, so failing loudly on a race would
		// cry wolf at every restart.
		//
		// What the caller CANNOT tell from here is whether it is out of the
		// cluster or whether the vault refused the login. That distinction is
		// what the first successful call reports below.
		return
	}
	fmt.Println("✓ vault access acquired (Kubernetes authentication, role " + roleKubernetesConsole + ")")
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		consecutifs := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// A FAILED REFRESH MUST BE VISIBLE, and this is not
				// decoration.
				//
				// The token lives one hour. If a refresh fails — the vault was
				// restarted, its role was renamed, its policy was edited — the
				// console keeps the previous token, which still has about
				// thirty minutes left. It then works, and stops working half an
				// hour later, with a message about a missing secret rather than
				// about an expired token.
				//
				// That is the same shape of failure this whole file exists to
				// fix: the symptom names the wrong cause. So the failure is
				// printed, with its reason, while the token is still valid and
				// the cause is still in the logs.
				if _, _, err := resoudreEtExporter(ctx); err != nil {
					consecutifs++
					fmt.Printf("⚠ vault token refresh failed (%d in a row): %v\n", consecutifs, err)
					continue
				}
				if consecutifs > 0 {
					fmt.Printf("✓ vault access restored after %d failed refresh(es)\n", consecutifs)
					consecutifs = 0
				}
			}
		}
	}()
}

// resoudreEtExporter performs the login and puts the result in the
// environment, so secrets.DepuisEnvironnement sees a configured vault.
func resoudreEtExporter(ctx context.Context) (string, string, error) {
	adresse, jeton, err := JetonInCluster(ctx)
	if err != nil {
		return "", "", err
	}
	os.Setenv("BAO_ADDR", adresse)
	os.Setenv("BAO_TOKEN", jeton)
	return adresse, jeton, nil
}
