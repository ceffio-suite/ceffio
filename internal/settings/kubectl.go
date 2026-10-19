// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package settings

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// This file provides the CONCRETE implementations of the two interfaces
// declared in internal/module. They live here rather than in internal/module
// because that package imports nothing internal — every module imports it, so
// anything it imported would become a dependency of every module.

// ConfigMaps is the ConfigMapStore backed by kubectl.
//
// WHY KUBECTL AND NOT A TYPED CLIENT: this is how the rest of Ceffio reaches the
// cluster (see internal/k8s), and the console already runs with a ServiceAccount
// that has the rights. A typed client would mean a second code path for the same
// three operations, and a second set of RBAC rules to keep in step — the
// non-regression test on the console's permissions checks the rules the CLI
// needs, and adding another client would put them out of its reach.
type ConfigMaps struct{}

// Lire returns the value of one key, or "" when the key is absent.
//
// AN ABSENT KEY IS NOT AN ERROR: it is the state before the first save, and the
// caller applies the field defaults. Returning an error would make every first
// read fail, and every module would have to special-case it.
func (ConfigMaps) Lire(ctx context.Context, ns, nom, cle string) (string, error) {
	out, err := kubectl(ctx, "get", "configmap", nom, "-n", ns, "-o", "json")
	if err != nil {
		if estAbsent(err) {
			return "", nil
		}
		return "", err
	}
	var doc struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return "", fmt.Errorf("settings: configmap %s/%s is not readable: %w", ns, nom, err)
	}
	return doc.Data[cle], nil
}

// Ecrire merges keys into the object, creating it if needed.
//
// MERGE, NOT REPLACE: two modules share the ConfigMap, and replacing it would
// make the second module's save erase the first module's settings — a loss that
// looks like settings that were never saved.
func (ConfigMaps) Ecrire(ctx context.Context, ns, nom string, donnees map[string]string) error {
	// Read first, so the other keys survive.
	existants := map[string]string{}
	if out, err := kubectl(ctx, "get", "configmap", nom, "-n", ns, "-o", "json"); err == nil {
		var doc struct {
			Data map[string]string `json:"data"`
		}
		if json.Unmarshal([]byte(out), &doc) == nil {
			existants = doc.Data
		}
	}
	if existants == nil {
		existants = map[string]string{}
	}
	for k, v := range donnees {
		existants[k] = v
	}

	// The object may not exist yet: `create` is attempted first, and a failure
	// falls back to `apply` — which handles both cases but refuses an object
	// created imperatively without the last-applied annotation. Trying create
	// first is what makes the first save work at all.
	if err := ecrireObjet(ctx, "configmap", nom, ns, existants); err != nil {
		return err
	}
	return nil
}

// Supprimer removes one key, leaving the object and the other modules' keys.
func (ConfigMaps) Supprimer(ctx context.Context, ns, nom, cle string) error {
	out, err := kubectl(ctx, "get", "configmap", nom, "-n", ns, "-o", "json")
	if err != nil {
		if estAbsent(err) {
			return nil
		}
		return err
	}
	var doc struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return err
	}
	if _, present := doc.Data[cle]; !present {
		return nil
	}
	delete(doc.Data, cle)
	return ecrireObjet(ctx, "configmap", nom, ns, doc.Data)
}

// Secrets is the SecretStore used when no vault is configured.
type Secrets struct{}

func (Secrets) Lire(ctx context.Context, ns, nom, cle string) (map[string]string, error) {
	out, err := kubectl(ctx, "get", "secret", nom, "-n", ns, "-o", "json")
	if err != nil {
		if estAbsent(err) {
			return nil, nil
		}
		return nil, err
	}
	var doc struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("settings: secret %s/%s is not readable: %w", ns, nom, err)
	}
	// The Secret holds a JSON map per group, base64-encoded by Kubernetes.
	brut, ok := doc.Data[cle]
	if !ok {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(brut)
	if err != nil {
		return nil, fmt.Errorf("settings: entry %s of secret %s/%s is not valid base64: %w", cle, ns, nom, err)
	}
	sortie := map[string]string{}
	if err := json.Unmarshal(decoded, &sortie); err != nil {
		return nil, fmt.Errorf("settings: entry %s of secret %s/%s is not valid JSON: %w", cle, ns, nom, err)
	}
	return sortie, nil
}

func (Secrets) Ecrire(ctx context.Context, ns, nom string, donnees map[string]string) error {
	// The values are base64-encoded HERE, because a Secret's data field holds
	// base64 and the caller passes plain text.
	enc := map[string]string{}
	for k, v := range donnees {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		enc[k] = base64.StdEncoding.EncodeToString(b)
	}
	return ecrireObjetSecret(ctx, nom, ns, enc)
}

// --- Helpers ---------------------------------------------------------------

func ecrireObjet(ctx context.Context, kind, nom, ns string, donnees map[string]string) error {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       kindOf(kind),
		"metadata": map[string]any{"name": nom, "namespace": ns,
			"labels": map[string]string{"app.kubernetes.io/part-of": "ceffio"}},
		"data": donnees,
	}
	return appliquer(ctx, obj, kind, nom, ns)
}

func ecrireObjetSecret(ctx context.Context, nom, ns string, donnees map[string]string) error {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{"name": nom, "namespace": ns,
			"labels": map[string]string{"app.kubernetes.io/part-of": "ceffio"}},
		"type": "Opaque",
		"data": donnees,
	}
	return appliquer(ctx, obj, "secret", nom, ns)
}

// appliquer creates the object, or replaces it when it already exists.
//
// WHY NOT `apply` ALONE: apply refuses an object created imperatively (no
// last-applied-configuration annotation) — which is the case for anything
// created with `kubectl create`. Create-then-delete-and-recreate is what
// actually converges, and it is the same pattern as the restore.
func appliquer(ctx context.Context, obj map[string]any, kind, nom, ns string) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "create", "-f", "-")
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(string(b))
	if out, err := cmd.CombinedOutput(); err == nil {
		return nil
	} else if !strings.Contains(string(out), "AlreadyExists") {
		return fmt.Errorf("settings: creating %s %s/%s: %s", kind, ns, nom, strings.TrimSpace(string(out)))
	}

	// It exists: replace it outright, which is the documented way to converge.
	cmd = k8s.Command(ctx, "kubectl", "replace", "-f", "-")
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(string(b))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("settings: replacing %s %s/%s: %s", kind, ns, nom, strings.TrimSpace(string(out)))
	}
	return nil
}

func kindOf(k string) string {
	if k == "secret" {
		return "Secret"
	}
	return "ConfigMap"
}

func kubectl(ctx context.Context, args ...string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", args...)
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func estAbsent(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	if ee, ok := err.(*exec.ExitError); ok {
		s += string(ee.Stderr)
	}
	s = strings.ToLower(s)
	return strings.Contains(s, "notfound") || strings.Contains(s, "not found")
}
