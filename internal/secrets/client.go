package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// client wraps the HTTP calls to OpenBao.
//
// We talk to the HTTP API directly rather than embedding the SDK: the need is
// small (read and write a KV), and one more dependency in a product we want
// self-contained costs at every security update.
type client struct {
	cfg  *Coffre
	http *http.Client
}

func nouveauClient(cfg *Coffre) *client {
	return &client{
		cfg: cfg,
		// A short timeout: if the vault does not answer fast, we want to fall
		// back to Kubernetes rather than block the deployment.
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// entetes sets the headers common to all calls.
func (c *client) entetes(req *http.Request) {
	req.Header.Set("X-Vault-Token", c.cfg.Jeton)
	// The namespace is set in a header, not in the path. A valid token that
	// does not see the expected engine almost always comes from there.
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
}

// LireEntree returns ALL keys of a vault entry.
//
// WHY PER ENTRY AND NOT PER KEY: the first version read one key per path
// ("ceffio/nextcloud/password"). A vault organized that way cannot be
// browsed — you find "a password" without knowing what it opens, and
// searching for an account returns nothing. One entry per ACCOUNT carries its
// keys together, and reads at a glance.
//
// ErrEntreeAbsente distinguishes "this entry does not exist (yet)" from "the
// vault does not answer". Confusing the two would generate a fresh secret
// where it was enough to go and fetch it — exactly the risk we want to avoid.
var ErrEntreeAbsente = errors.New("entry absent from vault")

// The read goes through the `data/` path (versioned KV): it is the one that
// carries the VALUES, while `metadata/` only lists. Confusing the two gives
// `data: null` and makes the entry look empty.
func (c *client) LireEntree(ctx context.Context, composant, nom string) (map[string]string, error) {
	chemin := fmt.Sprintf("%s/v1/%s/data/%s",
		strings.TrimRight(c.cfg.Adresse, "/"), c.cfg.Moteur,
		c.cfg.Chemin(composant, nom))

	req, err := http.NewRequestWithContext(ctx, "GET", chemin, nil)
	if err != nil {
		return nil, err
	}
	c.entetes(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	brut, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w : %s", ErrEntreeAbsente, c.cfg.Chemin(composant, nom))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault refused (HTTP %d): %.150s",
			resp.StatusCode, string(brut))
	}

	// Shape of the KV v2 response:
	// {"data":{"data":{"<key>":"<value>"},"metadata":{...}}}
	var corps struct {
		Data struct {
			Data map[string]string `json:"data"`
			Meta struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(brut, &corps); err != nil {
		return nil, fmt.Errorf("unreadable response from vault: %w", err)
	}
	if len(corps.Data.Data) == 0 {
		return nil, fmt.Errorf("empty entry in vault: %s", c.cfg.Chemin(composant, nom))
	}
	return corps.Data.Data, nil
}

// Ecrire puts a value in the vault.
//
// Idempotent in the useful sense: rewriting the same value creates a new
// version, which is the intended behavior — history is kept, and a secret
// overwritten by mistake stays recoverable.
func (c *client) EcrireEntree(ctx context.Context, composant, nom string, donnees map[string]string) error {
	chemin := fmt.Sprintf("%s/v1/%s/data/%s",
		strings.TrimRight(c.cfg.Adresse, "/"), c.cfg.Moteur,
		c.cfg.Chemin(composant, nom))

	poids, err := json.Marshal(map[string]any{"data": donnees})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", chemin, strings.NewReader(string(poids)))
	if err != nil {
		return err
	}
	c.entetes(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		brut, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("write refused (HTTP %d): %.150s",
			resp.StatusCode, string(brut))
	}
	return nil
}

// Lister returns the keys of a prefix. Used for diagnosis (which secrets are
// in the vault), never for operation: a component reads what it knows, it
// does not explore.
//
// WHY `metadata/` AND NOT THE VALUES PATH: on a versioned KV, listing the
// values path fails with "Invalid path for a versioned K/V secrets engine".
// It is the metadata path that lists.
func (c *client) Lister(ctx context.Context, composant string) ([]string, error) {
	chemin := fmt.Sprintf("%s/v1/%s/metadata/%s?list=true",
		strings.TrimRight(c.cfg.Adresse, "/"), c.cfg.Moteur,
		c.cfg.Chemin(composant, ""))

	req, err := http.NewRequestWithContext(ctx, "GET", chemin, nil)
	if err != nil {
		return nil, err
	}
	c.entetes(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	brut, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing refused (HTTP %d)", resp.StatusCode)
	}

	var corps struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(brut, &corps); err != nil {
		return nil, err
	}
	return corps.Data.Keys, nil
}

// ---------------------------------------------------------------------------
// Access with fallback
// ---------------------------------------------------------------------------

// LireOuSecret returns a secret from the vault if configured, otherwise from
// the Kubernetes Secret.
//
// THIS IS THE HEART OF THE "OPTIONAL OpenBao" RULE: the caller asks for a
// value, without knowing where it comes from. If the vault is absent or
// unreachable, we fall back to Kubernetes with a warning — never a fatal
// error. A deployment failing because an optional vault is down would be a
// regression, not security.
//
// Priority order: vault first (it is the source of truth when present),
// Kubernetes as fallback. This is what allows rotating a secret by writing it
// in the vault, without touching the cluster.
func LireOuSecret(ctx context.Context, cfg *Coffre, composant, nom, cle, nsSecret, cleSecret string) (string, error) {
	if cfg.Dispo() {
		c := nouveauClient(cfg)
		entree, err := c.LireEntree(ctx, composant, nom)
		if err == nil {
			if v, ok := entree[cle]; ok && v != "" {
				return v, nil
			}
			// THE ENTRY EXISTS BUT THE KEY IS MISSING: we say so, then fall
			// back. It is not the same as an absent entry — confusing the two
			// would make an incomplete vault pass for an empty one, and the
			// cause would disappear from the report.
			fmt.Printf("  ∙ vault: key \"%s\" missing in %s — falling back to the Kubernetes Secret\n",
				cle, cfg.Chemin(composant, nom))
		} else {
			// A configured but unreachable vault is not a deployment failure:
			// we warn and continue.
			fmt.Printf("  ∙ vault unreachable for %s (%v) — falling back to the Kubernetes Secret\n",
				cfg.Chemin(composant, nom), err)
		}
	}
	return lireSecretK8s(ctx, nsSecret, cleSecret)
}

// LireEntreeCoffre reads a WHOLE entry, and falls back on NOTHING.
//
// It is the only read a migrated component should use: the vault is the
// single source, and no copy exists in Kubernetes anymore. Returning the
// error, rather than an empty string, distinguishes "absent entry" from
// "unreachable vault" — the first case calls for generation, the second for
// a clean failure.
func LireEntreeCoffre(ctx context.Context, cfg *Coffre, composant, nom string) (map[string]string, error) {
	if cfg == nil || !cfg.Dispo() {
		return nil, fmt.Errorf("no vault configured: cannot read %s/%s", composant, nom)
	}
	return nouveauClient(cfg).LireEntree(ctx, composant, nom)
}

// EntreeAbsente says whether the error means "this entry does not exist yet".
func EntreeAbsente(err error) bool {
	return errors.Is(err, ErrEntreeAbsente)
}

// EcrireDansCoffre puts a secret in the vault, if configured.
//
// If no vault is configured, we do NOTHING and say so: the secret stays in
// Kubernetes, and this is the nominal behavior of an installation without
// OpenBao.
func EcrireDansCoffre(ctx context.Context, cfg *Coffre, composant, nom string, donnees map[string]string) error {
	if !cfg.Dispo() {
		return nil
	}
	c := nouveauClient(cfg)
	if err := c.EcrireEntree(ctx, composant, nom, donnees); err != nil {
		return fmt.Errorf("cannot write to vault (%s/%s): %w",
			composant, nom, err)
	}
	// We NEVER display the values — only the path and the number of keys.
	fmt.Printf("  ∙ vault: %s written (%d key(s))\n", cfg.Chemin(composant, nom), len(donnees))
	return nil
}

// lireSecretK8s reads a secret from a Kubernetes Secret (fallback).
func lireSecretK8s(ctx context.Context, ns, cle string) (string, error) {
	out, err := kubeGet(ctx, "get", "secret", ns, "-o",
		fmt.Sprintf("jsonpath={.data.%s}", cle))
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("secret %s/%s not found", ns, cle)
	}
	return decoderBase64(out)
}

// kubeGet runs kubectl and returns the output.
func kubeGet(ctx context.Context, args ...string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", args...)
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// decoderBase64 decodes a Kubernetes Secret value.
//
// Kubernetes stores values in base64: we decode here, once, instead of
// letting each caller do it — the classic source of a password that "does not
// work" because it is compared encoded.
func decoderBase64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("unreadable base64 value: %w", err)
	}
	return string(b), nil
}
