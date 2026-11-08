// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package freshness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTP reads tags from the three registries the stack uses.
//
// ONE TYPE, THREE PROTOCOLS: Docker Hub answers JSON on a public endpoint,
// GHCR requires a token even to LIST tags, quay.io wants its own path. The
// caller does not care which — it asks for a repository and gets names.
type HTTP struct {
	Client *http.Client
	// Jeton rend le jeton d'anonyme pour GHCR; nil = the default.
	Jeton func(ctx context.Context, depot string) (string, error)
}

// NewHTTP returns an HTTP source with a sane timeout.
//
// A TIMEOUT IS NOT A DETAIL: a weekly job that hangs on one registry reports
// nothing about the other thirteen, which is the failure mode this package
// exists to avoid.
func NewHTTP() *HTTP {
	return &HTTP{Client: &http.Client{Timeout: 20 * time.Second}}
}

// Tags dispatches on the registry the repository belongs to.
func (h *HTTP) Tags(ctx context.Context, depot string) ([]string, error) {
	switch {
	case strings.HasPrefix(depot, "docker.io/"):
		return h.dockerHub(ctx, strings.TrimPrefix(depot, "docker.io/"))
	case strings.HasPrefix(depot, "ghcr.io/"):
		return h.ghcr(ctx, strings.TrimPrefix(depot, "ghcr.io/"))
	case strings.HasPrefix(depot, "quay.io/"):
		return h.quay(ctx, strings.TrimPrefix(depot, "quay.io/"))
	default:
		return nil, fmt.Errorf("registre inconnu pour %s", depot)
	}
}

// dockerHub lists the tags of a public Docker Hub repository.
func (h *HTTP) dockerHub(ctx context.Context, depot string) ([]string, error) {
	espace, nom := "library", depot
	if i := strings.Index(depot, "/"); i >= 0 {
		espace, nom = depot[:i], depot[i+1:]
	}
	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/%s/tags?page_size=100&ordering=last_updated",
		espace, nom)
	var reponse struct {
		Resultats []struct {
			Nom string `json:"name"`
		} `json:"results"`
	}
	if err := h.lire(ctx, url, "", &reponse); err != nil {
		return nil, err
	}
	tags := make([]string, 0, len(reponse.Resultats))
	for _, r := range reponse.Resultats {
		tags = append(tags, r.Nom)
	}
	return tags, nil
}

// ghcr lists the tags of a GHCR repository, anonymously.
func (h *HTTP) ghcr(ctx context.Context, depot string) ([]string, error) {
	jeton, err := h.jetonGHCR(ctx, depot)
	if err != nil {
		return nil, err
	}
	var reponse struct {
		Tags []string `json:"tags"`
	}
	if err := h.lire(ctx, "https://ghcr.io/v2/"+depot+"/tags/list?n=100", jeton, &reponse); err != nil {
		return nil, err
	}
	return reponse.Tags, nil
}

// jetonGHCR obtains the anonymous pull token GHCR requires even for /tags/list.
func (h *HTTP) jetonGHCR(ctx context.Context, depot string) (string, error) {
	if h.Jeton != nil {
		return h.Jeton(ctx, depot)
	}
	var reponse struct {
		Jeton string `json:"token"`
	}
	url := "https://ghcr.io/token?scope=repository:" + depot + ":pull"
	if err := h.lire(ctx, url, "", &reponse); err != nil {
		return "", fmt.Errorf("jeton GHCR: %w", err)
	}
	if reponse.Jeton == "" {
		return "", fmt.Errorf("jeton GHCR vide pour %s", depot)
	}
	return reponse.Jeton, nil
}

// quay lists the active tags of a quay.io repository.
func (h *HTTP) quay(ctx context.Context, depot string) ([]string, error) {
	var reponse struct {
		Tags []struct {
			Nom string `json:"name"`
		} `json:"tags"`
	}
	url := "https://quay.io/api/v1/repository/" + depot + "/tag/?limit=100&onlyActiveTags=true"
	if err := h.lire(ctx, url, "", &reponse); err != nil {
		return nil, err
	}
	tags := make([]string, 0, len(reponse.Tags))
	for _, t := range reponse.Tags {
		tags = append(tags, t.Nom)
	}
	return tags, nil
}

// lire is the one place that speaks HTTP, so the error messages stay the same
// for the three registries.
func (h *HTTP) lire(ctx context.Context, url, jeton string, cible any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if jeton != "" {
		req.Header.Set("Authorization", "Bearer "+jeton)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		corps, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("%s: HTTP %d (%s)", url, resp.StatusCode, strings.TrimSpace(string(corps)))
	}
	return json.NewDecoder(resp.Body).Decode(cible)
}
