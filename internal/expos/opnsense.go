// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package expos publishes a Ceffio installation behind an OPNsense firewall.
//
// WHY this package exists: deploying Ceffio is not enough to make it
// reachable. In the target infrastructure, the firewall (OPNsense) terminates
// the public TLS and routes to the VM; without the domains declared on the
// OPNsense side, DNS answers but nothing reaches the cluster. It used to be a
// manual step — it is now in the CLI, because a deployment that leaves a
// manual step is not reproducible.
//
// Complete sequence of a publication:
//  1. the public DNS exists (created by the user: *.ceffio.example.com);
//  2. the wildcard certificate exists on the OPNsense side (created by the
//     user);
//  3. the domains + handlers are declared in os-caddy  <- this package;
//  4. the public hosts are added to the Traefik Ingresses <- internal/ingress.
//
// Authentication uses an OPNsense API key, read from a file (never hardcoded,
// never in Git).
package expos

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config describes how to reach the firewall and what to publish.
type Config struct {
	HoteAPI     string // e.g. firewall-api.example.com
	FichierCle  string // file containing key= / secret=
	Domaine     string // public base domain, e.g. ceffio.example.com
	IPInterne   string // target: IP of the VM that carries Traefik
	PortInterne string // e.g. "80" (TLS is terminated on the firewall side)
	// CertificatRef: refId of the wildcard certificate on the OPNsense side.
	// If empty, it is looked up automatically by its SANs.
	CertificatRef string
	SousDomaines  []string // e.g. cloud, keycloak, office, admin
}

// Resultat reports what was done — and what already existed.
type Resultat struct {
	Certificat   string   `json:"certificat"`
	Created      []string `json:"crees"`
	Existants    []string `json:"existants"`
	Applique     bool     `json:"applique"`
	Avertissemts []string `json:"avertissements,omitempty"`
}

// Minimal client for the OPNsense API.
type client struct {
	hote string
	auth string
	http *http.Client
}

func newClient(cfg Config) (*client, error) {
	cle, err := lireCredential(cfg.FichierCle, "key")
	if err != nil {
		return nil, err
	}
	secret, err := lireCredential(cfg.FichierCle, "secret")
	if err != nil {
		return nil, err
	}
	// The file may use "key=" or "key:", with optional spaces: an overly
	// strict extraction returns an empty string, and an empty key produces no
	// error — just empty responses, very expensive to diagnose.
	if len(cle) < 20 || len(secret) < 20 {
		return nil, fmt.Errorf("OPNsense credentials misread in %s (key=%d chars, secret=%d chars)",
			cfg.FichierCle, len(cle), len(secret))
	}
	return &client{
		hote: cfg.HoteAPI,
		auth: base64.StdEncoding.EncodeToString([]byte(cle + ":" + secret)),
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// The firewall serves a self-signed certificate: we cannot
				// validate it without embedding its CA.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}, nil
}

func lireCredential(fichier, nom string) (string, error) {
	b, err := os.ReadFile(fichier)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", fichier, err)
	}
	re := regexp.MustCompile(`(?im)^\s*` + nom + `\s*[:=]\s*(\S+)`)
	m := re.FindStringSubmatch(string(b))
	if m == nil {
		return "", fmt.Errorf("field %q missing from %s", nom, fichier)
	}
	return strings.TrimSpace(m[1]), nil
}

func (c *client) appel(ctx context.Context, chemin, methode string, corps any) (string, error) {
	var body io.Reader
	if corps != nil {
		b, err := json.Marshal(corps)
		if err != nil {
			return "", err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, methode, "https://"+c.hote+"/api/"+chemin, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic "+c.auth)
	// Content-Type ONLY if there is a body: on a GET, this firewall answers
	// "Invalid JSON syntax" and the error looks like a dead API.
	if corps != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

// Publier declares the domains and their handlers, then applies.
func Publier(ctx context.Context, cfg Config, progress func(string)) (*Resultat, error) {
	if progress == nil {
		progress = func(string) {}
	}
	res := &Resultat{}

	cli, err := newClient(cfg)
	if err != nil {
		return res, err
	}

	// 1. Verify that the firewall answers — on a point that ALWAYS has
	//    content: an empty response on all paths signals a wrong host.
	out, err := cli.appel(ctx, "core/firmware/status", "GET", nil)
	if err != nil || len(out) < 10 {
		return res, fmt.Errorf("firewall unreachable at %s (%v)", cfg.HoteAPI, err)
	}

	// 2. Find the wildcard certificate covering the domain.
	cert := cfg.CertificatRef
	if cert == "" {
		out, err := cli.appel(ctx, "acmeclient/certificates/search", "GET", nil)
		if err != nil {
			return res, fmt.Errorf("reading certificates: %w", err)
		}
		var d struct {
			Rows []struct {
				Name      string `json:"name"`
				AltNames  string `json:"altNames"`
				CertRefID string `json:"certRefId"`
			} `json:"rows"`
		}
		if json.Unmarshal([]byte(out), &d) != nil {
			return res, fmt.Errorf("certificate response unreadable")
		}
		for _, r := range d.Rows {
			if strings.Contains(r.AltNames, cfg.Domaine) {
				cert = r.CertRefID
				break
			}
		}
	}
	if cert == "" {
		return res, fmt.Errorf("no certificate covering %s on the firewall (create it first)", cfg.Domaine)
	}
	res.Certificat = cert
	progress("certificate: " + cert)

	// 3. List the domains already declared, so as not to create a duplicate
	//    (a duplicate FromDomain creates a conflicting entry).
	out, _ = cli.appel(ctx, "caddy/reverse_proxy/search_reverse_proxy", "GET", nil)
	existants := map[string]string{}
	var dr struct {
		Rows []struct {
			FromDomain string `json:"FromDomain"`
			UUID       string `json:"uuid"`
		} `json:"rows"`
	}
	if json.Unmarshal([]byte(out), &dr) == nil {
		for _, r := range dr.Rows {
			existants[r.FromDomain] = r.UUID
		}
	}
	progress(fmt.Sprintf("%d domains already declared on the firewall", len(existants)))

	// 4. Create each domain + its handler.
	for _, sub := range cfg.SousDomaines {
		hote := sub + "." + cfg.Domaine
		if _, ok := existants[hote]; ok {
			res.Existants = append(res.Existants, hote)
			continue
		}
		out, err := cli.appel(ctx, "caddy/reverse_proxy/add_reverse_proxy", "POST", map[string]any{
			"reverse": map[string]string{
				"enabled": "1", "FromDomain": hote, "CustomCertificate": cert,
				"DnsChallenge": "0", "DisableTls": "0",
				"description": "Ceffio - " + sub,
			},
		})
		if err != nil {
			return res, fmt.Errorf("creating domain %s: %w", hote, err)
		}
		var rd struct {
			UUID string `json:"uuid"`
		}
		if json.Unmarshal([]byte(out), &rd) != nil || rd.UUID == "" {
			return res, fmt.Errorf("domain %s creation refused: %s", hote, tronque(out))
		}

		out, err = cli.appel(ctx, "caddy/reverse_proxy/add_handle", "POST", map[string]any{
			"handle": map[string]string{
				"enabled": "1", "reverse": rd.UUID, "HandleType": "handle",
				"HandleDirective": "reverse_proxy",
				"ToDomain":        cfg.IPInterne, "ToPort": cfg.PortInterne,
				// HttpTls "0": the internal leg stays HTTP, since the public
				// TLS is terminated by the firewall. Avoids any self-signed
				// certificate question between the firewall and the VM.
				"HttpTls": "0", "HttpTlsInsecureSkipVerify": "0",
			},
		})
		if err != nil {
			return res, fmt.Errorf("creating handler %s: %w", hote, err)
		}
		var rh struct {
			UUID string `json:"uuid"`
		}
		if json.Unmarshal([]byte(out), &rh) != nil || rh.UUID == "" {
			return res, fmt.Errorf("handler %s refused: %s", hote, tronque(out))
		}
		progress("+ " + hote)
		res.Created = append(res.Created, hote)
	}

	// 5. Apply — without the Content-Type, as for every POST without a body.
	if _, err := cli.appel(ctx, "caddy/service/reconfigure", "POST", nil); err != nil {
		return res, fmt.Errorf("applying configuration: %w", err)
	}
	res.Applique = true
	progress("configuration applied")
	return res, nil
}

func tronque(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
