// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package expos

import (
	"encoding/json"
	"fmt"
	"os"
)

// LireConfig loads the publication configuration from a JSON file.
//
// Why a file rather than options: the configuration contains the path to a
// credentials file, and gathering both on a command line invites writing a
// secret into the shell history.
//
// The file is looked for in this program, never in the repo: it describes the
// local infrastructure (firewall address, internal IP), not the application.
func LireConfig(chemin string) (Config, error) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return Config{}, fmt.Errorf("configuration %s unreadable: %w\n\n"+
			"Example file:\n%s", chemin, err, exemple)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("configuration %s invalid: %w", chemin, err)
	}

	// Default values: the reference installation carries *.ceffio.example.com.
	if cfg.Domaine == "" {
		cfg.Domaine = "ceffio.example.com"
	}
	if cfg.PortInterne == "" {
		cfg.PortInterne = "80"
	}
	if len(cfg.SousDomaines) == 0 {
		// "bao" is part of the suite just like the others: the vault needs a
		// PUBLIC address because OIDC authentication sends the browser back to
		// a return address. Without this entry, DNS answers and the certificate
		// is valid, but nothing reaches the cluster: the firewall returns an
		// empty response, which looks like a service outage when only the route
		// is missing.
		cfg.SousDomaines = []string{"cloud", "keycloak", "office", "admin", "bao"}
	}
	return cfg, nil
}

// The example carries PLACEHOLDERS, never a real address: a public repo is not
// an infrastructure notebook — an IP in it is reconnaissance, it locates the
// network of whoever published it.
const exemple = `{
  "hoteAPI": "firewall-api.example.com",
  "fichierCle": "~/.config/opnsense/apikey.txt",
  "domaine": "ceffio.example.com",
  "ipInterne": "CLUSTER-INTERNAL-IP",
  "portInterne": "80",
  "sousDomaines": ["cloud", "keycloak", "office", "admin"]
}`
