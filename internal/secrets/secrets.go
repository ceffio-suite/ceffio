// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package secrets centralizes secret management for the Ceffio components.
//
// WHY THIS MODULE: today each component generates its secrets and sets them
// in a Kubernetes Secret, in its own corner. It works, but the operator has
// no single place to see them, rotate them, or back them up otherwise than by
// backing up the whole cluster. OpenBao brings that single place.
//
// DESIGN CONSTRAINT — OpenBao is OPTIONAL, never mandatory.
// Ceffio must stay "self-contained in one command": an SMB without OpenBao
// must be able to deploy the full suite. The vault is therefore an
// IMPROVEMENT, not a prerequisite:
//
//	vault configured → secrets are read from the vault, with fallback on
//	                   the Kubernetes Secret if the vault is unreachable;
//	vault absent     → we generate and set the secrets in Kubernetes, as before.
//
// This rule comes from a real constraint: a product that cannot be installed
// without an extra brick is not self-contained.
//
// What the vault carries, and what it does NOT carry:
//   - it carries what components CONSUME (database passwords, API keys,
//     session secrets);
//   - it does NOT carry what Ceffio MAKES for its users (API tokens created
//     on the fly): those live in the application database, ideally as a
//     fingerprint;
//   - it cannot carry its own unseal key — that is the zero-secret, to be
//     documented as such.
package secrets

import (
	"fmt"
	"os"
	"strings"
)

// Coffre describes a reachable OpenBao vault.
//
// The credentials come from the ENVIRONMENT, never from a versioned
// configuration file: it is the only way to use the same module with
// different vaults depending on the deployment.
type Coffre struct {
	Adresse   string // BAO_ADDR (e.g. https://bao.example.com)
	Jeton     string // BAO_TOKEN (token or AppRole token)
	Namespace string // BAO_NAMESPACE, empty if the engine is at the root
	Moteur    string // name of the KV engine (kv, secret…)
}

// DepuisEnvironnement builds the vault configuration from BAO_*.
//
// We do NOT try to guess: if the address is missing, we return nil and the
// caller falls back to Kubernetes. A misconfigured vault must never fail a
// deployment — this is the rule that guarantees OpenBao stays optional.
func DepuisEnvironnement() *Coffre {
	adresse := strings.TrimSpace(os.Getenv("BAO_ADDR"))
	if adresse == "" {
		return nil
	}
	// The engine name: `kv` is the Ceffio (and OpenBao) convention, but it is
	// configurable because the REAL name decides the path — a vault can expose
	// `secret/` at the root and `kv/` in a namespace.
	moteur := strings.TrimSpace(os.Getenv("BAO_MOTEUR"))
	if moteur == "" {
		moteur = "kv"
	}
	return &Coffre{
		Adresse: adresse,
		Jeton:   strings.TrimSpace(os.Getenv("BAO_TOKEN")),
		// A token read from a file can carry a trailing \r: the header would
		// then be silently corrupted and the API would answer "permission
		// denied" as if the token were wrong.
		Namespace: strings.TrimSpace(os.Getenv("BAO_NAMESPACE")),
		Moteur:    moteur,
	}
}

// Prefixe returns the path prefix of Ceffio secrets in the vault.
//
// A dedicated prefix ("ceffio/") rather than a namespace: isolation by
// namespace is expensive (authentication and policies to recreate in each)
// and only logical, not cryptographic — all share the same unseal key. A
// prefix per application gives the same property for much less, and suffices
// as long as there is no real separate trust domain.
func (c *Coffre) Prefixe() string {
	return "ceffio"
}

// Chemin returns the full path of a secret in the vault.
//
// The convention: ceffio/<component>/<name>. It reads left to right and
// answers "where does this secret come from" without documentation.
func (c *Coffre) Chemin(composant, nom string) string {
	return fmt.Sprintf("%s/%s/%s", c.Prefixe(), composant, nom)
}

// Dispo says whether a vault is configured, so the caller does not have to
// test nil itself. An absent vault is NOT an error: it is the nominal case of
// an installation without OpenBao.
func (c *Coffre) Dispo() bool {
	return c != nil && c.Adresse != ""
}

// Description returns a readable description of the vault, WITHOUT ever
// exposing the token. A secret value must never appear anywhere, not even in
// a startup log: only print what identifies the vault.
func (c *Coffre) Description() string {
	if !c.Dispo() {
		return "no vault configured (secrets managed in Kubernetes)"
	}
	ns := c.Namespace
	if ns == "" {
		ns = "(root)"
	}
	return fmt.Sprintf("%s, engine \"%s\", namespace %s", c.Adresse, c.Moteur, ns)
}
