// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package module defines the contract shared by every feature of the Ceffio
// suite.
//
// WHY THIS PACKAGE EXISTS: the CLI and the console must be able to install,
// observe and remove the same features without duplicating the logic or
// stepping on each other. Fixing a single interface here (and importing no
// other internal package) guarantees that any module — existing or future —
// is usable by both frontends, and that the registry can never create an
// import cycle.
package module

import (
	"context"
	"io"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ceffio-suite/ceffio/internal/acme"
)

// Module is a feature of the suite: something that can be installed,
// observed and removed, by the CLI and by the console alike.
//
// WHY an interface and not free functions: both frontends (CLI, console)
// walk the same registry; each feature decides on ITS OWN installation, and
// the scheduler only has to call these four methods in the right order.
type Module interface {
	Info() Info

	// Install MUST be idempotent: it is called by the CLI, by the console,
	// and again after any interruption — re-running it on an installed
	// module must be a no-op, never a corruption.
	Install(ctx context.Context, env Env) error

	State(ctx context.Context, env Env) State

	// Uninstall MUST remove workloads, services and volumes it created:
	// a leftover PVC keeps consuming disk on a machine that believes the
	// module is gone, and a leftover Service keeps an exposure open.
	Uninstall(ctx context.Context, env Env) error
}

// Kind separates what belongs to the core product from what is opt-in.
//
// WHY two categories: the install sequence only handles Core modules (they
// are the product); Optional ones depend on an explicit request, which
// avoids forcing gigabytes of services on a user who does not want them.
type Kind int

const (
	Core     Kind = iota // always installed, by the install sequence
	Optional             // installed on request, from the CLI or the console
)

// Info describes a module statically: everything the frontends must know
// WITHOUT installing it (console display, order computation, prerequisites).
type Info struct {
	ID          string // stable, kebab-case: "live-transcription"
	Title       string // shown in the console
	Description string // one or two sentences, shown in the console
	Kind        Kind
	// Default says whether `ceffio install` lays down the module without an
	// explicit request.
	//
	// WHY this field exists for Core modules too: a Core module is ALWAYS
	// installed by the sequence (that is the definition of Kind) — Default
	// therefore always equals true there, and a frontend that filters the list
	// on Default (the console, `install --without …`) gets the same result as
	// going through Kind, without having to know the distinction. For an
	// Optional module, Default=false means "on request only".
	Default    bool
	Requires   []string // module IDs that must be installed first
	Namespaces []string // where its pods live: status, doctor, uninstall

	Services  []Service // public exposures, for the status page
	Resources string    // "~9 GB disk, ~16 GB RAM", empty when negligible
	Warning   string    // shown before install, e.g. "settings cannot be changed in place"

	Permissions []Permission // what the CONSOLE needs to install/uninstall it
}

// Service describes a public exposure of the module.
//
// WHY declarative: the status page and the doctor must list the public
// access points without knowing the internal manifests of each module.
type Service struct {
	Sub, Name, Role string // "cloud", "Nextcloud", "Files, sharing and collaboration"

	// SSO says whether access to the service goes through single sign-on
	// (Keycloak).
	//
	// WHY this field exists: the status page already displays it
	// (ServicePublic.SSO, fed by catalogueServices in
	// internal/console/status.go); without it in the registry, the console
	// could not reproduce the current /api/status answer from the modules
	// alone. Keycloak itself is false: it is the gateway, it does not go
	// through itself.
	SSO bool

	// Technical marks a service meant for machines, not for humans: it
	// stays visible for diagnostics but is not presented as a user-facing
	// access point.
	Technical   bool
	PodPrefixes []string
}

// Permission describes the RBAC rights the CONSOLE (not the CLI, which runs
// as admin) must obtain to manage this module.
//
// WHY per module: the console runs under a service account with minimal
// rights; each module declares exactly what it needs, nothing more.
type Permission struct {
	Namespace string
	Rules     []rbacv1.PolicyRule // rbacv1 = k8s.io/api/rbac/v1
}

// Status is the lifecycle position of a module, as observed on the cluster.
//
// WHY a string and not an installed/not-installed boolean: a module can be
// half-installed, degraded, or being removed — hiding those states would
// make the doctor and the status page lie.
type Status string

const (
	Absent     Status = "absent"
	Installing Status = "installing"
	Installed  Status = "installed"
	Degraded   Status = "degraded"
	Removing   Status = "removing"
	Unknown    Status = "unknown"
)

// State is what a module reports about itself on the cluster.
//
// The JSON tags exist because the console serializes the state to the
// browser; the CLI displays it as-is.
type State struct {
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`

	// Blocked: non-empty = cannot be installed now, and why. It is the
	// answer to "why is the install button greyed out?" without the console
	// having to recompute the dependencies itself.
	Blocked string `json:"blocked,omitempty"`
}

// Env carries everything a module needs to act on a cluster.
//
// WHY a client type and not a kubeconfig: the CLI and the console already
// share an established connection; a module does not have to know who calls
// it, and Out lets it report its progress on the right channel (stdout for
// the CLI, the operation log for the console).
//
// WHY Acme IS CARRIED HERE RATHER THAN READ FROM THE ENVIRONMENT BY EACH
// MODULE: the settings of one installation must have ONE answer. A module
// calling os.Getenv("CEFFIO_ACME_CHALLENGE") would work in isolation and then
// silently disagree with the installer the first time the value is set in a
// different place (a shell, a unit file, the console's own process). Passing
// the resolved value means every module — and both frontends — see the same
// configuration, and that a settings page can later feed it without any module
// changing.
type Env struct {
	Domain string
	Kube   kubernetes.Interface // k8s.io/client-go/kubernetes
	Out    io.Writer            // CLI: stdout; console: the operation log

	// ModuleID is the ID of the module this Env was built for.
	//
	// WHY IT IS HERE: settings are stored under the module's ID, and a module
	// calling the settings package knows its own ID — but threading it through
	// every call would carry a value the caller can get wrong. One answer to
	// "which module is this?" is what keeps two modules from writing to the
	// same place.
	ModuleID string

	// Settings and Secrets give access to the stores, as INTERFACES declared
	// here.
	//
	// WHY INTERFACES AND NOT THE CONCRETE PACKAGES: this package imports no
	// other internal package (a rule, verified by a test): every module imports
	// internal/module, so anything imported here becomes a dependency of every
	// module. Declaring the two methods a module needs — read and write one
	// entry from a ConfigMap and a Secret — keeps internal/settings free to
	// import whatever it wants, and lets a test substitute both with a map.
	Settings ConfigMapStore
	Secrets  SecretStore

	// Acme is the resolved ACME configuration (challenge, DNS provider).
	//
	// It is the zero value's business, not the module's, to be correct: a
	// caller that does not fill it leaves Challenge empty, which the ingress
	// module reads as "http01" — the historical behaviour. A read-only caller
	// (a status view) should use acme.HTTP01() explicitly rather than rely on
	// that, so that its answer does not depend on how it was constructed.
	//
	// Deprecated: the ingress module reads its challenge and provider through
	// its own settings, and this field goes with that change. It stays until
	// then because the module still reads it.
	Acme acme.Reglages
}

// ConfigMapStore reads and writes ordinary settings.
//
// It is the shape of a Kubernetes ConfigMap, reduced to what a module needs: one
// key at a time. Lire answers "" when the key is absent — that is a normal
// state before the first save, not an error.
type ConfigMapStore interface {
	Lire(ctx context.Context, ns, nom, cle string) (string, error)
	// Ecrire merges the given keys into the object, creating it if needed.
	Ecrire(ctx context.Context, ns, nom string, donnees map[string]string) error
	Supprimer(ctx context.Context, ns, nom, cle string) error
}

// SecretStore reads and writes secret settings when no vault is configured.
//
// SAME SHAPE AS ConfigMapStore, and deliberately so: `secrets.DepuisEnvironnement`
// already decides whether the vault is used, and the module should not have to
// know which store answered. A module that must write to a specific path
// overrides Apply and says why.
type SecretStore interface {
	Lire(ctx context.Context, ns, nom, cle string) (map[string]string, error)
	Ecrire(ctx context.Context, ns, nom string, donnees map[string]string) error
}
