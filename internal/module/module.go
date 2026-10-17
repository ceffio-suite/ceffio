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
	// Default dit si `ceffio install` pose le module sans demande explicite.
	//
	// POURQUOI ce champ existe aussi pour les Core : un Core est TOUJOURS
	// installé par la séquence (c'est la définition de Kind) — Default y
	// vaut donc toujours true, et un frontal qui filtre la liste sur
	// Default (la console, `install --without …`) obtient le même résultat
	// qu'en passant par Kind, sans avoir à connaître la distinction. Pour
	// un Optional, Default=false signifie « sur demande uniquement ».
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

	// SSO dit si l'accès au service passe par l'authentification unique
	// (Keycloak).
	//
	// POURQUOI ce champ existe : la page de statut l'affiche déjà
	// (ServicePublic.SSO, alimenté par catalogueServices dans
	// internal/console/status.go) ; sans lui dans le registre, la console
	// ne pourrait pas reproduire la réponse actuelle de /api/status à
	// partir des seuls modules. Keycloak lui-même vaut false : c'est la
	// porte d'entrée, elle ne passe pas par elle-même.
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
type Env struct {
	Domain string
	Kube   kubernetes.Interface // k8s.io/client-go/kubernetes
	Out    io.Writer            // CLI: stdout; console: the operation log
}
