// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package module définit le contrat commun à toutes les fonctionnalités de la
// suite Ceffio.
//
// POURQUOI CE PACKAGE EXISTE : le CLI et la console doivent pouvoir
// installer, observer et retirer les mêmes fonctionnalités sans dupliquer la
// logique ni se marcher dessus. En fixant ici une interface unique (et en
// n'important aucun autre package interne), on garantit que n'importe quel
// module — existant ou futur — est utilisable par les deux frontaux, et que
// le registre ne peut jamais créer de cycle d'import.
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
// POURQUOI une interface et non des fonctions libres : les deux frontaux
// (CLI, console) parcourent le même registre ; chaque fonctionnalité décide
// elle-même de SON installation, et le planificateur n'a qu'à appeler ces
// quatre méthodes dans le bon ordre.
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

// Kind distingue ce qui appartient au socle de ce qui est à la carte.
//
// POURQUOI deux catégories : la séquence d'installation ne traite que les
// modules Core (ils sont le produit) ; les Optional ne dépendent que d'une
// demande explicite, ce qui évite d'imposer des gigaoctets de services à un
// utilisateur qui n'en veut pas.
type Kind int

const (
	Core     Kind = iota // always installed, by the install sequence
	Optional             // installed on request, from the CLI or the console
)

// Info décrit un module de façon statique : tout ce que les frontaux doivent
// savoir SANS l'installer (affichage console, calcul d'ordre, prérequis).
type Info struct {
	ID          string // stable, kebab-case: "live-transcription"
	Title       string // shown in the console
	Description string // one or two sentences, shown in the console
	Kind        Kind
	Default     bool     // Optional only: installed by `ceffio install` unless --without
	Requires    []string // module IDs that must be installed first
	Namespaces  []string // where its pods live: status, doctor, uninstall

	Services  []Service // public exposures, for the status page
	Resources string    // "~9 GB disk, ~16 GB RAM", empty when negligible
	Warning   string    // shown before install, e.g. "settings cannot be changed in place"

	Permissions []Permission // what the CONSOLE needs to install/uninstall it
}

// Service décrit une exposition publique du module.
//
// POURQUOI déclarative : la page de statut et le doctor doivent lister les
// accès publics sans connaître les manifests internes de chaque module.
type Service struct {
	Sub, Name, Role string // "cloud", "Nextcloud", "Files, sharing and collaboration"

	// Technical marque un service destiné aux machines, pas aux humains :
	// il reste visible pour le diagnostic mais n'est pas présenté comme un
	// accès utilisateur.
	Technical   bool
	PodPrefixes []string
}

// Permission décrit les droits RBAC que la CONSOLE (et non le CLI, qui
// tourne en admin) doit obtenir pour gérer ce module.
//
// POURQUOI par module : la console fonctionne avec un compte de service aux
// droits minimaux ; chaque module déclare exactement ce dont il a besoin,
// rien de plus.
type Permission struct {
	Namespace string
	Rules     []rbacv1.PolicyRule // rbacv1 = k8s.io/api/rbac/v1
}

// Status is the lifecycle position of a module, as observed on the cluster.
//
// POURQUOI une chaîne et non un booléen installé/pas installé : un module
// peut être à moitié installé, dégradé, ou en cours de retrait — masquer ces
// états ferait mentir le doctor et la page de statut.
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
// Les balises JSON existent parce que la console sérialise l'état vers le
// navigateur ; le CLI l'affiche tel quel.
type State struct {
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`

	// Blocked: non-empty = cannot be installed now, and why. C'est la
	// réponse à « pourquoi le bouton installer est-il grisé ? » sans que la
	// console ait à recalculer les dépendances elle-même.
	Blocked string `json:"blocked,omitempty"`
}

// Env carries everything a module needs to act on a cluster.
//
// POURQUOI un type client et non un kubeconfig : le CLI et la console
// partagent déjà une connexion établie ; un module n'a pas à savoir qui
// l'appelle, et Out lui permet de raconter sa progression dans le bon canal
// (stdout pour le CLI, journal d'opération pour la console).
type Env struct {
	Domain string
	Kube   kubernetes.Interface // k8s.io/client-go/kubernetes
	Out    io.Writer            // CLI: stdout; console: the operation log
}
