// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package socle regroupe les lectures d'état partagées par les modules des
// dix couches du socle (Kind Core).
//
// POURQUOI UN PACKAGE PARTAGÉ : les dix modules lisent l'état de la même
// façon — compter les pods prêts qui portent leurs charges — et les règles de
// filtrage (ignorer les pods en Terminating, ne pas compter un job Succeeded
// comme « pas prêt », un pod sans statut de conteneur n'est pas prêt) sont
// EXACTEMENT celles de la page de statut (internal/console/status.go). Les
// dupliquer dix fois garantirait dix dérives silencieuses ; les partager
// garantit une seule vérité entre le CLI, la console et le doctor.
//
// Ce package n'enregistre AUCUN module (pas d'appel à module.Register) : il
// n'a donc pas à figurer dans internal/modules/all.go, et le test garde-fou
// all_test.go ne le réclame pas.
package socle

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// sansClient est l'état renvoyé quand Env ne porte pas de client Kubernetes :
// sans connexion au cluster, toute lecture serait une invention. On répond
// Unknown, jamais Absent — l'absence est un fait observé, pas un défaut de
// point de vue.
func sansClient() module.State {
	return module.State{Status: module.Unknown, Detail: "no Kubernetes client in the environment"}
}

// porte dit si le nom du pod est porté par l'un des préfixes, avec la même
// règle que porteService dans internal/console/status.go : le nom doit
// commencer par « préfixe- », pour que « talk-signaling » ne matche pas un
// pod « talk-recording-… ».
func porte(podNom string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(podNom, p+"-") {
			return true
		}
	}
	return false
}

// podPret reprend la règle de la page de statut : tous les conteneurs prêts,
// et au moins un statut de conteneur — un pod qui n'a encore aucun statut
// (image en cours de tirage) n'est pas prêt.
func podPret(p corev1.Pod) bool {
	if len(p.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, cs := range p.Status.ContainerStatuses {
		if !cs.Ready {
			return false
		}
	}
	return true
}

// EtatDesPods calcule l'état d'un module à partir des pods de ses namespaces
// dont le nom commence par l'un des préfixes.
//
// POURQUOI ces seuils : aucun pod → Absent (la couche n'est pas là) ; tous
// prêts → Installed ; sinon Degraded avec le compte réel. Un échec de
// lecture (API injoignable, namespace illisible) → Unknown : on ne conclut
// jamais « absent » sur un échec, exactement comme les modules existants.
func EtatDesPods(ctx context.Context, env module.Env, namespaces []string, prefixes []string) module.State {
	if env.Kube == nil {
		return sansClient()
	}
	total, prets := 0, 0
	for _, ns := range namespaces {
		pods, err := env.Kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return module.State{Status: module.Unknown,
				Detail: fmt.Sprintf("listing pods in %s: %v", ns, err)}
		}
		for _, p := range pods.Items {
			// Même filtrage que la page de statut : un pod en cours de
			// suppression fausse les totaux, et un job terminé
			// (Succeeded) n'est pas « pas prêt ».
			if p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded {
				continue
			}
			if !porte(p.Name, prefixes) {
				continue
			}
			total++
			if podPret(p) {
				prets++
			}
		}
	}
	switch {
	case total == 0:
		return module.State{Status: module.Absent}
	case prets == total:
		return module.State{Status: module.Installed}
	case prets > 0:
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("%d/%d pods ready", prets, total)}
	default:
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("0/%d pods ready", total)}
	}
}

// EtatDuDeploiement lit l'état d'un Deployment précis (nom + namespace).
//
// POURQUOI un helper distinct : certaines charges du socle ne se repèrent
// pas par préfixe de pod dans LEURS namespaces (l'opérateur CNPG vit dans
// cnpg-system, cert-manager dans cert-manager) ; le déploiement prêt est
// alors le signal le plus direct. Comme k8sapi.DeploiementPret, on lit le
// statut et non la seule existence : un Deployment à zéro réplique prête
// existe, et répondre « installé » pour lui annoncerait un service qui ne
// sert rien.
func EtatDuDeploiement(ctx context.Context, env module.Env, ns, nom string) module.State {
	if env.Kube == nil {
		return sansClient()
	}
	d, err := env.Kube.AppsV1().Deployments(ns).Get(ctx, nom, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return module.State{Status: module.Absent}
	case err != nil:
		return module.State{Status: module.Unknown,
			Detail: fmt.Sprintf("reading deployment %s/%s: %v", ns, nom, err)}
	case d.Status.ReadyReplicas > 0:
		return module.State{Status: module.Installed}
	default:
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("deployment %s/%s exists but has no ready replica", ns, nom)}
	}
}

// EtatNamespaceActif renvoie Installed si le namespace existe et est Active,
// Absent s'il n'existe pas, Unknown si la lecture échoue.
//
// POURQUOI lire la phase et non la seule existence : un namespace en
// Terminating existe encore mais n'accepte plus aucune création — répondre
// « installé » pour lui ferait échouer le déploiement suivant sans que le
// diagnostic n'ait rien vu.
func EtatNamespaceActif(ctx context.Context, env module.Env, nom string) module.State {
	if env.Kube == nil {
		return sansClient()
	}
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, nom, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return module.State{Status: module.Absent}
	case err != nil:
		return module.State{Status: module.Unknown,
			Detail: fmt.Sprintf("reading namespace %s: %v", nom, err)}
	case ns.Status.Phase == corev1.NamespaceActive:
		return module.State{Status: module.Installed}
	default:
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("namespace %s is %s", nom, ns.Status.Phase)}
	}
}

// EtatLePlusBas combine plusieurs états : un module adossé à plusieurs
// charges n'est « installé » que si TOUTES le sont.
//
// POURQUOI Unknown l'emporte : si l'une des lectures n'a pas pu aboutir, on
// ne peut rien conclure — répondre Degraded inventerait un diagnostic, et
// répondre Installed masquerait l'inconnu.
func EtatLePlusBas(etats ...module.State) module.State {
	installes, absents := 0, 0
	var details []string
	for _, e := range etats {
		if e.Status == module.Unknown {
			return e
		}
		switch e.Status {
		case module.Installed:
			installes++
		case module.Absent:
			absents++
		}
		if e.Detail != "" {
			details = append(details, e.Detail)
		}
	}
	detail := strings.Join(details, "; ")
	switch {
	case installes == len(etats):
		return module.State{Status: module.Installed, Detail: detail}
	case absents == len(etats):
		return module.State{Status: module.Absent}
	default:
		return module.State{Status: module.Degraded, Detail: detail}
	}
}

// ErreurSocleIndemontable est l'erreur renvoyée par Uninstall pour toute
// couche du socle.
//
// POURQUOI UNE ERREUR ET NON UN RETRAIT : les dix couches sont le produit —
// l'interface Module exige Uninstall, mais aucune désinstallation par couche
// n'existe ni n'a de sens (retirer PostgreSQL ou l'identité laisserait une
// suite amnésique qui se croirait saine). La vraie désinstallation est
// `ceffio uninstall`, qui détruit le cluster entier. Une fonction qui
// prétendrait retirer la couche mentirait ; une erreur explicite dit la
// vérité et empêche un frontal de déclencher un retrait partiel destructif.
func ErreurSocleIndemontable(id string) error {
	return fmt.Errorf("%s is a core layer of the suite: it is removed with the cluster (ceffio uninstall), not on its own", id)
}
