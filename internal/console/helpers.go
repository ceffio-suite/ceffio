// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

// Helpers used by several console pages, kept here rather than beside one of
// them. Most of them lived in smtp.go, which moved to the files module when the
// SMTP settings became the module's: what remained was not about SMTP at all,
// and leaving it there would have deleted callers across the console.

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// tronquer shortens a value for a log line or a table cell.
//
// IT COLLAPSES NEWLINES TOO: an occ output or an API error carries a whole
// message, and printing it raw breaks the alignment of every table it lands in.
func tronquer(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// premier returns the first non-empty value.
func premier(valeurs ...string) string {
	for _, v := range valeurs {
		if v != "" {
			return v
		}
	}
	return ""
}

// podNextcloud returns a running Nextcloud pod, for the pages that run occ.
//
// WHY THE POD AND NOT THE DEPLOYMENT: `kubectl exec` addresses a pod, and the
// deployment's name is not enough for it. Reading the pod here means every page
// that needs occ shares one answer to "which pod?", instead of each picking the
// deployment and failing at the first restart.
func (s *Server) podNextcloud(ctx context.Context) (string, error) {
	pods, err := s.kube.CoreV1().Pods("ceffio-files").List(ctx, metav1.ListOptions{
		LabelSelector: "app=nextcloud",
	})
	if err != nil {
		return "", err
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			return p.Name, nil
		}
	}
	return "", fmt.Errorf("no Nextcloud pod in service")
}
