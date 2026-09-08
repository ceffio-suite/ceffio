package console

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Layer décrit l'état d'une couche de la pile.
type Layer struct {
	Name  string `json:"name"`
	Ready int    `json:"ready"`
	Total int    `json:"total"`
	Pods  []Pod  `json:"pods"`
}

type Pod struct {
	Name     string `json:"name"`
	Ready    bool   `json:"ready"`
	Restarts int    `json:"restarts"`
}

type IngressInfo struct {
	Name string `json:"name"`
	Host string `json:"host"`
	NS   string `json:"ns"`
}

type CertInfo struct {
	Name      string `json:"name"`
	NS        string `json:"ns"`
	Condition string `json:"condition"`
}

// handleStatus renvoie le dashboard via l'API K8s in-cluster (client-go + SA du pod).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	layers := []string{"data", "identity", "files", "office", "chat", "video", "system"}
	var stack []Layer
	for _, l := range layers {
		ly := Layer{Name: l}
		pl, err := s.kube.CoreV1().Pods("ceffio-"+l).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, p := range pl.Items {
				ready := false
				restarts := 0
				for _, cs := range p.Status.ContainerStatuses {
					if cs.Ready {
						ready = true
					}
					restarts += int(cs.RestartCount)
				}
				ly.Total++
				if ready {
					ly.Ready++
				}
				ly.Pods = append(ly.Pods, Pod{Name: p.Name, Ready: ready, Restarts: restarts})
			}
		}
		stack = append(stack, ly)
	}

	// Ingress (networking.k8s.io/v1) — triés par host.
	var ing []IngressInfo
	il, err := s.kube.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, i := range il.Items {
			for _, ru := range i.Spec.Rules {
				if ru.Host != "" {
					ing = append(ing, IngressInfo{Name: i.Name, NS: i.Namespace, Host: ru.Host})
				}
			}
		}
		sort.Slice(ing, func(a, b int) bool { return ing[a].Host < ing[b].Host })
	}

	// Certificats cert-manager : ressource non typée → on lit via l'API dynamique légère
	// (sans se lier aux types cert-manager). Statut Ready.
	certs := s.listCerts(ctx)

	writeJSON(w, 200, map[string]any{
		"domain":  s.Domain,
		"stack":   stack,
		"ingress": ing,
		"certs":   certs,
	})
}

// listCerts lit les Certificate cert-manager via le schéma non structuré (dynamic client).
func (s *Server) listCerts(ctx context.Context) []CertInfo {
	out := []CertInfo{}
	list, err := s.kube.Discovery().RESTClient().Get().AbsPath("/apis/cert-manager.io/v1", "certificates").DoRaw(ctx)
	if err != nil {
		return out
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(list, &doc); err != nil {
		return out
	}
	for _, it := range doc.Items {
		cond := "?"
		for _, c := range it.Status.Conditions {
			if c.Type == "Ready" {
				cond = c.Status
			}
		}
		out = append(out, CertInfo{Name: it.Metadata.Name, NS: it.Metadata.Namespace, Condition: cond})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}
