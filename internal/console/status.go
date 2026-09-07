package console

import (
	"encoding/json"
	"net/http"
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
	Name  string `json:"name"`
	NS    string `json:"ns"`
	Ready string `json:"condition"`
}

// handleStatus renvoie le dashboard : pods par couche + ingress hosts + certs.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	layers := []string{"data", "identity", "files", "office", "chat", "video", "system"}
	var stack []Layer
	for _, l := range layers {
		out, err := kubeCombined("get", "pods", "-n", "ceffio-"+l, "-o", "json")
		if err != nil {
			stack = append(stack, Layer{Name: l})
			continue
		}
		var pl struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Status struct {
					ContainerStatuses []struct {
						Ready        bool `json:"ready"`
						RestartCount int  `json:"restartCount"`
					} `json:"containerStatuses"`
				} `json:"status"`
			} `json:"items"`
		}
		_ = json.Unmarshal([]byte(out), &pl)
		ly := Layer{Name: l}
		ly.Total = len(pl.Items)
		for _, it := range pl.Items {
			ready := false
			restarts := 0
			for _, c := range it.Status.ContainerStatuses {
				if c.Ready {
					ready = true
				}
				restarts += c.RestartCount
			}
			if ready {
				ly.Ready++
			}
			ly.Pods = append(ly.Pods, Pod{Name: it.Metadata.Name, Ready: ready, Restarts: restarts})
		}
		stack = append(stack, ly)
	}

	// ingress hosts
	var ing []IngressInfo
	if out, err := kubeCombined("get", "ingress", "-A", "-o", "json"); err == nil {
		var il struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec struct {
					Rules []struct {
						Host string `json:"host"`
					} `json:"rules"`
				} `json:"spec"`
			} `json:"items"`
		}
		_ = json.Unmarshal([]byte(out), &il)
		for _, it := range il.Items {
			for _, ru := range it.Spec.Rules {
				if ru.Host != "" {
					ing = append(ing, IngressInfo{Name: it.Metadata.Name, NS: it.Metadata.Namespace, Host: ru.Host})
				}
			}
		}
	}
	// certificats
	var certs []CertInfo
	if out, err := kubeCombined("get", "certificate", "-A", "-o", "json"); err == nil {
		var cl struct {
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
		_ = json.Unmarshal([]byte(out), &cl)
		for _, it := range cl.Items {
			cond := "?"
			for _, c := range it.Status.Conditions {
				if c.Type == "Ready" {
					cond = c.Status
				}
			}
			certs = append(certs, CertInfo{Name: it.Metadata.Name, NS: it.Metadata.Namespace, Ready: cond})
		}
	}

	writeJSON(w, 200, map[string]any{
		"domain":  s.Domain,
		"stack":   stack,
		"ingress": ing,
		"certs":   certs,
	})
}
