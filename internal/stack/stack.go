// Package stack queries the real state of a Ceffio installation through the
// Kubernetes API. It is the common building block for `ceffio status` and
// `ceffio doctor`.
//
// Why this package rather than command-line kubectl: `status` and `doctor`
// must be able to say what is broken even when kubectl cannot be used
// (missing kubeconfig, execution permissions). By going through the Go API,
// we keep an actionable diagnostic and produce structured data instead of
// text to be re-parsed.
package stack

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Layer of the stack: an application namespace and the pods it contains.
type Layer struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Ready     int    `json:"ready"`
	Total     int    `json:"total"`
	Restarts  int    `json:"restarts"`
	Pods      []Pod  `json:"pods"`
}

type Pod struct {
	Name      string `json:"name"`
	Phase     string `json:"phase"`
	Ready     bool   `json:"ready"`
	Completed bool   `json:"completed,omitempty"`
	Restarts  int    `json:"restarts"`
}

type Ingress struct {
	Name string `json:"name"`
	NS   string `json:"ns"`
	Host string `json:"host"`
}

type Certificate struct {
	Name      string `json:"name"`
	NS        string `json:"ns"`
	Ready     bool   `json:"ready"`
	Condition string `json:"condition"`
}

type Service struct {
	Name   string `json:"name"`
	NS     string `json:"ns"`
	Type   string `json:"type"`
	IP     string `json:"ip,omitempty"`
	Port   string `json:"port,omitempty"`
	Status string `json:"status,omitempty"`
}

// State is a complete snapshot of the installation.
type State struct {
	ClusterReachable bool          `json:"cluster_reachable"`
	ClusterError     string        `json:"cluster_error,omitempty"`
	Nodes            []Node        `json:"nodes"`
	NodesReady       int           `json:"nodes_ready"`
	Layers           []Layer       `json:"layers"`
	Ingresses        []Ingress     `json:"ingresses"`
	Certificates     []Certificate `json:"certificates"`
	Services         []Service     `json:"services"`
	Domain           string        `json:"domain,omitempty"`
	TotalPods        int           `json:"total_pods"`
	ReadyPods        int           `json:"ready_pods"`
	CompletedPods    int           `json:"completed_pods"`
	TotalRestarts    int           `json:"total_restarts"`
}

type Node struct {
	Name       string `json:"name"`
	Ready      bool   `json:"ready"`
	Version    string `json:"version,omitempty"`
	InternalIP string `json:"internal_ip,omitempty"`
	Roles      string `json:"roles,omitempty"`
}

// Layers is the ordered list of layers deployed by `ceffio install`.
// The order follows the deployment order, not the alphabet: it is the one a
// human wants to read when diagnosing.
//
// WARNING: a namespace must appear only ONCE. The "platform" layer
// (cert-manager, issuers) and the "console" layer (the admin interface)
// share the ceffio-system namespace: listing them separately counted the
// same pods twice, and the displayed total no longer matched the sum of the
// layers.
var Layers = []struct{ Name, Namespace string }{
	{"platform", "ceffio-system"},
	{"data", "ceffio-data"},
	{"identity", "ceffio-identity"},
	{"files", "ceffio-files"},
	{"office", "ceffio-office"},
	{"chat", "ceffio-chat"},
	{"video", "ceffio-video"},
}

// Collect queries the cluster and returns a complete snapshot.
// Never returns an error: an error becomes an unreachable cluster, which is
// exactly the information `doctor` needs.
func Collect(ctx context.Context) *State {
	st := &State{Layers: []Layer{}, Nodes: []Node{}, Ingresses: []Ingress{},
		Certificates: []Certificate{}, Services: []Service{}}

	nodes, err := kubectlJSON(ctx, "get", "nodes", "-o", "json")
	if err != nil {
		st.ClusterReachable = false
		st.ClusterError = err.Error()
		return st
	}
	st.ClusterReachable = true

	var nl struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				NodeInfo struct {
					KubeletVersion string `json:"kubeletVersion"`
				} `json:"nodeInfo"`
				Addresses []struct {
					Type    string `json:"type"`
					Address string `json:"address"`
				} `json:"addresses"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(nodes, &nl); err == nil {
		for _, n := range nl.Items {
			nd := Node{Name: n.Metadata.Name, Version: n.Status.NodeInfo.KubeletVersion}
			for _, a := range n.Status.Addresses {
				if a.Type == "InternalIP" {
					nd.InternalIP = a.Address
				}
			}
			for _, c := range n.Status.Conditions {
				if c.Type == "Ready" && c.Status == "True" {
					nd.Ready = true
				}
			}
			var roles []string
			for l := range n.Metadata.Labels {
				if strings.HasPrefix(l, "node-role.kubernetes.io/") {
					roles = append(roles, strings.TrimPrefix(l, "node-role.kubernetes.io/"))
				}
			}
			if len(roles) == 0 {
				nd.Roles = "worker"
			} else {
				sort.Strings(roles)
				nd.Roles = strings.Join(roles, ",")
			}
			if nd.Ready {
				st.NodesReady++
			}
			st.Nodes = append(st.Nodes, nd)
		}
	}

	// Pods of each layer.
	for _, l := range Layers {
		layer := Layer{Name: l.Name, Namespace: l.Namespace, Pods: []Pod{}}
		raw, err := kubectlJSON(ctx, "get", "pods", "-n", l.Namespace, "-o", "json")
		if err != nil {
			// Missing layer = useful information, we keep it empty.
			st.Layers = append(st.Layers, layer)
			continue
		}
		var pl struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Status struct {
					Phase             string `json:"phase"`
					ContainerStatuses []struct {
						Ready        bool `json:"ready"`
						RestartCount int  `json:"restartCount"`
					} `json:"containerStatuses"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &pl); err == nil {
			for _, p := range pl.Items {
				pod := Pod{Name: p.Metadata.Name, Phase: p.Status.Phase}
				for _, cs := range p.Status.ContainerStatuses {
					if cs.Ready {
						pod.Ready = true
					}
					pod.Restarts += cs.RestartCount
				}
				// A finished pod (phase Succeeded) has completed its work:
				// neither ready nor failing. Counting it as "not ready" would
				// fail the diagnostic on a healthy installation.
				if pod.Phase == "Succeeded" {
					pod.Ready = true
					pod.Completed = true
					st.CompletedPods++
				}
				layer.Total++
				layer.Restarts += pod.Restarts
				if pod.Ready {
					layer.Ready++
					st.ReadyPods++
				}
				st.TotalPods++
				st.TotalRestarts += pod.Restarts
				layer.Pods = append(layer.Pods, pod)
			}
		}
		sort.Slice(layer.Pods, func(a, b int) bool { return layer.Pods[a].Name < layer.Pods[b].Name })
		st.Layers = append(st.Layers, layer)
	}

	// Ingress.
	if raw, err := kubectlJSON(ctx, "get", "ingress", "-A", "-o", "json"); err == nil {
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
		if err := json.Unmarshal(raw, &il); err == nil {
			for _, i := range il.Items {
				for _, r := range i.Spec.Rules {
					if r.Host == "" {
						continue
					}
					st.Ingresses = append(st.Ingresses, Ingress{
						Name: i.Metadata.Name, NS: i.Metadata.Namespace, Host: r.Host,
					})
					if st.Domain == "" {
						st.Domain = deriveDomain(r.Host)
					}
				}
			}
			sort.Slice(st.Ingresses, func(a, b int) bool {
				return st.Ingresses[a].Host < st.Ingresses[b].Host
			})
		}
	}

	// cert-manager certificates.
	if raw, err := kubectlJSON(ctx, "get", "certificates", "-A", "-o", "json"); err == nil {
		var cl struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Status struct {
					Conditions []struct {
						Type    string `json:"type"`
						Status  string `json:"status"`
						Reason  string `json:"reason"`
						Message string `json:"message"`
					} `json:"conditions"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &cl); err == nil {
			for _, c := range cl.Items {
				cert := Certificate{Name: c.Metadata.Name, NS: c.Metadata.Namespace}
				for _, cond := range c.Status.Conditions {
					if cond.Type == "Ready" {
						cert.Ready = cond.Status == "True"
						cert.Condition = cond.Status
						if !cert.Ready && cond.Reason != "" {
							cert.Condition = cond.Reason
						}
					}
				}
				st.Certificates = append(st.Certificates, cert)
			}
			sort.Slice(st.Certificates, func(a, b int) bool {
				return st.Certificates[a].Name < st.Certificates[b].Name
			})
		}
	}

	// Exposed services (mostly LoadBalancer: that's how we get in).
	if raw, err := kubectlJSON(ctx, "get", "svc", "-A", "-o", "json"); err == nil {
		var sl struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec struct {
					Type  string `json:"type"`
					Ports []struct {
						Port     int    `json:"port"`
						NodePort int    `json:"nodePort"`
						Protocol string `json:"protocol"`
					} `json:"ports"`
				} `json:"spec"`
				Status struct {
					LoadBalancer struct {
						Ingress []struct {
							IP       string `json:"ip"`
							Hostname string `json:"hostname"`
						} `json:"ingress"`
					} `json:"loadBalancer"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &sl); err == nil {
			for _, s := range sl.Items {
				if s.Spec.Type != "LoadBalancer" && s.Spec.Type != "NodePort" {
					continue
				}
				svc := Service{Name: s.Metadata.Name, NS: s.Metadata.Namespace, Type: s.Spec.Type}
				for _, ing := range s.Status.LoadBalancer.Ingress {
					if ing.IP != "" {
						svc.IP = ing.IP
					} else {
						svc.IP = ing.Hostname
					}
				}
				var ports []string
				for _, p := range s.Spec.Ports {
					if p.Protocol == "UDP" || p.Protocol == "SCTP" {
						ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
					} else {
						ports = append(ports, fmt.Sprintf("%d", p.Port))
					}
				}
				svc.Port = strings.Join(ports, ",")
				if s.Spec.Type == "LoadBalancer" && svc.IP == "" {
					svc.Status = "waiting for address"
				}
				st.Services = append(st.Services, svc)
			}
			sort.Slice(st.Services, func(a, b int) bool {
				if st.Services[a].NS != st.Services[b].NS {
					return st.Services[a].NS < st.Services[b].NS
				}
				return st.Services[a].Name < st.Services[b].Name
			})
		}
	}

	return st
}
