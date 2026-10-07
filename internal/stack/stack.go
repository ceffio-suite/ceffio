// Package stack interroge l'état réel d'une installation Ceffio via l'API
// Kubernetes. C'est la brique commune à `ceffio status` et `ceffio doctor`.
//
// Pourquoi ce package plutôt que du kubectl en ligne de commande : `status` et
// `doctor` doivent pouvoir dire ce qui est cassé même quand kubectl n'est pas
// utilisable (kubeconfig manquant, droits d'exécution). En passant par
// l'interface Go, on conserve un diagnostic exploitable et on produit des
// données structurées plutôt que du texte à re-parser.
package stack

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Couche de la pile : un namespace applicatif et les pods qu'il contient.
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

// State est un instantané complet de l'installation.
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

// Layers est la liste ordonnée des couches déployées par `ceffio install`.
// L'ordre suit celui du déploiement, pas l'alphabet : c'est celui qu'un humain
// veut lire quand il diagnostique.
// L'ordre suit celui du déploiement, pas l'alphabet : c'est celui qu'un humain
// veut lire quand il diagnostique.
//
// ATTENTION : un namespace ne doit apparaître qu'UNE fois. Les couches
// « plateforme » (cert-manager, issuers) et « console » (l'interface d'admin)
// partagent le namespace ceffio-system : les lister séparément faisait compter
// deux fois les mêmes pods, et le total affiché ne correspondait plus à la
// somme des couches.
var Layers = []struct{ Name, Namespace string }{
	{"plateforme", "ceffio-system"},
	{"données", "ceffio-data"},
	{"identité", "ceffio-identity"},
	{"fichiers", "ceffio-files"},
	{"bureau", "ceffio-office"},
	{"chat", "ceffio-chat"},
	{"visio", "ceffio-video"},
}

// Collecte interroge le cluster et renvoie un instantané complet.
// Ne retourne jamais d'erreur : une erreur devient un cluster injoignable,
// ce qui est exactement l'information dont `doctor` a besoin.
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

	// Pods de chaque couche.
	for _, l := range Layers {
		layer := Layer{Name: l.Name, Namespace: l.Namespace, Pods: []Pod{}}
		raw, err := kubectlJSON(ctx, "get", "pods", "-n", l.Namespace, "-o", "json")
		if err != nil {
			// Couche absente = information utile, on la garde vide.
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
				// Un pod terminé (phase Succeeded) a fini son travail : ni prêt
				// ni en panne. Le compter comme « non prêt » ferait échouer le
				// diagnostic sur une installation saine.
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

	// Certificats cert-manager.
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

	// Services exposés (LoadBalancer surtout : c'est par eux qu'on entre).
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
					svc.Status = "en attente d'adresse"
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
