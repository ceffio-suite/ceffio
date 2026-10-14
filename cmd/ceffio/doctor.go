package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/stack"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	var bundle bool
	var asJSON bool

	c := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose the state of the platform",
		Long: `Checks the platform layer by layer and reports the problems that are actually
detectable: nodes not ready, pods failing or in a restart loop, certificates
not issued, exposed services without an address, unresponsive ingress.

Each problem is reported with a probable cause and a lead for the fix —
this is not a plain state snapshot (for that, see "ceffio status").

With --bundle, produces a support archive to hand to the maintainer:
it contains NO secret (no Secret value, no password, no private key),
only states and redacted logs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			st := stack.Collect(cmd.Context())
			findings := diagnose(st)
			report := stack.Report{State: st, Findings: findings}

			if asJSON {
				return stack.WriteJSON(os.Stdout, report)
			}

			printDoctor(report)

			if bundle {
				path, err := stack.WriteBundle(report)
				if err != nil {
					return fmt.Errorf("producing the bundle: %w", err)
				}
				fmt.Printf("\nSupport archive: %s\n", path)
				fmt.Println("(with no secrets: Secret values, passwords and private keys excluded)")
			}

			if len(findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	c.Flags().BoolVar(&bundle, "bundle", false, "Produce a support archive (ceffio-support-*.tar.gz)")
	c.Flags().BoolVar(&asJSON, "json", false, "JSON output")

	return c
}

// diagnose turns a state into a list of actionable problems.
//
// Principle: only report what we can act on. A "Completed" pod is not an
// anomaly (a finished migration job), whereas a pod in CrashLoopBackOff or an
// unissued certificate is one.
func diagnose(st *stack.State) []stack.Finding {
	var f []stack.Finding

	if !st.ClusterReachable {
		return append(f, stack.Finding{
			Severity: "critical", Scope: "cluster", Title: "Kubernetes cluster unreachable",
			Detail: st.ClusterError,
			Action: "Check that the k3s service is running (systemctl status k3s) and that the kubeconfig is readable.",
		})
	}

	// Nodes
	if st.NodesReady < len(st.Nodes) {
		for _, n := range st.Nodes {
			if !n.Ready {
				f = append(f, stack.Finding{
					Severity: "critical", Scope: "cluster", Title: "Node not ready: " + n.Name,
					Action: "Inspect the node: kubectl describe node " + n.Name +
						" (disk full, memory, stopped kubelet).",
				})
			}
		}
	}

	// Application layers
	for _, l := range st.Layers {
		switch {
		case l.Total == 0:
			// "video" is genuinely optional (--video option): its absence is
			// a warning. Any other missing layer is critical: the platform
			// does not deliver the service it announces.
			sev := "critical"
			if l.Name == "video" {
				sev = "warning"
			}
			f = append(f, stack.Finding{
				Severity: sev, Scope: l.Name,
				Title:  fmt.Sprintf("Layer %q missing", l.Name),
				Detail: "No pod in namespace " + l.Namespace + ".",
				Action: "Layer not installed or scaled to zero: reinstall, or kubectl scale -n " +
					l.Namespace + " --all --replicas=1.",
			})
		case l.Ready < l.Total:
			detail := fmt.Sprintf("%d pod(s) out of %d are not ready.", l.Total-l.Ready, l.Total)
			var notReady []string
			for _, p := range l.Pods {
				if !p.Ready {
					notReady = append(notReady, p.Name)
				}
			}
			sort.Strings(notReady)
			action := "kubectl describe pod -n " + l.Namespace + " " + notReady[0]
			if len(notReady) > 0 {
				action = "kubectl logs -n " + l.Namespace + " " + notReady[0] + " --tail=100"
			}
			f = append(f, stack.Finding{
				Severity: "critical", Scope: l.Name,
				Title: fmt.Sprintf("Layer %q degraded", l.Name), Detail: detail, Action: action,
			})
		}

		// Restarts: a pod that has restarted is a signal, even if it is
		// currently ready. Beyond 3, it is no longer a transient incident.
		for _, p := range l.Pods {
			if p.Restarts >= 3 {
				f = append(f, stack.Finding{
					Severity: "warning", Scope: l.Name,
					Title:  fmt.Sprintf("%s: %d restarts", p.Name, p.Restarts),
					Detail: "The pod restarts repeatedly — instability rather than an isolated incident.",
					Action: "kubectl logs -n " + l.Namespace + " " + p.Name + " --previous --tail=100",
				})
			}
		}
	}

	// Certificates
	for _, c := range st.Certificates {
		if !c.Ready && strings.Contains(strings.ToLower(c.Condition), "issu") {
			f = append(f, stack.Finding{
				Severity: "critical", Scope: "tls",
				Title:  "Certificate not issued: " + c.Name,
				Detail: c.NS + " — " + c.Condition,
				Action: "kubectl describe certificate -n " + c.NS + " " + c.Name +
					" ; check that the issuer (ceffio-ca-issuer) is ready.",
			})
		}
	}

	// Ingress without an entry address: the platform answers internally but
	// is not reachable from outside — a classic, silent trap.
	for _, s := range st.Services {
		if s.Type == "LoadBalancer" && s.IP == "" {
			f = append(f, stack.Finding{
				Severity: "critical", Scope: "network",
				Title:  "Exposed service without an address: " + s.Name,
				Detail: "The LoadBalancer received no address — no external entry possible.",
				Action: "kubectl get svc -n " + s.NS + " " + s.Name +
					" ; on K3s, check the ServiceLB (kube-system) and that the port is free on the host.",
			})
		}
	}

	// Consistency: ingresses exist but no pod serves them.
	if len(st.Ingresses) > 0 && st.ReadyPods == 0 {
		f = append(f, stack.Finding{
			Severity: "critical", Scope: "platform",
			Title:  "Ingresses declared but no pod ready",
			Action: "Every route will answer 502: fix the application layers first.",
		})
	}

	// Sort: critical before warning, then by scope.
	ordre := map[string]int{"critical": 0, "warning": 1}
	sort.SliceStable(f, func(i, j int) bool {
		if ordre[f[i].Severity] != ordre[f[j].Severity] {
			return ordre[f[i].Severity] < ordre[f[j].Severity]
		}
		return f[i].Scope < f[j].Scope
	})

	return f
}

func printDoctor(r stack.Report) {
	st := r.State
	fmt.Println("Ceffio — diagnostic")
	fmt.Println()

	dash := "—"
	if st.Domain != "" {
		dash = st.Domain
	}
	fmt.Printf("Platform     %s\n", dash)
	fmt.Printf("Cluster      %d/%d node(s) ready\n", st.NodesReady, len(st.Nodes))
	fmt.Printf("Pods         %d/%d ready\n", st.ReadyPods, st.TotalPods)
	fmt.Printf("Layers       %d\n", len(st.Layers))
	fmt.Printf("Ingress      %d\n", len(st.Ingresses))
	fmt.Printf("Certificates %d\n", len(st.Certificates))
	fmt.Println()

	if len(r.Findings) == 0 {
		fmt.Println("✓ No problem detected.")
		fmt.Println()
		fmt.Println("Checks performed: nodes, application layers, repeated restarts,")
		fmt.Println("certificate issuance, service exposure, ingress/pod consistency.")
		return
	}

	crit, warn := 0, 0
	for _, x := range r.Findings {
		if x.Severity == "critical" {
			crit++
		} else {
			warn++
		}
	}

	fmt.Printf("%d problem(s): %d critical, %d warning(s)\n", len(r.Findings), crit, warn)
	fmt.Println()

	for _, x := range r.Findings {
		mark := "!"
		if x.Severity == "warning" {
			mark = "·"
		}
		fmt.Printf("%s [%s] %s\n", mark, x.Scope, x.Title)
		if x.Detail != "" {
			fmt.Printf("    %s\n", x.Detail)
		}
		if x.Action != "" {
			fmt.Printf("    → %s\n", x.Action)
		}
		fmt.Println()
	}

	fmt.Println("For the detailed layer-by-layer state: ceffio status --pods")
}
