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
		Short: "Diagnostiquer l'état de la plateforme",
		Long: `Vérifie la plateforme couche par couche et signale les problèmes réellement
détectables : nœuds non prêts, pods en échec ou en boucle de redémarrage, certificats
non délivrés, services exposés sans adresse, ingress sans réponse.

Chaque problème est rapporté avec une cause probable et une piste de correction —
ce n'est pas un simple relevé d'état (pour cela, voir « ceffio status »).

Avec --bundle, produit une archive de support à transmettre au mainteneur :
elle ne contient AUCUN secret (pas de valeur de Secret, pas de mot de passe,
pas de clé privée), seulement des états et des journaux expurgés.`,
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
					return fmt.Errorf("production du bundle : %w", err)
				}
				fmt.Printf("\nArchive de support : %s\n", path)
				fmt.Println("(sans aucun secret : valeurs de Secret, mots de passe et clés privées exclus)")
			}

			if len(findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	c.Flags().BoolVar(&bundle, "bundle", false, "Produire une archive de support (ceffio-support-*.tar.gz)")
	c.Flags().BoolVar(&asJSON, "json", false, "Sortie JSON")

	return c
}

// diagnose transforme un état en liste de problèmes exploitables.
//
// Principe : ne signaler que ce sur quoi on peut agir. Un pod « Completed »
// n'est pas une anomalie (job de migration terminé), alors qu'un pod en
// CrashLoopBackOff ou un certificat non délivré en sont une.
func diagnose(st *stack.State) []stack.Finding {
	var f []stack.Finding

	if !st.ClusterReachable {
		return append(f, stack.Finding{
			Severity: "critique", Scope: "cluster", Title: "Cluster Kubernetes injoignable",
			Detail: st.ClusterError,
			Action: "Vérifier que le service k3s tourne (systemctl status k3s) et que le kubeconfig est lisible.",
		})
	}

	// Nœuds
	if st.NodesReady < len(st.Nodes) {
		for _, n := range st.Nodes {
			if !n.Ready {
				f = append(f, stack.Finding{
					Severity: "critique", Scope: "cluster", Title: "Nœud non prêt : " + n.Name,
					Action: "Inspecter le nœud : kubectl describe node " + n.Name +
						" (disque plein, mémoire, kubelet arrêté).",
				})
			}
		}
	}

	// Couches applicatives
	for _, l := range st.Layers {
		switch {
		case l.Total == 0:
			// « visio » est réellement facultative (option --video) : son absence
			// est un avertissement. Toute autre couche absente est critique :
			// la plateforme ne rend pas le service qu'elle annonce.
			sev := "critique"
			if l.Name == "visio" {
				sev = "avertissement"
			}
			f = append(f, stack.Finding{
				Severity: sev, Scope: l.Name,
				Title:  fmt.Sprintf("Couche « %s » absente", l.Name),
				Detail: "Aucun pod dans le namespace " + l.Namespace + ".",
				Action: "Couche non installée ou mise à l'échelle à zéro : réinstaller, ou kubectl scale -n " +
					l.Namespace + " --all --replicas=1.",
			})
		case l.Ready < l.Total:
			detail := fmt.Sprintf("%d pod(s) sur %d ne sont pas prêts.", l.Total-l.Ready, l.Total)
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
				Severity: "critique", Scope: l.Name,
				Title: fmt.Sprintf("Couche « %s » dégradée", l.Name), Detail: detail, Action: action,
			})
		}

		// Redémarrages : un pod qui a redémarré est un signal, même s'il est
		// actuellement prêt. Au-delà de 3, ce n'est plus un incident transitoire.
		for _, p := range l.Pods {
			if p.Restarts >= 3 {
				f = append(f, stack.Finding{
					Severity: "avertissement", Scope: l.Name,
					Title:  fmt.Sprintf("%s : %d redémarrages", p.Name, p.Restarts),
					Detail: "Le pod redémarre de façon répétée — instabilité plutôt qu'incident isolé.",
					Action: "kubectl logs -n " + l.Namespace + " " + p.Name + " --previous --tail=100",
				})
			}
		}
	}

	// Certificats
	for _, c := range st.Certificates {
		if !c.Ready && strings.Contains(strings.ToLower(c.Condition), "issu") {
			f = append(f, stack.Finding{
				Severity: "critique", Scope: "tls",
				Title:  "Certificat non délivré : " + c.Name,
				Detail: c.NS + " — " + c.Condition,
				Action: "kubectl describe certificate -n " + c.NS + " " + c.Name +
					" ; vérifier que l'issuer (ceffio-ca-issuer) est prêt.",
			})
		}
	}

	// Ingress sans adresse d'entrée : la plateforme répond en interne mais
	// n'est pas joignable de l'extérieur — piège classique et silencieux.
	for _, s := range st.Services {
		if s.Type == "LoadBalancer" && s.IP == "" {
			f = append(f, stack.Finding{
				Severity: "critique", Scope: "réseau",
				Title:  "Service exposé sans adresse : " + s.Name,
				Detail: "Le LoadBalancer n'a pas reçu d'adresse — aucune entrée externe possible.",
				Action: "kubectl get svc -n " + s.NS + " " + s.Name +
					" ; sur K3s, vérifier le ServiceLB (kube-system) et que le port est libre sur l'hôte.",
			})
		}
	}

	// Cohérence : des ingress existent mais aucun pod ne les sert.
	if len(st.Ingresses) > 0 && st.ReadyPods == 0 {
		f = append(f, stack.Finding{
			Severity: "critique", Scope: "plateforme",
			Title:  "Ingress déclarés mais aucun pod prêt",
			Action: "Toutes les routes répondront en 502 : corriger d'abord les couches applicatives.",
		})
	}

	// Tri : critique avant avertissement, puis par portée.
	ordre := map[string]int{"critique": 0, "avertissement": 1}
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
	fmt.Printf("Plateforme   %s\n", dash)
	fmt.Printf("Cluster      %d/%d nœud(s) prêt(s)\n", st.NodesReady, len(st.Nodes))
	fmt.Printf("Pods         %d/%d prêts\n", st.ReadyPods, st.TotalPods)
	fmt.Printf("Couches      %d\n", len(st.Layers))
	fmt.Printf("Ingress      %d\n", len(st.Ingresses))
	fmt.Printf("Certificats  %d\n", len(st.Certificates))
	fmt.Println()

	if len(r.Findings) == 0 {
		fmt.Println("✓ Aucun problème détecté.")
		fmt.Println()
		fmt.Println("Contrôles effectués : nœuds, couches applicatives, redémarrages répétés,")
		fmt.Println("délivrance des certificats, exposition des services, cohérence ingress/pods.")
		return
	}

	crit, warn := 0, 0
	for _, x := range r.Findings {
		if x.Severity == "critique" {
			crit++
		} else {
			warn++
		}
	}

	fmt.Printf("%d problème(s) : %d critique(s), %d avertissement(s)\n", len(r.Findings), crit, warn)
	fmt.Println()

	for _, x := range r.Findings {
		mark := "!"
		if x.Severity == "avertissement" {
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

	fmt.Println("Pour l'état détaillé couche par couche : ceffio status --pods")
}
