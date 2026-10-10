// Package upgrade met à niveau une installation Ceffio.
//
// Une mise à niveau n'est acceptable que si elle est réversible. Ce package
// impose donc trois étapes avant toute modification :
//
//  1. un préflight — la cible est-elle saine, et qu'est-ce qui tourne
//     réellement (comparé au registre de versions, pas à une supposition) ;
//  2. une sauvegarde — obligatoire, et vérifiée : sans archive exploitable,
//     aucun retour arrière n'est possible ;
//  3. un plan — ce qui changerait, affiché avant d'agir.
//
// Sans ces trois étapes, un `upgrade` est un pari.
package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// Etat décrit ce qui tourne, par composant.
type Etat struct {
	Nom       string `json:"nom"`
	Installee string `json:"installee"`
	Cible     string `json:"cible"`
	Ecart     bool   `json:"ecart"`
	Depuis    string `json:"depuis,omitempty"` // image réellement en service
}

// Plan est le résultat du préflight : ce qui changerait, et les blocages.
type Plan struct {
	Etats       []Etat   `json:"etats"`
	Changements []Etat   `json:"changements"`
	Blocages    []string `json:"blocages"`
	Alertes     []string `json:"alertes"`
	Pret        bool     `json:"pret"`
	ClusterOK   bool     `json:"cluster_ok"`
	NœudsPrets  int      `json:"noeuds_prets"`
	NœudsTotal  int      `json:"noeuds_total"`
}

// Preparer construit le plan de mise à niveau.
//
// Il ne modifie RIEN : c'est un diagnostic. `upgrade` ne doit jamais toucher à
// une installation avant d'avoir montré ce qu'il fera.
func Preparer(ctx context.Context, cible []version.Composant) *Plan {
	p := &Plan{Etats: []Etat{}, Changements: []Etat{}, Blocages: []string{}, Alertes: []string{}}

	// 1. Le cluster répond-il, et est-il sain ? Monter une version sur un
	//    cluster dégradé empêche de distinguer la panne d'origine de celle
	//    qu'on vient d'introduire.
	nodes, introuvables := imagesEnService(ctx)
	p.NœudsTotal, p.NœudsPrets = noeuds(ctx)
	if p.NœudsTotal == 0 {
		p.Blocages = append(p.Blocages, "Cluster injoignable : impossible de préparer une mise à niveau.")
		return p
	}
	p.ClusterOK = true
	if p.NœudsPrets < p.NœudsTotal {
		p.Blocages = append(p.Blocages,
			fmt.Sprintf("Nœuds non prêts (%d/%d) : corriger l'état du cluster avant de mettre à niveau.",
				p.NœudsPrets, p.NœudsTotal))
	}

	// 2. Pods en difficulté : une mise à niveau sur une base instable ne permet
	//    pas d'attribuer une panne à sa cause.
	if noms := podsEnDifficulte(ctx); len(noms) > 0 {
		p.Blocages = append(p.Blocages,
			fmt.Sprintf("%d pod(s) en difficulté : %s — stabiliser d'abord.",
				len(noms), strings.Join(noms, ", ")))
	}

	// 3. Cohérence du registre : une image sans tag pinné interdit toute
	//    comparaison de versions (on ne saurait pas ce qu'on installe).
	for _, pb := range version.VerifierCoherence() {
		p.Blocages = append(p.Blocages, pb)
	}

	// 4. Comparaison composant par composant : ce qui tourne vs la cible.
	for _, c := range cible {
		e := Etat{Nom: c.Nom, Cible: c.Version}
		if img, ok := nodes[c.Nom]; ok {
			e.Installee = version.TagDe(img)
			e.Depuis = img
		}
		// Un composant absent n'est pas un écart : c'est une couche non
		// installée (visio sans --video). Le signaler sans bloquer — mais le
		// signaler TOUJOURS : un composant qu'on ne sait pas lire ne doit pas
		// passer pour conforme (c'était le défaut de la première version, qui
		// déclarait « aucun écart » alors qu'une image différente tournait).
		if e.Installee == "" {
			raison := "non déployé sur cette installation"
			if _, vu := introuvables[c.Nom]; vu {
				raison = "image non identifiable sur cette installation"
			}
			p.Alertes = append(p.Alertes, fmt.Sprintf("%s : %s", c.Nom, raison))
		} else if e.Installee != e.Cible {
			e.Ecart = true
			p.Changements = append(p.Changements, e)
		}
		p.Etats = append(p.Etats, e)
	}

	sort.Slice(p.Etats, func(i, j int) bool { return p.Etats[i].Nom < p.Etats[j].Nom })
	p.Pret = len(p.Blocages) == 0
	return p
}

// imagesEnService lit, pour chaque composant connu, l'image réellement utilisée
// par les pods en cours. On interroge l'API Kubernetes plutôt que de relire les
// fichiers du dépôt : c'est la seule façon de voir une dérive entre ce que le
// code déclare et ce qui tourne.
// imagesEnService lit l'inventaire RÉEL des images en service.
//
// Première version, et pourquoi elle était fausse : elle cherchait, pour chaque
// composant, un pod dont l'image contenait un fragment prédéfini (« redis: »,
// « keycloak », …). Deux défauts : le fragment était deviné, et l'absence de
// correspondance était ignorée en silence — la comparaison sautait le composant
// et `upgrade` déclarait « aucun écart » alors qu'une image différente tournait.
//
// Désormais : on lit TOUTES les images des pods ceffio-*, et on les fait
// correspondre par nom. Ce qui n'est pas trouvé est signalé comme tel, au lieu
// de passer pour conforme.
func imagesEnService(ctx context.Context) (map[string]versionImage, map[string]versionImage) {
	trouvees := map[string]versionImage{}

	raw, err := kubectl(ctx, "get", "pods", "-A", "-o", "json")
	if err != nil {
		return trouvees, nil
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return trouvees, nil
	}

	// On collecte toutes les images des namespaces ceffio-* (et des opérateurs).
	toutes := map[string]string{} // nom de conteneur -> image
	for _, p := range doc.Items {
		ns := p.Metadata.Namespace
		if !strings.HasPrefix(ns, "ceffio-") && ns != "cnpg-system" && ns != "cert-manager" {
			continue
		}
		for _, c := range p.Spec.Containers {
			toutes[c.Name] = c.Image
			// On indexe aussi par image, pour les correspondances par sous-chaîne.
			toutes["img:"+c.Image] = c.Image
		}
	}

	// Correspondance nom de composant -> fragments d'image acceptables.
	// Plusieurs fragments par composant : le nom du conteneur varie selon la
	// façon dont l'application est empaquetée.
	regles := map[string][]string{
		"keycloak":       {"keycloak"},
		"nextcloud":      {"nextcloud"},
		"onlyoffice":     {"documentserver"},
		"redis":          {"redis:"},
		"cloudnative-pg": {"cloudnative-pg"},
		"cert-manager":   {"cert-manager"},
	}

	inconnues := map[string]versionImage{}
	for composant, fragments := range regles {
		trouve := false
		for _, img := range toutes {
			for _, f := range fragments {
				if strings.Contains(img, f) {
					trouvees[composant] = img
					trouve = true
					break
				}
			}
			if trouve {
				break
			}
		}
		if !trouve {
			inconnues[composant] = ""
		}
	}
	return trouvees, inconnues
}

// versionImage est un alias de chaîne, pour la lisibilité des signatures.
type versionImage = string

func noeuds(ctx context.Context) (total, prets int) {
	raw, err := kubectl(ctx, "get", "nodes", "-o", "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}")
	if err != nil {
		return 0, 0
	}
	for _, l := range strings.Split(raw, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		total++
		if f[1] == "True" {
			prets++
		}
	}
	return total, prets
}

func podsEnDifficulte(ctx context.Context) []string {
	raw, err := kubectl(ctx, "get", "pods", "-A", "-o", "json")
	if err != nil {
		return nil
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					Ready        bool `json:"ready"`
					RestartCount int  `json:"restartCount"`
					State        struct {
						Waiting struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil
	}
	var out []string
	for _, p := range doc.Items {
		if !strings.HasPrefix(p.Metadata.Namespace, "ceffio-") {
			continue
		}
		// Un job terminé n'est pas une difficulté.
		if p.Status.Phase == "Succeeded" {
			continue
		}
		enDifficulte := false
		for _, cs := range p.Status.ContainerStatuses {
			if cs.State.Waiting.Reason == "CrashLoopBackOff" ||
				cs.State.Waiting.Reason == "ImagePullBackOff" ||
				cs.State.Waiting.Reason == "CreateContainerConfigError" {
				enDifficulte = true
			}
			if !cs.Ready && p.Status.Phase == "Running" && cs.State.Waiting.Reason != "" {
				enDifficulte = true
			}
		}
		if p.Status.Phase == "Failed" {
			enDifficulte = true
		}
		if enDifficulte {
			out = append(out, p.Metadata.Namespace+"/"+p.Metadata.Name)
		}
	}
	sort.Strings(out)
	return out
}

func kubectl(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := k8s.Command(ctx, "kubectl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
