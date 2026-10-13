// Package k8sapi est LA PORTE D'ENTRÉE UNIQUE vers le cluster.
//
// POURQUOI CE PAQUET EXISTE. Le module du coffre parlait au cluster en lançant
// `kubectl` et en lisant sa sortie. Cela a produit cinq défauts, tous de la même
// famille : confondre « je n'ai pas pu demander » avec « on m'a répondu ».
//
//  1. `kubectl run` mêle ses messages d'accompagnement à la sortie utile : une
//     clé de 32 octets est devenue un Secret de 309 caractères contenant le mot
//     « pod deleted ».
//  2. `CombinedOutput` fusionne la sortie standard et la sortie d'erreur, et
//     `kubectl exec` s'en accommode mal : « failed to start exec ».
//  3. Un code de sortie non nul peut vouloir dire « la commande a tourné et a
//     rendu un verdict » (le cas de `bao status` scellé) ou « la commande n'a
//     pas pu tourner ». Les confondre a fait croire qu'un coffre répondait
//     « non initialisé » alors qu'il n'avait jamais été interrogé.
//  4. Une commande absente de l'image (`curl`) produisait un message d'erreur
//     qui, analysé comme du JSON, redevenait un objet vide — donc un état
//     plausible, et faux.
//  5. Un jsonpath qui revient vide pour une raison qu'on n'a jamais élucidée.
//
// L'API Kubernetes, elle, est TYPÉE. Un `Secret` est un `Secret`, pas du texte
// qu'il faut découper ; une erreur est une erreur, pas une sortie qu'il faut
// interpréter. Ce paquet supprime la classe entière de défauts en supprimant
// l'intermédiaire : plus de binaire externe dont on devine le comportement.
//
// RÈGLE : tout ce qui parle au cluster passe par ici. Un appel direct à
// `kubectl` ailleurs dans le code est une régression.
package k8sapi

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/yaml"
)

// Client regroupe les accès au cluster. Il est construit UNE fois, et sa
// construction ÉCHOUE FRANCHEMENT si le cluster est injoignable.
//
// C'est le point le plus important du paquet : la version précédente laissait
// une configuration introuvable se manifester plus tard, sous la forme d'une
// sortie vide qu'on interprétait comme un état. Ici, pas de cluster : pas de
// client, et l'appelant le sait immédiatement.
type Client struct {
	cfg *rest.Config
	cs  kubernetes.Interface
	dyn dynamic.Interface
}

// Nouveau construit la porte d'entrée unique.
func Nouveau() (*Client, error) {
	cfg, err := chargerConfig()
	if err != nil {
		return nil, err
	}
	// Un délai court : on préfère un échec net à une attente indéfinie.
	cfg.Timeout = 30 * time.Second

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("client Kubernetes : %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("client dynamique : %w", err)
	}
	return &Client{cfg: cfg, cs: cs, dyn: dyn}, nil
}

// chargerConfig résout la configuration, dans l'ordre des conventions :
// KUBECONFIG s'il est posé, sinon ~/.kube/config.
//
// L'ÉCHEC EST EXPLICITE et dit quoi faire. Une configuration absente ne doit pas
// pouvoir ressembler à un cluster vide.
func chargerConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	chemin := os.Getenv("KUBECONFIG")
	if chemin == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return nil, fmt.Errorf("dossier personnel introuvable : impossible de localiser le kubeconfig")
		}
		chemin = filepath.Join(home, ".kube", "config")
	}
	if _, err := os.Stat(chemin); err != nil {
		return nil, fmt.Errorf("kubeconfig introuvable (%s) : le cluster n'est pas joignable depuis cette machine", chemin)
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", chemin)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig illisible (%s) : %w", chemin, err)
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// LireSecret rend la valeur d'une clé, ou "" si le Secret ou la clé n'existe pas.
//
// L'absence n'est PAS une erreur : c'est un état normal, et l'appelant décide.
func (c *Client) LireSecret(ctx context.Context, ns, nom, cle string) (string, error) {
	s, err := c.cs.CoreV1().Secrets(ns).Get(ctx, nom, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("lecture du secret %s/%s : %w", ns, nom, err)
	}
	return string(s.Data[cle]), nil
}

// PoserSecret crée ou remplace un Secret. Idempotent.
func (c *Client) PoserSecret(ctx context.Context, ns, nom string, donnees map[string][]byte) error {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: nom, Namespace: ns},
		Data:       donnees,
	}
	if _, err := c.cs.CoreV1().Secrets(ns).Create(ctx, s, metav1.CreateOptions{}); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("création du secret %s/%s : %w", ns, nom, err)
	}
	if _, err := c.cs.CoreV1().Secrets(ns).Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("mise à jour du secret %s/%s : %w", ns, nom, err)
	}
	return nil
}

// SupprimerSecret supprime un Secret, sans échouer s'il n'existe pas.
func (c *Client) SupprimerSecret(ctx context.Context, ns, nom string) error {
	if err := c.cs.CoreV1().Secrets(ns).Delete(ctx, nom, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Application de manifestes
// ---------------------------------------------------------------------------

// Appliquer pose un manifeste YAML, éventuellement multi-documents.
//
// On décode en objets non structurés et on applique par le client dynamique :
// c'est l'équivalent de `kubectl apply`, en typé, sans binaire externe.
func (c *Client) Appliquer(ctx context.Context, manifeste string) error {
	for _, doc := range decouper(manifeste) {
		// YAML VERS JSON, PUIS UNSTRUCTURED. C'est le chemin fiable : le
		// décodeur universel ne connaît pas forcément les types qu'on lui donne,
		// et `UnmarshalJSON` sur des octets YAML échoue silencieusement ou
		// produit un objet vide — exactement le genre de faux état qu'on
		// cherche à éliminer.
		brut, err := yaml.YAMLToJSON([]byte(doc))
		if err != nil {
			return fmt.Errorf("manifeste illisible : %w", err)
		}
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(brut); err != nil {
			return fmt.Errorf("manifeste illisible : %w", err)
		}
		if obj.GetName() == "" {
			continue
		}
		if err := c.appliquerObjet(ctx, obj); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) appliquerObjet(ctx context.Context, obj *unstructured.Unstructured) error {
	ns := obj.GetNamespace()
	if ns == "" {
		ns = "default"
	}
	gvk := obj.GroupVersionKind()
	ressource, err := c.ressourceDe(gvk)
	if err != nil {
		return err
	}
	var ri dynamic.ResourceInterface
	if obj.GetNamespace() == "" {
		ri = c.dyn.Resource(ressource)
	} else {
		ri = c.dyn.Resource(ressource).Namespace(ns)
	}
	_, err = ri.Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("application de %s/%s : %w", gvk.Kind, obj.GetName(), err)
	}
	// Existe déjà : on remplace, en conservant la version de ressource pour
	// éviter un conflit de mise à jour optimiste.
	actuel, err := ri.Get(ctx, obj.GetName(), metav1.GetOptions{})
	if err != nil {
		return err
	}

	// LES nodePort DÉJÀ ATTRIBUÉS SONT REPORTÉS, et ce n'est pas un détail.
	//
	// Un NodePort est une ressource DU CLUSTER : Kubernetes l'attribue une fois
	// et le réserve. Appliquer un manifeste qui ne le mentionne plus demande donc
	// implicitement d'en attribuer un autre — et l'opération échoue sur
	// « provided port is already allocated », mesuré en service. Le service se
	// détenait alors son propre port, et refusait de se mettre à jour.
	//
	// On reporte les valeurs existantes pour que la mise à jour soit réellement
	// idempotente : réappliquer le même manifeste ne doit rien changer.
	if gvk.Kind == "Service" {
		reporterNodePorts(actuel, obj)
	}

	obj.SetResourceVersion(actuel.GetResourceVersion())
	if _, err := ri.Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("mise à jour de %s/%s : %w", gvk.Kind, obj.GetName(), err)
	}
	return nil
}

// reporterNodePorts recopie les nodePort déjà attribués de l'objet existant vers
// l'objet voulu, en appariant les ports par leur nom.
//
// On apparie PAR NOM et non par position : l'ordre des ports n'est pas garanti,
// et apparier par index attribuerait le port d'un service à un autre.
func reporterNodePorts(actuel, voulu *unstructured.Unstructured) {
	portsVoulus, ok, _ := unstructured.NestedSlice(voulu.Object, "spec", "ports")
	if !ok {
		return
	}
	portsActuels, ok, _ := unstructured.NestedSlice(actuel.Object, "spec", "ports")
	if !ok {
		return
	}
	for i, p := range portsVoulus {
		pv, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		nom, _ := pv["name"].(string)
		for _, a := range portsActuels {
			pa, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			na, _ := pa["name"].(string)
			if nom != "" && nom == na {
				if np, existe := pa["nodePort"]; existe {
					pv["nodePort"] = np
				}
			}
		}
		portsVoulus[i] = pv
	}
	_ = unstructured.SetNestedSlice(voulu.Object, portsVoulus, "spec", "ports")
}

// ressourceDe traduit un type d'objet en ressource d'API.
//
// DEUX CHEMINS, ET LE SECOND EST LE PLUS IMPORTANT. Le premier est une table
// locale : elle répond sans appel réseau, pour les types les plus courants. Le
// second DEMANDE au cluster, et c'est lui qui supprime un défaut que la table
// seule produisait : chaque nouveau type d'objet — un ServiceAccount, une
// liaison de rôle — échouait sur « type d'objet non pris en charge ». Ce refus
// ne parle pas du manifeste qu'on essaie d'appliquer, et il fallait le corriger
// dans le code plutôt que dans le manifeste. Constaté en service.
//
// La table évite un aller-retour dans le cas courant ; le cluster reste la
// référence pour tout le reste. Une table qui prétendrait couvrir tous les types
// possibles est une table qu'on oublie de compléter.
func (c *Client) ressourceDe(gvk schema.GroupVersionKind) (schema.GroupVersionResource, error) {
	switch gvk.Kind {
	case "Namespace":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}, nil
	case "ConfigMap":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, nil
	case "Service":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}, nil
	case "Secret":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}, nil
	case "ServiceAccount":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}, nil
	case "StatefulSet":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, nil
	case "Pod":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, nil
	}
	if r, ok := c.chercherDansCluster(gvk); ok {
		return r, nil
	}
	return schema.GroupVersionResource{},
		fmt.Errorf("type d'objet introuvable : %s (absent de la table locale, et le cluster ne l'annonce pas)", gvk.Kind)
}

// chercherDansCluster interroge la découverte du cluster et retient la première
// ressource dont le Kind correspond.
func (c *Client) chercherDansCluster(gvk schema.GroupVersionKind) (schema.GroupVersionResource, bool) {
	listes, err := c.cs.Discovery().ServerPreferredResources()
	// Une erreur partielle est NORMALE : le cluster annonce parfois des groupes
	// dont une API est momentanément absente. On continue avec ce qu'on a reçu ;
	// seul le cas « rien du tout » est un échec.
	if err != nil && len(listes) == 0 {
		return schema.GroupVersionResource{}, false
	}
	groupe := gvk.GroupVersion().Group
	for _, l := range listes {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			continue
		}
		// Un Kind peut exister dans plusieurs groupes (« Deployment » autrefois).
		// Quand le manifeste nomme un groupe, on s'y tient.
		if groupe != "" && gv.Group != groupe {
			continue
		}
		for _, r := range l.APIResources {
			// Les sous-ressources (« pods/exec ») ne s'appliquent pas à un
			// manifeste : les écarter évite de produire une ressource inutilisable.
			if strings.Contains(r.Name, "/") || r.Kind != gvk.Kind {
				continue
			}
			return gv.WithResource(r.Name), true
		}
	}
	return schema.GroupVersionResource{}, false
}

// decouper sépare les documents d'un manifeste multi-documents.
func decouper(manifeste string) []string {
	var docs []string
	for _, bloc := range strings.Split(manifeste, "\n---") {
		if strings.TrimSpace(bloc) != "" {
			docs = append(docs, bloc)
		}
	}
	return docs
}

// ---------------------------------------------------------------------------
// Pods et exécution
// ---------------------------------------------------------------------------

// NoeudDuPod rend le nœud sur lequel le pod est installé, ou "" s'il ne l'est
// pas encore.
//
// TYPÉ, DONC FIABLE : plus de jsonpath dont l'échec se confond avec un résultat
// vide.
func (c *Client) NoeudDuPod(ctx context.Context, ns, pod string) (string, error) {
	p, err := c.cs.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("lecture du pod %s/%s : %w", ns, pod, err)
	}
	return p.Spec.NodeName, nil
}

// Executer lance une commande DANS un conteneur, et rend sa sortie.
//
// SORTIES SÉPARÉES, comme un terminal : c'est le comportement auquel `kubectl`
// ne se tenait pas, et qui provoquait « failed to start exec ».
//
// L'erreur rendue distingue explicitement l'échec d'exécution du verdict de la
// commande : l'appelant ne peut plus confondre les deux.
func (c *Client) Executer(ctx context.Context, ns, pod, conteneur string, args ...string) (string, error) {
	req := c.cs.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace(ns).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: conteneur,
			Command:   args,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executeur, err := remotecommand.NewSPDYExecutor(c.cfg, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("exécution impossible dans %s/%s : %w", ns, pod, err)
	}
	var sortie, errs bytes.Buffer
	if err := executeur.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &sortie, Stderr: &errs,
	}); err != nil {
		return sortie.String() + errs.String(),
			fmt.Errorf("%w (sortie : %.200s)", err, errs.String())
	}
	return sortie.String() + errs.String(), nil
}

// ExecuterAvecEntree lance une commande DANS un conteneur en alimentant son
// entrée standard.
//
// POURQUOI CE N'EST PAS UN DÉTAIL : un secret transmis par l'entrée standard ne
// laisse aucune trace — ni dans la table des processus du conteneur, ni sur son
// disque. Le passer en argument l'exposerait à quiconque peut lister les
// processus ; l'écrire dans un fichier laisserait une fenêtre pendant laquelle
// il est lisible. L'entrée standard n'a ni l'un ni l'autre de ces défauts.
func (c *Client) ExecuterAvecEntree(ctx context.Context, ns, pod, conteneur, entree string, args ...string) (string, error) {
	req := c.cs.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace(ns).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: conteneur,
			Command:   args,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executeur, err := remotecommand.NewSPDYExecutor(c.cfg, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("exécution impossible dans %s/%s : %w", ns, pod, err)
	}
	var sortie, errs bytes.Buffer
	if err := executeur.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  strings.NewReader(entree + "\n"),
		Stdout: &sortie,
		Stderr: &errs,
	}); err != nil {
		return sortie.String() + errs.String(),
			fmt.Errorf("%w (sortie : %.200s)", err, errs.String())
	}
	return sortie.String() + errs.String(), nil
}

// NodePortDuService rend le port externe attribué à un service, pour un port
// nommé, ou 0 s'il n'y en a pas.
//
// POURQUOI ON LE LIT AU LIEU DE LE FIXER : un NodePort est une ressource DU
// CLUSTER ENTIER, pas du namespace. Le figer dans un manifeste réserve ce numéro
// pour toute la vie du cluster — et une recréation échoue alors sur « provided
// port is already allocated », mesuré en service. Laisser Kubernetes attribuer,
// puis LIRE, supprime la réservation et la valeur figée du même coup.
func (c *Client) NodePortDuService(ctx context.Context, ns, nom, port string) (int32, error) {
	svc, err := c.cs.CoreV1().Services(ns).Get(ctx, nom, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("lecture du service %s/%s : %w", ns, nom, err)
	}
	for _, p := range svc.Spec.Ports {
		if p.Name == port {
			return p.NodePort, nil
		}
	}
	return 0, nil
}

// WebhookEstPret dit si un webhook mutateur a publié sa graine de confiance.
//
// C'EST LE SEUL SIGNAL QUI PROUVE QUE L'INJECTION FONCTIONNERA : l'injecteur écrit
// ce caBundle lui-même, une fois son certificat généré. Un pod « Ready » ne le
// prouve pas — il peut être prêt avant d'avoir patché son webhook.
func (c *Client) WebhookEstPret(ctx context.Context, nom string) (bool, error) {
	wh, err := c.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, nom, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if len(wh.Webhooks) == 0 {
		return false, nil
	}
	return len(wh.Webhooks[0].ClientConfig.CABundle) > 0, nil
}

// AttendrePodInstalle attend que le pod soit affecté à un nœud.
//
// Le message dit CE QU'ON A VU : un contrôle muet qui se trompe fait perdre des
// minutes, constaté en service.
func (c *Client) AttendrePodInstalle(ctx context.Context, ns, pod string, limite time.Duration) (string, error) {
	fin := time.Now().Add(limite)
	var dernier string
	for time.Now().Before(fin) {
		noeud, err := c.NoeudDuPod(ctx, ns, pod)
		if err != nil {
			dernier = err.Error()
		} else if noeud != "" {
			return noeud, nil
		} else {
			dernier = "pod présent mais sans nœud"
		}
		time.Sleep(3 * time.Second)
	}
	return "", fmt.Errorf("pod %s/%s non installé après %s (%s)", ns, pod, limite, dernier)
}
