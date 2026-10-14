// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package k8sapi is THE SINGLE ENTRY POINT to the cluster.
//
// WHY THIS PACKAGE EXISTS. The vault module used to talk to the cluster by
// launching `kubectl` and reading its output. That produced five defects, all
// of the same family: confusing "I could not ask" with "I was answered".
//
//  1. `kubectl run` mixes its side messages into the useful output: a 32-byte
//     key became a 309-character Secret containing the word "pod deleted".
//  2. `CombinedOutput` merges standard output and standard error, and
//     `kubectl exec` copes badly with it: "failed to start exec".
//  3. A non-zero exit code can mean "the command ran and rendered a verdict"
//     (the case of a sealed `bao status`) or "the command could not run".
//     Confusing the two once made us believe a vault answered "not
//     initialized" when it had never been queried.
//  4. A command missing from the image (`curl`) produced an error message
//     which, parsed as JSON, became an empty object again — hence a
//     plausible state, and a false one.
//  5. A jsonpath that comes back empty for a reason we never elucidated.
//
// The Kubernetes API, on the other hand, is TYPED. A `Secret` is a `Secret`,
// not text to be cut up; an error is an error, not output to interpret. This
// package removes the whole class of defects by removing the intermediary: no
// more external binary whose behavior we guess.
//
// RULE: everything that talks to the cluster goes through here. A direct call
// to `kubectl` elsewhere in the code is a regression.
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

// Client groups the accesses to the cluster. It is built ONCE, and its
// construction FAILS FRANKLY if the cluster is unreachable.
//
// This is the most important point of the package: the previous version let a
// missing configuration show up later, as empty output that we interpreted as
// a state. Here, no cluster: no client, and the caller knows immediately.
type Client struct {
	cfg *rest.Config
	cs  kubernetes.Interface
	dyn dynamic.Interface
}

// Nouveau builds the single entry point.
func Nouveau() (*Client, error) {
	cfg, err := chargerConfig()
	if err != nil {
		return nil, err
	}
	// A short timeout: we prefer a clean failure to an indefinite wait.
	cfg.Timeout = 30 * time.Second

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("Kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	return &Client{cfg: cfg, cs: cs, dyn: dyn}, nil
}

// chargerConfig resolves the configuration, in the order of the conventions:
// KUBECONFIG if set, otherwise ~/.kube/config.
//
// THE FAILURE IS EXPLICIT and says what to do. A missing configuration must
// not be able to look like an empty cluster.
func chargerConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	chemin := os.Getenv("KUBECONFIG")
	if chemin == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return nil, fmt.Errorf("home directory not found: cannot locate the kubeconfig")
		}
		chemin = filepath.Join(home, ".kube", "config")
	}
	if _, err := os.Stat(chemin); err != nil {
		return nil, fmt.Errorf("kubeconfig not found (%s): the cluster is not reachable from this machine", chemin)
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", chemin)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig unreadable (%s): %w", chemin, err)
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// LireSecret returns the value of a key, or "" if the Secret or the key does
// not exist.
//
// Absence is NOT an error: it is a normal state, and the caller decides.
func (c *Client) LireSecret(ctx context.Context, ns, nom, cle string) (string, error) {
	s, err := c.cs.CoreV1().Secrets(ns).Get(ctx, nom, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading secret %s/%s: %w", ns, nom, err)
	}
	return string(s.Data[cle]), nil
}

// PoserSecret creates or replaces a Secret. Idempotent.
func (c *Client) PoserSecret(ctx context.Context, ns, nom string, donnees map[string][]byte) error {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: nom, Namespace: ns},
		Data:       donnees,
	}
	if _, err := c.cs.CoreV1().Secrets(ns).Create(ctx, s, metav1.CreateOptions{}); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating secret %s/%s: %w", ns, nom, err)
	}
	if _, err := c.cs.CoreV1().Secrets(ns).Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating secret %s/%s: %w", ns, nom, err)
	}
	return nil
}

// SupprimerSecret deletes a Secret, without failing if it does not exist.
func (c *Client) SupprimerSecret(ctx context.Context, ns, nom string) error {
	if err := c.cs.CoreV1().Secrets(ns).Delete(ctx, nom, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Manifest application
// ---------------------------------------------------------------------------

// Appliquer applies a YAML manifest, possibly multi-document.
//
// We decode into unstructured objects and apply via the dynamic client: this
// is the equivalent of `kubectl apply`, typed, without an external binary.
func (c *Client) Appliquer(ctx context.Context, manifeste string) error {
	for _, doc := range decouper(manifeste) {
		// YAML TO JSON, THEN UNSTRUCTURED. This is the reliable path: the
		// universal decoder does not necessarily know the types we give it,
		// and `UnmarshalJSON` on YAML bytes fails silently or produces an
		// empty object — exactly the kind of false state we are trying to
		// eliminate.
		brut, err := yaml.YAMLToJSON([]byte(doc))
		if err != nil {
			return fmt.Errorf("unreadable manifest: %w", err)
		}
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(brut); err != nil {
			return fmt.Errorf("unreadable manifest: %w", err)
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
		return fmt.Errorf("applying %s/%s: %w", gvk.Kind, obj.GetName(), err)
	}
	// Already exists: we replace it, keeping the resource version to avoid an
	// optimistic update conflict.
	actuel, err := ri.Get(ctx, obj.GetName(), metav1.GetOptions{})
	if err != nil {
		return err
	}

	// THE ALREADY-ALLOCATED nodePort VALUES ARE CARRIED OVER, and this is not
	// a detail.
	//
	// A NodePort is a resource OF THE CLUSTER: Kubernetes allocates it once
	// and reserves it. Applying a manifest that no longer mentions it
	// therefore implicitly asks for another one — and the operation fails on
	// "provided port is already allocated", measured in service. The
	// service then held its own port, and refused to update itself.
	//
	// We carry over the existing values so the update is truly idempotent:
	// re-applying the same manifest must change nothing.
	if gvk.Kind == "Service" {
		reporterNodePorts(actuel, obj)
	}

	obj.SetResourceVersion(actuel.GetResourceVersion())
	if _, err := ri.Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating %s/%s: %w", gvk.Kind, obj.GetName(), err)
	}
	return nil
}

// reporterNodePorts copies the already-allocated nodePort values from the
// existing object to the wanted object, matching ports by their name.
//
// We match BY NAME and not by position: the order of the ports is not
// guaranteed, and matching by index would assign one service's port to
// another.
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

// ressourceDe translates an object type into an API resource.
//
// TWO PATHS, AND THE SECOND IS THE MOST IMPORTANT. The first is a local
// table: it answers without a network call, for the most common types. The
// second ASKS the cluster, and it is the one that removes a defect the table
// alone produced: each new object type — a ServiceAccount, a role binding —
// failed on "type d'objet non pris en charge". This refusal says nothing
// about the manifest one is trying to apply, and it had to be fixed in the
// code rather than in the manifest. Observed in service.
//
// The table avoids a round-trip in the common case; the cluster remains the
// reference for everything else. A table that would claim to cover every
// possible type is a table one forgets to complete.
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
		fmt.Errorf("object type not found: %s (absent from the local table, and the cluster does not advertise it)", gvk.Kind)
}

// chercherDansCluster queries the cluster's discovery and keeps the first
// resource whose Kind matches.
func (c *Client) chercherDansCluster(gvk schema.GroupVersionKind) (schema.GroupVersionResource, bool) {
	listes, err := c.cs.Discovery().ServerPreferredResources()
	// A partial error is NORMAL: the cluster sometimes advertises groups
	// where one API is momentarily absent. We continue with what we received;
	// only the "nothing at all" case is a failure.
	if err != nil && len(listes) == 0 {
		return schema.GroupVersionResource{}, false
	}
	groupe := gvk.GroupVersion().Group
	for _, l := range listes {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			continue
		}
		// A Kind may exist in several groups ("Deployment" in the old days).
		// When the manifest names a group, we stick to it.
		if groupe != "" && gv.Group != groupe {
			continue
		}
		for _, r := range l.APIResources {
			// Sub-resources ("pods/exec") do not apply to a manifest:
			// dropping them avoids producing an unusable resource.
			if strings.Contains(r.Name, "/") || r.Kind != gvk.Kind {
				continue
			}
			return gv.WithResource(r.Name), true
		}
	}
	return schema.GroupVersionResource{}, false
}

// decouper separates the documents of a multi-document manifest.
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
// Pods and execution
// ---------------------------------------------------------------------------

// NoeudDuPod returns the node the pod is scheduled on, or "" if it is not yet.
//
// TYPED, HENCE RELIABLE: no more jsonpath whose failure is confused with an
// empty result.
func (c *Client) NoeudDuPod(ctx context.Context, ns, pod string) (string, error) {
	p, err := c.cs.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading pod %s/%s: %w", ns, pod, err)
	}
	return p.Spec.NodeName, nil
}

// Executer runs a command INSIDE a container, and returns its output.
//
// SEPARATE OUTPUTS, like a terminal: this is the behavior `kubectl` did not
// hold to, and which caused "failed to start exec".
//
// The returned error explicitly distinguishes the execution failure from the
// command's verdict: the caller can no longer confuse the two.
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
		return "", fmt.Errorf("execution impossible in %s/%s: %w", ns, pod, err)
	}
	var sortie, errs bytes.Buffer
	if err := executeur.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &sortie, Stderr: &errs,
	}); err != nil {
		return sortie.String() + errs.String(),
			fmt.Errorf("%w (output: %.200s)", err, errs.String())
	}
	return sortie.String() + errs.String(), nil
}

// ExecuterAvecEntree runs a command INSIDE a container while feeding its
// standard input.
//
// WHY THIS IS NOT A DETAIL: a secret passed through standard input leaves no
// trace — neither in the container's process table, nor on its disk. Passing
// it as an argument would expose it to anyone who can list the processes;
// writing it to a file would leave a window during which it is readable.
// Standard input has neither of those defects.
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
		return "", fmt.Errorf("execution impossible in %s/%s: %w", ns, pod, err)
	}
	var sortie, errs bytes.Buffer
	if err := executeur.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  strings.NewReader(entree + "\n"),
		Stdout: &sortie,
		Stderr: &errs,
	}); err != nil {
		return sortie.String() + errs.String(),
			fmt.Errorf("%w (output: %.200s)", err, errs.String())
	}
	return sortie.String() + errs.String(), nil
}

// NodePortDuService returns the external port allocated to a service, for a
// named port, or 0 if there is none.
//
// WHY WE READ IT INSTEAD OF FIXING IT: a NodePort is a resource of the WHOLE
// CLUSTER, not of the namespace. Freezing it in a manifest reserves that
// number for the whole life of the cluster — and a re-creation then fails on
// "provided port is already allocated", measured in service. Letting
// Kubernetes allocate, then READING, removes the reservation and the frozen
// value in one go.
func (c *Client) NodePortDuService(ctx context.Context, ns, nom, port string) (int32, error) {
	svc, err := c.cs.CoreV1().Services(ns).Get(ctx, nom, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("reading service %s/%s: %w", ns, nom, err)
	}
	for _, p := range svc.Spec.Ports {
		if p.Name == port {
			return p.NodePort, nil
		}
	}
	return 0, nil
}

// WebhookEstPret says whether a mutating webhook has published its trust seed.
//
// THIS IS THE ONLY SIGNAL THAT PROVES INJECTION WILL WORK: the injector writes
// this caBundle itself, once its certificate is generated. A "Ready" pod does
// not prove it — it can be ready before having patched its webhook.
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

// AttendrePodInstalle waits until the pod is assigned to a node.
//
// The message says WHAT WE SAW: a silent check that gets it wrong wastes
// minutes, observed in service.
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
			dernier = "pod present but not scheduled on a node"
		}
		time.Sleep(3 * time.Second)
	}
	return "", fmt.Errorf("pod %s/%s not scheduled after %s (%s)", ns, pod, limite, dernier)
}
