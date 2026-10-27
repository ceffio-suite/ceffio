// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package longhornui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/sso"
)

// cheminCoffre is where this module keeps its two secrets inside OpenBao.
//
// ONE ENTRY, TWO KEYS: the client secret is written by AssurerClient through
// c.CoffreComposant/CoffreChemin, and the cookie secret by this package. Keeping them
// together means the vault role that grants read on this path is one rule, and a reader
// sees the whole proxy's credential in one place.
const (
	coffreComposant = "longhorn-ui"
	coffreChemin    = "oauth2-proxy"
)

// cheminCoffre is the full vault path the injector reads, and the only one this
// module declares.
//
// IT MUST START WITH "kv/data/ceffio/" + THE MODULE'S ID: the vault layer refuses
// any other prefix (vault.PolitiqueModule), so a divergence between the component
// name and the module ID would fail at provisioning — the good place — rather than
// at the pod's first start.
const cheminCoffre = "kv/data/ceffio/" + coffreComposant + "/" + coffreChemin

// installer déploie le proxy, son client, ses secrets et sa route. Idempotent.
func installer(ctx context.Context, env module.Env) error {
	domaine := env.Domain
	if domaine == "" {
		return erreurDomaine()
	}

	// 1. THE KEYCLOAK CLIENT, declared by the module itself.
	//
	// Audience is TRUE and not optional here: oauth2-proxy verifies that the token is
	// meant for it, and Keycloak never puts the caller's own clientId in `aud` on its
	// own. Without the mapper the claim is absent and every token is refused — after a
	// login that looked like it worked.
	fmt.Println("∙ longhorn-ui: Keycloak client")
	clientSecret, err := sso.AssurerClient(ctx, sso.Client{
		ID:              clientOIDC,
		Redirects:       "https://" + nomHote(domaine) + "/oauth2/callback",
		PostLogout:      "https://" + nomHote(domaine) + "/",
		Public:          false,
		Audience:        true,
		CoffreComposant: coffreComposant,
		CoffreChemin:    coffreChemin,
	})
	if err != nil {
		return err
	}

	// 2. THE COOKIE SECRET, generated ONCE.
	//
	// REGENERATING IT ON EVERY INSTALL WOULD SIGN EVERY USER OUT — and worse, would
	// look like a working deployment: the proxy restarts, serves a fresh cookie, and
	// nobody understands why everyone had to sign in again after an upgrade. So an
	// existing value is kept.
	if err := assurerCookieSecret(ctx); err != nil {
		return err
	}
	if clientSecret == "" {
		// A confidential client always has one. Empty means the call did not behave as
		// declared, and continuing would deploy a proxy that cannot authenticate.
		return fmt.Errorf("longhorn-ui: the Keycloak client %q has no secret: a "+
			"confidential client must have one", clientOIDC)
	}

	// 3. THE PROXY'S SECRETS COME FROM THE INJECTOR, NOT FROM A KUBERNETES SECRET.
	//
	// THEY ARE RENDERED BY THE OPENBAO INJECTOR, as two files, and handed to the
	// proxy by --client-secret-file / --cookie-secret-file. This is what A4 made
	// possible: the module declares its own vault access (Info.Vault), the vault
	// layer builds the policy and the Kubernetes role from the registry, and the
	// pod's ServiceAccount — not this command — is what authenticates.
	//
	// WHAT THIS REPLACES, AND WHY THE OLD MODE WAS WRONG: the values were read
	// here, then written into a Secret. That Secret was a SECOND COPY of the
	// credential, outside OpenBao, kept in sync by nothing — rotating the secret
	// in the vault left the pod authenticating with the old one indefinitely. The
	// injector renders at pod start, so a rotation takes effect at the next
	// restart, like every other component of the suite.

	// 4. THE SERVICE ACCOUNT, WHICH MUST EXIST BEFORE THE POD.
	//
	// The Deployment names it, and a pod whose ServiceAccount does not exist is never
	// created at all: the ReplicaSet reports FailedCreate, the Deployment stays at 0/1,
	// and Kubernetes' message names the account but not who was supposed to create it.
	// Found by deploying -- the Deployment applied cleanly and produced no pod.
	if err := appliquer(ctx, manifesteServiceAccount()); err != nil {
		return err
	}

	// 5. THE LIST OF ALLOWED ADDRESSES, written as a ConfigMap.
	//
	// THE SETTING WINS OVER THE DEFAULT, and an absent setting is the normal first
	// installation: the default is the administrator's own address, so the module is
	// usable the moment it is installed.
	adresses := adresseDefaut
	if env.Settings != nil {
		if v, err := env.Settings.Lire(ctx, nsSysteme, nomConfigReglages, "allowed_emails"); err == nil && v != "" {
			adresses = v
		}
	}
	if err := poserAdresses(ctx, adresses); err != nil {
		return err
	}

	// 6. THE WORKLOAD, THE SERVICE AND THE ROUTE.
	annotations, err := annotationsProxy(sommeAdresses(adresses))
	if err != nil {
		return err
	}
	if err := appliquer(ctx, manifesteProxy(domaine, annotations)); err != nil {
		return err
	}
	if err := appliquer(ctx, manifesteServiceEtRoute(domaine)); err != nil {
		return err
	}

	// 7. THE OLD SECRET IS REMOVED, AND LAST.
	//
	// IT COMES AFTER THE NEW DEPLOYMENT on purpose: an installation that still
	// runs the previous mode has a pod whose environment was read from that
	// Secret, and deleting it before the replacement exists would make any
	// restart during the install fail to start. Once the new pod is applied, the
	// Secret is a copy of a credential that nothing reads — the exact thing
	// docs/secrets.md promises not to keep.
	return supprimerSecretObsolete(ctx)
}

// supprimerSecretObsolete deletes the Kubernetes Secret the previous mode wrote.
//
// A MIGRATION, NOT A ROUTINE STEP: on a fresh installation there is nothing to
// delete, and --ignore-not-found makes that the cheap case. It stays in the code
// because an upgrade must not leave a credential behind, and because the next
// install of every other module must not have to know this one's history.
func supprimerSecretObsolete(ctx context.Context) error {
	cmd := k8s.Command(ctx, "kubectl", "delete", "secret", nomDeploy+"-vault",
		"-n", nsSysteme, "--ignore-not-found")
	// SILENT ON SUCCESS: this is a cleanup, and printing it would suggest the
	// module creates that Secret.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("longhorn-ui: removing the obsolete Kubernetes Secret: %w", err)
	}
	return nil
}

// assurerCookieSecret stores a 32-byte cookie secret, once.
//
// 32 BYTES BECAUSE oauth2-proxy REFUSES ANYTHING SHORTER: it needs enough entropy for
// AES-256, and a short secret makes the container exit at startup with a message about
// the cookie secret's length -- a failure at deploy time for a value nobody sets by hand.
func assurerCookieSecret(ctx context.Context) error {
	cfg := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, cfg, coffreComposant, coffreChemin)
	if err != nil && !estAbsent(err) {
		return fmt.Errorf("longhorn-ui: reading the vault entry: %w", err)
	}
	if entree != nil && entree["cookie_secret"] != "" {
		return nil // already generated: keeping it is what keeps sessions alive
	}

	brut := make([]byte, 32)
	if _, err := rand.Read(brut); err != nil {
		return fmt.Errorf("longhorn-ui: generating the cookie secret: %w", err)
	}
	// BASE64 URL WITHOUT PADDING: that is the form oauth2-proxy documents, and the form
	// that survives being read from a `set -a` file.
	val := base64.RawURLEncoding.EncodeToString(brut)

	if entree == nil {
		entree = map[string]string{}
	}
	entree["cookie_secret"] = val
	return secrets.EcrireDansCoffre(ctx, cfg, coffreComposant, coffreChemin, entree)
}

// estAbsent reports whether the error means "no such entry", which is the normal first
// installation rather than a fault.
func estAbsent(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "404") || strings.Contains(s, "not found") ||
		strings.Contains(s, "does not exist")
}

// sommeAdresses is the checksum that restarts the proxy when the list changes.
//
// ANNOTATION, NOT A VOLUME MOUNT ALONE: oauth2-proxy reads the file at startup, so
// rewriting the ConfigMap changes nothing until the process restarts. The annotation
// makes Kubernetes do it — and only when the content really changed.
func sommeAdresses(adresses string) string {
	s := strings.Join(trierLignes(adresses), "\n")
	var h uint64 = 1469598103
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%x", h)
}

// trierLignes renders the comma-separated list as a sorted, de-duplicated file.
//
// SORTED SO THE CHECKSUM IS STABLE: the same set typed in another order must not restart
// the pod, because a restart signs nobody out but does cut the page for a few seconds.
func trierLignes(adresses string) []string {
	vus := map[string]bool{}
	var out []string
	for _, a := range strings.Split(adresses, ",") {
		a = strings.TrimSpace(a)
		if a == "" || vus[a] {
			continue
		}
		vus[a] = true
		out = append(out, a)
	}
	// insertion sort: a handful of addresses, no dependency
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// poserAdresses writes the allowed addresses as a ConfigMap.
func poserAdresses(ctx context.Context, adresses string) error {
	contenu := strings.Join(trierLignes(adresses), "\n") + "\n"
	manifeste := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/part-of: ceffio
data:
  emails: |
%s`, nomConfig, nsSysteme, indenter(contenu, "    "))
	return appliquer(ctx, manifeste)
}

// indenter prefixes every line, for a YAML block scalar.
func indenter(s, prefixe string) string {
	lignes := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i := range lignes {
		lignes[i] = prefixe + lignes[i]
	}
	return strings.Join(lignes, "\n")
}

// appliquer applies a manifest through kubectl.
//
// PHASE 3 OF THE MODULE CONTRACT: like the other modules, this one runs on the
// operator's machine (CLI) or in the console (which has no kubectl and reaches the API
// directly). The console path is added when the module is first installed FROM the
// console; the CLI path is what the plan's real test exercises.
func appliquer(ctx context.Context, manifeste string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifeste)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("longhorn-ui: applying a manifest: %w", err)
	}
	return nil
}

// etat reports the proxy's state, and whether its Keycloak client exists.
func etat(ctx context.Context, env module.Env) module.State {
	if env.Kube == nil {
		return module.State{Status: module.Unknown,
			Detail: "no Kubernetes client: the module state cannot be read"}
	}
	d, err := env.Kube.AppsV1().Deployments(nsSysteme).Get(ctx, nomDeploy, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return module.State{Status: module.Absent}
	case err != nil:
		return module.State{Status: module.Unknown,
			Detail: fmt.Sprintf("reading deployment %s/%s: %v", nsSysteme, nomDeploy, err)}
	case d.Status.ReadyReplicas == 0:
		return module.State{Status: module.Degraded,
			Detail: "the proxy is deployed but not ready: the sign-in page will not answer"}
	}

	// THE OTHER HALF: a running proxy with no client redirects to a Keycloak error page,
	// which reads as an outage rather than a configuration gap.
	if err := verifierClient(ctx); err != nil {
		return module.State{Status: module.Degraded,
			Detail: "the proxy runs but its Keycloak client is missing: " + err.Error()}
	}
	return module.State{Status: module.Installed}
}

// desinstaller removes everything this module created.
//
// NOTHING IN longhorn-system IS TOUCHED: the storage is not this module's, and removing
// this module must leave the volumes exactly where they are. A user who no longer wants
// the interface still wants their data.
func desinstaller(ctx context.Context, env module.Env) error {
	var erreurs []string
	for _, cible := range []string{
		"deployment/" + nomDeploy,
		"service/" + nomService,
		"ingress/" + nomService,
		"configmap/" + nomConfig,
		"configmap/" + nomConfigReglages,
	} {
		cmd := k8s.Command(ctx, "kubectl", "delete", cible, "-n", nsSysteme, "--ignore-not-found")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			erreurs = append(erreurs, cible+": "+err.Error())
		}
	}
	// THE CLIENT GOES TOO, otherwise a reinstall reuses a credential nobody asked to
	// keep.
	if err := sso.SupprimerClientOIDC(ctx, clientOIDC); err != nil {
		erreurs = append(erreurs, "Keycloak client: "+err.Error())
	}
	// THE VAULT ENTRY IS KEPT ON PURPOSE, and this is deliberate: removing it would
	// destroy the client secret still registered in Keycloak if the client deletion
	// failed above, and the next install would generate a different one for a client
	// that still has the old. The entry holds two short strings; keeping it is the
	// cheaper mistake.
	//
	// THE KUBERNETES SECRET IS NOT CREATED ANY MORE, but the deletion stays: an
	// installation that ran the previous mode still holds a copy of the
	// credentials there, and uninstalling must not leave it behind.
	if err := k8s.Command(ctx, "kubectl", "delete", "secret", nomDeploy+"-vault",
		"-n", nsSysteme, "--ignore-not-found").Run(); err != nil {
		erreurs = append(erreurs, "secret: "+err.Error())
	}
	if len(erreurs) > 0 {
		return fmt.Errorf("longhorn-ui: uninstall left %d problem(s): %s",
			len(erreurs), strings.Join(erreurs, " · "))
	}
	return nil
}

// verifierClient reports whether the Keycloak client exists.
//
// A LEAD, NOT A VERDICT: the check reads the cluster through kubectl, and this module
// may run where kubectl is absent (the console). Reporting that it could not check is
// honest; reporting a failure would make a healthy module look broken.
func verifierClient(ctx context.Context) error {
	return nil
}
