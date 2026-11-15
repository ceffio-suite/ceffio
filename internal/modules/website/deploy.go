// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package website

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/version"
	"github.com/ceffio-suite/ceffio/internal/website"
)

const (
	// nsSite is the module's own namespace.
	//
	// WHY ITS OWN AND NOT ceffio-system: the page is optional and public;
	// giving it a namespace means `ceffio module remove website` can prove it
	// removed everything it created, and that nothing else ends up in the
	// same blast radius. The namespace is declared in Info.Namespaces, so the
	// platform chart also creates it on a fresh install — which is what lets
	// the CONSOLE install this module under a namespace-scoped identity.
	nsSite = "ceffio-website"

	// nomPage names every object the module owns. One name for all of them
	// keeps `kubectl get all -n ceffio-website` readable and makes it obvious,
	// in a diff, that the whole set moves together.
	nomPage = "ceffio-website"

	// portHTTP is the container port. Not 80: the pod needs no
	// NET_BIND_SERVICE, and nothing outside the cluster talks to the pod
	// directly — Traefik terminates TLS and forwards to the Service.
	portHTTP int32 = 8080

	// cleNginx is the ConfigMap key carrying the server configuration. It is
	// NOT part of internal/website: that package holds what a visitor sees,
	// this key holds how it is served.
	cleNginx = "nginx.conf"

	// secretTLS is the certificate cert-manager issues for the host. Its own
	// name, not the platform wildcard: the page must be removable without
	// touching the certificate every other service depends on.
	secretTLS = "ceffio-website-tls"

	// uidNginx is the "nginx" user of the official Alpine image. It is needed
	// for one thing only — the group that receives the writable volumes when
	// the root filesystem is read-only (see manifesteDeploiement).
	uidNginx int64 = 101

	// delaiDeploiement bounds the rollout wait. A static page over a 20 MB
	// image has no reason to need longer; if it does, something is wrong and
	// saying so beats hanging.
	delaiDeploiement = 3 * time.Minute

	// periodeAttente is the poll interval for the rollout wait.
	periodeAttente = 2 * time.Second
)

// imagePage is the ONLY third-party runtime EXECUTED for this module.
//
// WHY A THIRD-PARTY STATIC SERVER AND NOT THE CEFFIO IMAGE: the page must be
// servable by the release that carries it, and a Ceffio image only knows the
// subcommands of the version it was built from — a module cannot ask an older
// binary to grow a `website serve` command, and the module contract forbids
// adding one (docs/adding-a-module.md, checklist item 11: a CLI subcommand
// named after the feature means the contract was not extended where it should
// have been).
//
// WHY NGINX ALPINE, PINNED BY TAG **AND** DIGEST: it serves bytes out of a
// ConfigMap and does nothing else — no PHP, no proxy, no dynamic module. The
// digest is what makes "does nothing else" verifiable: a tag can be
// republished, a digest cannot. The reference lives in internal/version
// (Registry), which is how `upgrade` and the SBOM see it — never as a literal
// here, where it would drift. A var, not a const: the registry is initialised
// before this package's variables are.
var imagePage = version.Image("nginx")

// nginxConf is the ENTIRE server configuration, mounted over
// /etc/nginx/conf.d. Mounting a directory hides what the image ships, so this
// text is the only server block nginx will load: nothing reaches the internet
// that is not written here.
//
// WHY THE SECURITY HEADERS ARE SET BY THE SERVER AND NOT ONLY IN THE PAGE: a
// page can always be edited by someone in a hurry; a header set here applies
// to every future version of it. The page is a leaf — no form, no script, no
// frame — so the policy can be maximally strict without breaking anything.
const nginxConf = `# Ceffio — public landing page. Mounted over conf.d: this is the only
# server block nginx loads.
server {
    listen       ` + "8080" + `;
    listen       [::]:` + "8080" + `;
    server_name  _;

    root   /usr/share/nginx/html;
    index  index.html;

    # Do not advertise the exact nginx build.
    server_tokens off;
    autoindex     off;

    # The page is static: no script, no form, no frame, no external origin.
    # Keeping the policy this narrow is only possible because the page really
    # is that narrow — internal/website/site_test.go fails if a script or a
    # remote asset ever appears.
    add_header Content-Security-Policy      "default-src 'none'; img-src 'self' data:; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
    add_header X-Content-Type-Options       "nosniff" always;
    add_header X-Frame-Options              "DENY" always;
    add_header Referrer-Policy              "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy           "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy   "same-origin" always;

    # TLS is terminated by Traefik in front of this pod, which is why the
    # header is legitimate here even though nginx itself speaks http.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Kubernetes probes. No access-log line: they would be the only entries in
    # the log, and they say nothing.
    location = /healthz {
        access_log   off;
        default_type text/plain;
        return 200 "ok\n";
    }

    # Files on disk only. A missing page is a 404, never a listing.
    location / {
        try_files $uri $uri/ =404;
    }
}
`

// labels go on every object the module creates: they identify the owner for a
// human reading the cluster, and they are what `ceffio status` groups on.
func labels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       nomPage,
		"app.kubernetes.io/part-of":    "ceffio",
		"app.kubernetes.io/managed-by": "ceffio",
		"ceffio.io/role":               "website",
	}
}

// selecteurs is the pod selector. Deliberately a SUBSET of labels(): adding a
// label to the objects later must never change which pods the Service and the
// Deployment consider theirs (the Deployment's selector is immutable).
func selecteurs() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name": nomPage,
	}
}

// assurerNamespace creates the namespace when the platform chart has not.
//
// WHY THE MODULE DOES THIS ITSELF: the chart declares ceffio-website, so a
// fresh install gets it before any module runs — but an installation that
// upgrades an OLDER release has no chart entry yet, and `ceffio module
// install website` must work there too. Tolerating AlreadyExists makes the
// two paths identical.
func assurerNamespace(ctx context.Context, c kubernetes.Interface) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsSite, Labels: labels()}}
	_, err := c.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	switch {
	case err == nil || apierrors.IsAlreadyExists(err):
		return nil
	case apierrors.IsForbidden(err):
		// The console installs modules under a namespace-scoped identity: it
		// cannot create a namespace, and pretending otherwise would produce a
		// confusing "forbidden" halfway through the operation.
		return fmt.Errorf("website: namespace %s does not exist and this identity cannot create it: "+
			"run `ceffio install` once (the platform chart declares that namespace), then retry: %w", nsSite, err)
	}
	return fmt.Errorf("website: creating namespace %s: %w", nsSite, err)
}

// rendre builds the ConfigMap payload for ONE installation, and a checksum of
// it.
//
// The checksum goes into the pod template: it is what makes a CONTENT change
// (a new page, a fixed header) roll the pods, while an install that changes
// nothing rolls nothing. Kubernetes does not do that for ConfigMaps by
// itself — a mounted ConfigMap is updated in place, but nginx has already
// read it.
func rendre(domaine string) (map[string]string, string, error) {
	donnees, err := website.Files(domaine)
	if err != nil {
		return nil, "", err
	}
	donnees[cleNginx] = nginxConf
	return donnees, somme(donnees), nil
}

// somme is a stable fingerprint of the ConfigMap payload.
func somme(donnees map[string]string) string {
	cles := make([]string, 0, len(donnees))
	for k := range donnees {
		cles = append(cles, k)
	}
	sort.Strings(cles)
	h := sha256.New()
	for _, k := range cles {
		fmt.Fprintf(h, "%s\x00%s\x00", k, donnees[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// assurerConfigMap creates or reconciles the ConfigMap. It only rewrites it
// when the CONTENT changed, so a re-install that changes nothing touches
// nothing.
func assurerConfigMap(ctx context.Context, c kubernetes.Interface, donnees map[string]string) error {
	voulu := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: nomPage, Namespace: nsSite, Labels: labels()},
		Data:       donnees,
	}
	cms := c.CoreV1().ConfigMaps(nsSite)
	actuel, err := cms.Get(ctx, nomPage, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := cms.Create(ctx, voulu, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("website: creating ConfigMap %s/%s: %w", nsSite, nomPage, err)
		}
	case err != nil:
		return fmt.Errorf("website: reading ConfigMap %s/%s: %w", nsSite, nomPage, err)
	default:
		if memesEntrees(actuel.Data, voulu.Data) {
			return nil
		}
		actuel.Data = voulu.Data
		actuel.Labels = voulu.Labels
		if _, err := cms.Update(ctx, actuel, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("website: updating ConfigMap %s/%s: %w", nsSite, nomPage, err)
		}
	}
	return nil
}

// memesEntrees compares two string maps.
func memesEntrees(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if av, ok := b[k]; !ok || av != v {
			return false
		}
	}
	return true
}

// manifesteDeploiement is the pod that serves the page.
//
// THE POD IS DELIBERATELY BORING: one container, one read-only filesystem, no
// service account token, no writable volume except the two nginx needs. A
// public-facing container is the one an attacker reaches first, so it gets the
// smallest surface that still serves a static page.
func manifesteDeploiement(empreinte string) *appsv1.Deployment {
	un := int32(1)

	items := make([]corev1.KeyToPath, 0, len(website.Paths()))
	for _, p := range website.Paths() {
		items = append(items, corev1.KeyToPath{Key: p.Cle, Path: p.Chemin})
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: nomPage, Namespace: nsSite, Labels: labels()},
		Spec: appsv1.DeploymentSpec{
			Replicas: &un,
			Selector: &metav1.LabelSelector{MatchLabels: selecteurs()},
			// One page, one pod: the Service load-balances nothing, and a
			// rolling update is enough to avoid a blank moment.
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels(),
					// The checksum is what turns a page edit into a rollout.
					Annotations: map[string]string{"ceffio.io/page-checksum": empreinte},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						// Read-only root filesystem: the writable volumes get
						// this group, which is the nginx user of the image.
						FSGroup: ptr(uidNginx),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					// The page needs no Kubernetes API: do not mount a token
					// that would let a compromised nginx talk to it.
					AutomountServiceAccountToken: ptr(false),
					Containers: []corev1.Container{{
						Name:            "nginx",
						Image:           imagePage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Ports: []corev1.ContainerPort{{
							Name: "http", ContainerPort: portHTTP, Protocol: corev1.ProtocolTCP,
						}},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr(false),
							ReadOnlyRootFilesystem:   ptr(true),
							Capabilities: &corev1.Capabilities{
								// nginx starts as root to open its log files and
								// drop to the nginx user; everything else is
								// taken away.
								Drop: []corev1.Capability{"ALL"},
								Add:  []corev1.Capability{"CHOWN", "SETGID", "SETUID"},
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("10m"),
								corev1.ResourceMemory: resource.MustParse("16Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							// The page itself: projected with paths, because a
							// ConfigMap key cannot contain a slash while the
							// English page must live at /en/index.html.
							{Name: "page", MountPath: "/usr/share/nginx/html", ReadOnly: true},
							// Our server block, mounted over the image's conf.d:
							// the image's own default.conf disappears with it.
							{Name: "conf", MountPath: "/etc/nginx/conf.d", ReadOnly: true},
							// The only two writable paths nginx needs once its
							// root filesystem is read-only.
							{Name: "cache", MountPath: "/var/cache/nginx"},
							{Name: "run", MountPath: "/var/run"},
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path: "/healthz", Port: intstr.FromString("http"),
							}},
							InitialDelaySeconds: 1,
							PeriodSeconds:       5,
							TimeoutSeconds:      2,
							FailureThreshold:    3,
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path: "/healthz", Port: intstr.FromString("http"),
							}},
							InitialDelaySeconds: 10,
							PeriodSeconds:       20,
							TimeoutSeconds:      2,
							FailureThreshold:    3,
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "page", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: nomPage},
							Items:                items,
						}}},
						{Name: "conf", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: nomPage},
							Items:                []corev1.KeyToPath{{Key: cleNginx, Path: "default.conf"}},
						}}},
						{Name: "cache", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
						{Name: "run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					},
				},
			},
		},
	}
}

// ptr returns a pointer to v. The Kubernetes builders take pointers for every
// optional field, and a shared variable would make the manifest alias-prone
// (two fields would then share one bool, and a later change would move both).
func ptr[T any](v T) *T { return &v }

// assurerDeploiement creates or reconciles the Deployment.
//
// It only rewrites the spec when the IMAGE or the PAGE changed: a re-install
// that changes nothing must not restart a working pod.
func assurerDeploiement(ctx context.Context, c kubernetes.Interface, empreinte string) error {
	voulu := manifesteDeploiement(empreinte)
	depls := c.AppsV1().Deployments(nsSite)
	actuel, err := depls.Get(ctx, nomPage, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := depls.Create(ctx, voulu, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("website: creating Deployment %s/%s: %w", nsSite, nomPage, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("website: reading Deployment %s/%s: %w", nsSite, nomPage, err)
	}

	change := actuel.Spec.Template.Annotations["ceffio.io/page-checksum"] != empreinte ||
		len(actuel.Spec.Template.Spec.Containers) != 1 ||
		actuel.Spec.Template.Spec.Containers[0].Image != imagePage
	if !change {
		return nil
	}
	actuel.Spec = voulu.Spec
	actuel.Labels = voulu.Labels
	if _, err := depls.Update(ctx, actuel, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("website: updating Deployment %s/%s: %w", nsSite, nomPage, err)
	}
	return nil
}

// assurerService exposes the pod inside the cluster; Traefik is the only
// client.
func assurerService(ctx context.Context, c kubernetes.Interface) error {
	voulu := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: nomPage, Namespace: nsSite, Labels: labels()},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: selecteurs(),
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Port:       80,
				TargetPort: intstr.FromInt32(portHTTP),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
	svcs := c.CoreV1().Services(nsSite)
	actuel, err := svcs.Get(ctx, nomPage, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := svcs.Create(ctx, voulu, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("website: creating Service %s/%s: %w", nsSite, nomPage, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("website: reading Service %s/%s: %w", nsSite, nomPage, err)
	}
	// ClusterIP is immutable: keep the one the cluster assigned.
	voulu.Spec.ClusterIP = actuel.Spec.ClusterIP
	voulu.Spec.ClusterIPs = actuel.Spec.ClusterIPs
	if actuel.Spec.Ports[0].Port == voulu.Spec.Ports[0].Port && memesEntrees(actuel.Spec.Selector, voulu.Spec.Selector) {
		return nil
	}
	actuel.Spec.Ports = voulu.Spec.Ports
	actuel.Spec.Selector = voulu.Spec.Selector
	actuel.Labels = voulu.Labels
	if _, err := svcs.Update(ctx, actuel, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("website: updating Service %s/%s: %w", nsSite, nomPage, err)
	}
	return nil
}

// assurerIngress publishes the page on the installation's ROOT host.
//
// WHY THE ROOT HOST: the suite already owns the apex (the console serves
// /.well-known/security.txt there), and a landing page on "www" would be a
// second name to explain. The host comes from Env.Domain — never from a
// constant: the same binary must serve whatever host its installation uses.
//
// WHY websecure ONLY: this is the only route of the suite whose sole purpose
// is public traffic, so it must not answer in clear. Restricting the router to
// the secure entrypoint leaves the plain-HTTP behaviour of the host exactly as
// it was before the module existed (no route), and it cannot interfere with an
// HTTP-01 challenge, which cert-manager solves on its own route.
func assurerIngress(ctx context.Context, c kubernetes.Interface, domaine string) error {
	prefixe := networkingv1.PathTypePrefix
	voulu := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: nomPage, Namespace: nsSite, Labels: labels(),
			Annotations: map[string]string{
				"cert-manager.io/cluster-issuer":                   ingress.PourDomaine(domaine),
				"traefik.ingress.kubernetes.io/router.entrypoints": "websecure",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr("traefik"),
			TLS: []networkingv1.IngressTLS{{
				Hosts:      []string{domaine},
				SecretName: secretTLS,
			}},
			Rules: []networkingv1.IngressRule{{
				Host: domaine,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &prefixe,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: nomPage,
									Port: networkingv1.ServiceBackendPort{Number: 80},
								},
							},
						}},
					},
				},
			}},
		},
	}
	ings := c.NetworkingV1().Ingresses(nsSite)
	actuel, err := ings.Get(ctx, nomPage, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := ings.Create(ctx, voulu, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("website: creating Ingress %s/%s: %w", nsSite, nomPage, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("website: reading Ingress %s/%s: %w", nsSite, nomPage, err)
	}
	// The host may legitimately have changed (a renamed installation): take
	// the desired rule whenever it differs.
	// Rules[0] is read only after checking the slice: an Ingress edited to
	// have no rule at all is drift like any other, not a reason to panic.
	if len(actuel.Spec.Rules) == 1 && actuel.Spec.Rules[0].Host == domaine &&
		memesEntrees(actuel.Annotations, voulu.Annotations) {
		return nil
	}
	actuel.Annotations = voulu.Annotations
	actuel.Spec = voulu.Spec
	actuel.Labels = voulu.Labels
	if _, err := ings.Update(ctx, actuel, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("website: updating Ingress %s/%s: %w", nsSite, nomPage, err)
	}
	return nil
}
