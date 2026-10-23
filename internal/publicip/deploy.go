// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package publicip

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/ceffio-suite/ceffio/internal/version"
)

const (
	// NomDeploiement is the reporter workload.
	NomDeploiement = "ceffio-public-ip"

	// ServiceAccount is the identity the pod runs under: it reads and writes
	// one ConfigMap, nothing else.
	NomCompte = "ceffio-public-ip"

	// portSante is the health/read API port. The image is FROM scratch: no
	// shell, hence an HTTP probe rather than an exec one.
	portSante = 8080
)

// Image is the reporter image: the Ceffio image itself, which already carries
// the `publicip serve` subcommand.
//
// WHY NOT A SECOND ARTEFACT: the release already publishes a multi-arch,
// FROM-scratch image embedding the exact binaries of the release. Building a
// second one for a 200-line loop would double the supply chain for nothing —
// and the pod would still be the same size.
func Image() string {
	return "ghcr.io/ceffio-suite/ceffio:" + version.ImageTag()
}

func labels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       NomDeploiement,
		"app.kubernetes.io/managed-by": "ceffio",
	}
}

// Deploy installs the reporter: ServiceAccount, Role, RoleBinding, the empty
// ConfigMap (so readers see "nothing published yet" rather than NotFound) and
// the Deployment.
//
// IDEMPOTENT like every layer: re-running updates in place. The Deployment is
// NOT recreated on every install — restarting the reporter would not lose the
// published value, but it would produce a rollout on every `ceffio install`
// for no reason.
func Deploy(ctx context.Context, c kubernetes.Interface) error {
	if c == nil {
		return fmt.Errorf("publicip: no Kubernetes client")
	}

	if err := assurerCompte(ctx, c); err != nil {
		return err
	}
	if err := assurerRole(ctx, c); err != nil {
		return err
	}
	if err := assurerLiaison(ctx, c); err != nil {
		return err
	}
	if err := assurerConfigMap(ctx, c); err != nil {
		return err
	}
	return assurerDeploiement(ctx, c)
}

func assurerCompte(ctx context.Context, c kubernetes.Interface) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: NomCompte, Namespace: Namespace, Labels: labels()},
	}
	_, err := c.CoreV1().ServiceAccounts(Namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("publicip: creating ServiceAccount %s/%s: %w", Namespace, NomCompte, err)
}

// assurerRole grants exactly what the reporter does: read/write ONE ConfigMap.
// No pods, no secrets, no exec.
func assurerRole(ctx context.Context, c kubernetes.Interface) error {
	voulu := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: NomCompte, Namespace: Namespace, Labels: labels()},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "create", "update", "patch"},
		}},
	}
	roles := c.RbacV1().Roles(Namespace)
	actuel, err := roles.Get(ctx, NomCompte, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := roles.Create(ctx, voulu, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("publicip: creating Role %s/%s: %w", Namespace, NomCompte, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("publicip: reading Role %s/%s: %w", Namespace, NomCompte, err)
	}
	actuel.Rules = voulu.Rules
	actuel.Labels = voulu.Labels
	if _, err := roles.Update(ctx, actuel, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("publicip: updating Role %s/%s: %w", Namespace, NomCompte, err)
	}
	return nil
}

func assurerLiaison(ctx context.Context, c kubernetes.Interface) error {
	nom := NomCompte
	voulu := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: nom, Namespace: Namespace, Labels: labels()},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: NomCompte, Namespace: Namespace}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: nom},
	}
	lbs := c.RbacV1().RoleBindings(Namespace)
	actuel, err := lbs.Get(ctx, nom, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := lbs.Create(ctx, voulu, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("publicip: creating RoleBinding %s/%s: %w", Namespace, nom, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("publicip: reading RoleBinding %s/%s: %w", Namespace, nom, err)
	}
	actuel.Subjects = voulu.Subjects
	actuel.RoleRef = voulu.RoleRef
	actuel.Labels = voulu.Labels
	if _, err := lbs.Update(ctx, actuel, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("publicip: updating RoleBinding %s/%s: %w", Namespace, nom, err)
	}
	return nil
}

// assurerConfigMap creates the publication target empty. An absent object and
// an empty one are not the same answer: the first looks like a broken install,
// the second says "the reporter has not published yet".
func assurerConfigMap(ctx context.Context, c kubernetes.Interface) error {
	cms := c.CoreV1().ConfigMaps(Namespace)
	_, err := cms.Get(ctx, Nom, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("publicip: reading ConfigMap %s/%s: %w", Namespace, Nom, err)
	}
	_, err = cms.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: Nom, Namespace: Namespace, Labels: labels()},
		Data:       map[string]string{},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("publicip: creating ConfigMap %s/%s: %w", Namespace, Nom, err)
	}
	return nil
}

func assurerDeploiement(ctx context.Context, c kubernetes.Interface) error {
	replicas := int32(1)
	nonRoot := true
	lectureSeule := true
	pasDEscalade := false
	seccomp := corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	uid := int64(65532)
	gid := int64(65532)

	voulu := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: NomDeploiement, Namespace: Namespace, Labels: labels()},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": NomDeploiement}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"app": NomDeploiement},
					Annotations: map[string]string{AnnotationIP: ""},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: NomCompte,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   &nonRoot,
						RunAsUser:      &uid,
						RunAsGroup:     &gid,
						SeccompProfile: &seccomp,
					},
					Containers: []corev1.Container{{
						Name:            "reporter",
						Image:           Image(),
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            []string{"publicip", "serve"},
						Ports: []corev1.ContainerPort{{
							Name: "http", ContainerPort: portSante, Protocol: corev1.ProtocolTCP,
						}},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &pasDEscalade,
							ReadOnlyRootFilesystem:   &lectureSeule,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/healthz", Port: intstr.FromInt32(portSante),
								},
							},
							InitialDelaySeconds: 3,
							PeriodSeconds:       10,
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/healthz", Port: intstr.FromInt32(portSante),
								},
							},
							InitialDelaySeconds: 15,
							PeriodSeconds:       30,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("10m"),
								corev1.ResourceMemory: resource.MustParse("24Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
					}},
				},
			},
		},
	}

	ds := c.AppsV1().Deployments(Namespace)
	actuel, err := ds.Get(ctx, NomDeploiement, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := ds.Create(ctx, voulu, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("publicip: creating Deployment %s/%s: %w", Namespace, NomDeploiement, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("publicip: reading Deployment %s/%s: %w", Namespace, NomDeploiement, err)
	}

	// UPDATE IN PLACE, but only the fields this layer owns. The pod template
	// annotations are NOT copied: the reporter patches the public-ip annotation
	// on its consumers, and overwriting the template on every install would
	// erase the one it wrote on itself — harmless here, but the same habit
	// applied to a consumer would trigger a rollout on every reinstall.
	actuel.Labels = voulu.Labels
	actuel.Spec.Replicas = voulu.Spec.Replicas
	actuel.Spec.Selector = voulu.Spec.Selector
	actuel.Spec.Template.Spec = voulu.Spec.Template.Spec
	if actuel.Spec.Template.Labels == nil {
		actuel.Spec.Template.Labels = voulu.Spec.Template.Labels
	}
	if _, err := ds.Update(ctx, actuel, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("publicip: updating Deployment %s/%s: %w", Namespace, NomDeploiement, err)
	}
	return nil
}
