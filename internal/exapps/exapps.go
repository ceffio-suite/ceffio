// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package exapps installs HaRP, the deploy daemon that lets Nextcloud install
// and run its External Apps (ExApps) inside this cluster.
//
// WHY THIS COMPONENT EXISTS AT ALL. Nextcloud's AI features — live
// transcription in Talk, assistants, Memories — are not PHP applications. They
// ship as CONTAINERS, and Nextcloud cannot start a container by itself: it
// needs a Deploy Daemon, a service it asks to "run this image with these
// variables". Without one, AppAPI reports "No registered daemon configs" and
// every ExApp install fails before it starts. That is the state Ceffio was in.
//
// WHY HaRP AND NOT SOMETHING ELSE. HaRP is published by the Nextcloud
// organisation itself (github.com/nextcloud/HaRP), described by the
// documentation as "the newer and the recommended way", and actively
// maintained. Above all it speaks the Kubernetes API NATIVELY: with
// HP_K8S_ENABLED it creates a Deployment and a PersistentVolumeClaim per ExApp
// and a Service for the exposure — no Docker socket involved.
//
// An earlier reading of the project concluded the opposite, on the strength of
// the first install example in its README (which mounts /var/run/docker.sock).
// That example is the DOCKER mode; the Kubernetes backend is documented further
// down the same file and exercised by the project's own k8s integration test.
// Verify before concluding, especially when the conclusion is "this cannot
// work".
//
// PERMISSIONS ARE DELIBERATELY NARROW. A Role scoped to the ExApp namespace,
// covering deployments, services, PVCs and pod listing. Nothing cluster-wide is
// needed as long as ExApps are exposed as ClusterIP — which is what we do, and
// which also keeps them off the public network by default.
package exapps

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
)

const (
	// The namespace where the ExApp workloads live. HaRP NEVER creates it —
	// it only manages resources inside it — so we create it first.
	//
	// Separate from ceffio-files on purpose: ExApps are third-party code, and
	// keeping them in their own namespace means a Role scoped to it cannot
	// reach anything of ours.
	nsExapps = "nextcloud-exapps"

	// Where the HaRP pod itself runs. It could live in the ExApp namespace,
	// but keeping it with the rest of the platform means its own permissions
	// (reading its config) do not sit next to the workloads it creates.
	nsHarp = "ceffio-system"

	nomHarp   = "appapi-harp"
	imageHarp = "ghcr.io/nextcloud/nextcloud-appapi-harp:release"

	// HaRP listens on 8780 for the AppAPI control calls, and 8782 for the FRP
	// tunnel it opens towards the ExApps.
	portControl = 8780
	portFRP     = 8782

	// The vault entry holding the shared key between Nextcloud and HaRP.
	entreeCoffre = "exapps/harp"
)

// Deploy installs HaRP and everything it needs, in dependency order:
//
//  1. the namespace the ExApps will live in
//  2. the ServiceAccount and its Role/RoleBinding
//  3. the shared key, in the vault
//  4. the HaRP pod itself
//
// It does NOT register the daemon in AppAPI: that is a Nextcloud-side action,
// done with occ once HaRP answers. See the note in the returned instructions.
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDeploying the ExApp deploy daemon (HaRP)...")

	if err := creerNamespace(ctx); err != nil {
		return err
	}
	if err := creerRBAC(ctx); err != nil {
		return err
	}
	cle, err := ensureClePartagee(ctx)
	if err != nil {
		return err
	}
	if err := deployerHarp(ctx, domain, cle); err != nil {
		return err
	}
	if err := attendrePret(ctx); err != nil {
		return err
	}

	fmt.Println("✓ ExApp deploy daemon (HaRP) deployed")
	fmt.Println("  Nextcloud still has to register it — run, once:")
	fmt.Printf("    occ app_api:daemon:register harp \\\n")
	fmt.Printf("      \"HaRP\" \"docker-install\" \"http\" \\\n")
	fmt.Printf("      %s.%s.svc:%d %s \\\n", nomHarp, nsHarp, portControl, "https://cloud."+domain)
	fmt.Println("      --k8s --k8s_namespace " + nsExapps + " --k8s_expose_type clusterip --set-default")
	return nil
}

// creerNamespace creates the ExApp namespace.
//
// HaRP manages resources INSIDE it but never creates it — its RBAC does not
// even allow that. Without this step the first ExApp install fails on a
// namespace that does not exist, which reads as a HaRP fault.
func creerNamespace(ctx context.Context) error {
	manifeste := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    app.kubernetes.io/part-of: ceffio
    # Marks the namespace as holding third-party workloads: nothing here is
    # written by us, and nothing here should be trusted with platform access.
    ceffio.io/role: exapps
`, nsExapps)
	return appliquer(ctx, manifeste)
}

// creerRBAC lays down the ServiceAccount, the Role and the RoleBinding.
//
// THE PERMISSIONS ARE SCOPE-LIMITED, and the list is the COMPLETE set the
// upstream README documents. Nothing wider is required as long as ExApps are
// exposed as ClusterIP; only the NodePort exposure would need cluster-scoped
// "nodes" reading, and we do not use it. The Role lives in the ExApp namespace
// (that is where the permissions apply) while its subject is the ServiceAccount
// the HaRP pod runs under, in ceffio-system. A mismatch in either the name or
// the namespace of that subject makes every HaRP request answer 403 — so these
// two values must stay aligned with deployerHarp below.
func creerRBAC(ctx context.Context) error {
	manifeste := fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[2]s
  namespace: %[3]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: harp-exapps
  namespace: %[1]s
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "create", "patch", "delete"]
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "list", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["create", "delete"]
  # Listing pods lets HaRP report an image pull failure immediately instead of
  # waiting for its startup timeout. It is the only reason this is needed.
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: harp-exapps
  namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: harp-exapps
subjects:
  - kind: ServiceAccount
    name: %[2]s
    # The namespace of the POD, not of this Role — the two differ on purpose.
    namespace: %[3]s
`, nsExapps, nomHarp, nsHarp)
	return appliquer(ctx, manifeste)
}

// ensureClePartagee puts the Nextcloud/HaRP shared key in the vault.
//
// The key authenticates the calls between AppAPI and the daemon. It is
// generated once and REFUSED on an existing entry: regenerating it would leave
// a daemon that starts, looks healthy, and rejects every request from
// Nextcloud — the same silent-breakage shape as the other components.
func ensureClePartagee(ctx context.Context) (string, error) {
	coffre := secrets.DepuisEnvironnement()

	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "exapps", "harp")
	switch {
	case err == nil:
	case secrets.EntreeAbsente(err):
		existant = map[string]string{}
	default:
		return "", fmt.Errorf("vault unreadable for exapps/harp: %w", err)
	}

	if cle := existant["shared-key"]; cle != "" {
		return cle, nil
	}

	cle, err := genSecret(32)
	if err != nil {
		return "", err
	}
	existant["shared-key"] = cle
	if err := secrets.EcrireDansCoffre(ctx, coffre, "exapps", "harp", existant); err != nil {
		return "", err
	}
	fmt.Println("∙ shared key generated and stored in the vault")
	return cle, nil
}

// deployerHarp creates the pod.
//
// SECRETS COME FROM THE INJECTOR, like every other component: HP_SHARED_KEY is
// read from the vault through the annotations, never written in the manifest.
// The container sources /secrets/env before starting, because HaRP — like the
// others — reads its configuration from the environment.
func deployerHarp(ctx context.Context, domain, _ string) error {
	annotations := vault.AnnotationsAgent(8, "exapps-harp", "kv/data/ceffio/exapps/harp",
		vault.GabaritExports("kv/data/ceffio/exapps/harp",
			[2]string{"HP_SHARED_KEY", vault.ChampCoffre("shared-key")},
		))

	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
      annotations:
%[3]s
    spec:
      serviceAccountName: %[1]s
      containers:
      - name: harp
        image: %[4]s
        imagePullPolicy: IfNotPresent
        # The secrets live in /secrets/env (written by the vault injector);
        # HaRP reads them from the environment and would otherwise start with
        # an empty shared key and refuse every AppAPI call.
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
          exec /entrypoint.sh
        env:
        # THE KUBERNETES BACKEND. Without this flag HaRP looks for a Docker
        # socket, does not find one, and the ExApp install fails.
        - name: HP_K8S_ENABLED
          value: "true"
        # Must match the Role and the namespace created above.
        - name: HP_K8S_NAMESPACE
          value: %[5]s
        - name: NC_INSTANCE_URL
          value: https://cloud.%[6]s
        # Leave empty to use the cluster default storage class. Stated
        # explicitly so the value is visible rather than implied.
        - name: HP_K8S_DEFAULT_STORAGE_SIZE
          value: 10Gi
        ports:
        - {name: control, containerPort: %[7]d}
        - {name: frp, containerPort: %[8]d}
        readinessProbe:
          httpGet: {path: /info, port: control}
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests: {memory: 128Mi, cpu: 50m}
          limits: {memory: 512Mi}
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
spec:
  selector:
    app: %[1]s
  ports:
  - {name: control, port: %[7]d, targetPort: %[7]d}
  - {name: frp, port: %[8]d, targetPort: %[8]d}
`, nomHarp, nsHarp, indentYaml(annotations, 8), imageHarp, nsExapps, domain, portControl, portFRP)

	return appliquer(ctx, manifeste)
}

// attendrePret blocks until HaRP answers on its control port.
//
// /info is the endpoint that reports whether HaRP reached the Kubernetes API.
// It proves connectivity and authentication only: with a wrong RoleBinding the
// API is still reported reachable, and the missing permission surfaces as a 403
// on the first ExApp install. So this passing does not mean "permissions are
// right", only "the daemon is up".
func attendrePret(ctx context.Context) error {
	fmt.Println("∙ waiting for HaRP to be ready...")
	fin := time.Now().Add(180 * time.Second)
	for time.Now().Before(fin) {
		cmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/"+nomHarp,
			"-n", nsHarp, "--timeout=10s")
		if err := cmd.Run(); err == nil {
			fmt.Println("  ✓ HaRP ready")
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("HaRP is not ready after 180s")
}

// ---------------------------------------------------------------------------

func genSecret(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b), nil
}

func appliquer(ctx context.Context, manifeste string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifeste)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("applying: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func indentYaml(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lignes := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lignes {
		if l != "" {
			lignes[i] = pad + l
		}
	}
	return strings.Join(lignes, "\n")
}
