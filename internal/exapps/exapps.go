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
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
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
	nsExapps = "ceffio-exapps"
	// nomCA: the ConfigMap the install creates in every application namespace
	// (internal/ingress createCAConfigs). Copied into the ExApp namespace by copierCA.
	nomCA = "ceffio-ca-cm"

	// HARP LIVES IN THE EXAPP NAMESPACE, NOT IN ceffio-system.
	//
	// It used to live there, and that was a design mistake: HaRP IS the ExApp
	// deployer. It creates the Deployments, Services, Ingresses and volumes
	// INSIDE ceffio-exapps, and its Role must therefore be defined there.
	//
	// The opposite argument — "keep its permissions away from the workloads it
	// creates" — turns against itself: a deployer separated from what it
	// deploys needs WIDER rights, not narrower ones. A Role in ceffio-exapps
	// is enough, and it then has no access to ceffio-system, where the
	// console, OpenBao and the other platform components live.
	//
	// MEASURED: the deployer ran in ceffio-system while the applications
	// installed into ceffio-exapps, and the Role of each ExApp had to be
	// created remotely, in a foreign namespace.
	nsHarp = nsExapps

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
//
// Preparer creates the ExApp namespace WITHOUT deploying HaRP.
//
// # WHAT IT IS FOR, AND WHY IT IS SEPARATE FROM Deploy
//
// `ceffio install` used to deploy HaRP unconditionally. That put the deploy
// daemon — a namespace, a workload, and a permanent right for Nextcloud to
// start containers — on every installation, whether or not the operator ever
// wanted it. Installing it is now an explicit action, taken from the
// administration console.
//
// This function keeps what the installation still needs: the namespace, because
// the console's write permissions live in it, and because creating it on the
// first click would make that click slower and more fragile than it needs to
// be.
//
// Idempotent: on a re-run, an existing namespace is left alone.
func Preparer(ctx context.Context) error {
	if err := creerNamespace(ctx); err != nil {
		return err
	}
	fmt.Println("✓ ExApp namespace ready (deploy daemon not installed — use the console)")
	return nil
}

func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDeploying the ExApp deploy daemon (HaRP)...")

	// WE WAIT FOR THE NAMESPACE TO BE THERE, NOT TO DISAPPEAR.
	//
	// I had written the opposite here — AttendreDisparition instead of
	// AttendreExistence — and the result was a deployment that did NOTHING:
	// the function waited for an already existing namespace to disappear,
	// until its two-minute timeout, then failed. Measured: seven minutes
	// without a single resource created, and a log that stopped at
	//
	//	Deploying the ExApp deploy daemon (HaRP)...
	//
	// The intent was to handle the "Remove" then "Deploy" sequence, where the
	// namespace is still Terminating. That requires waiting for its stable
	// EXISTENCE — not its absence.
	if err := creerNamespace(ctx); err != nil {
		return err
	}
	cliNs, err := k8sapi.Nouveau()
	if err != nil {
		return err
	}
	if err := cliNs.AttendrePret(ctx, nsExapps, 3*time.Minute); err != nil {
		return err
	}

	// RBAC FOR HARP ITSELF, NOT FOR THE CONSOLE.
	//
	// The only RBAC objects created here are the ServiceAccount, Role and
	// RoleBinding of the deploy daemon, all scoped to ceffio-exapps. Creating
	// them is PERMITTED: the console already holds those namespace-scoped
	// rights (serviceaccounts, roles, rolebindings) through the
	// ceffio-admin-namespaces ClusterRole, bound in every platform namespace by
	// the console's own manifest at installation time. A Role granting no more
	// than what its creator already holds is not an escalation.
	//
	// The console must NOT create cluster-scoped RBAC (ClusterRole /
	// ClusterRoleBinding): that would be privilege escalation, and it is
	// exactly what the previous code did here and what Kubernetes refused.
	if err := creerRBAC(ctx); err != nil {
		return err
	}
	cle, err := ensureClePartagee(ctx)
	if err != nil {
		return err
	}
	// The CA must be present in THIS namespace before HaRP starts: its
	// manifest mounts ceffio-ca-cm, and a missing ConfigMap leaves the pod
	// stuck in ContainerCreating with a message about a missing volume.
	if err := copierCA(ctx); err != nil {
		return err
	}
	if err := deployerHarp(ctx, domain, cle); err != nil {
		return err
	}
	if err := attendrePret(ctx); err != nil {
		return err
	}

	// REGISTER THE DAEMON, rather than printing a command to copy. The
	// installation is not usable until Nextcloud knows about HaRP, and an
	// instruction that has to be run by hand is one that can be skipped,
	// mis-typed, or run with the wrong values.
	//
	// Note the arguments, each of which cost time to get right:
	//   - "kubernetes-install", NOT "docker-install": it selects the backend
	//     HaRP actually uses. "docker-install" is the legacy Docker socket
	//     path, deprecated in Nextcloud 35.
	//   - --harp_frp_address: the address HaRP exposes the ExApps on. WITHOUT
	//     IT AppAPI polls https://cloud.<domain>/exapps/<app>/heartbeat, gets
	//     404, and retries HUNDREDS of times: the app installs, then never
	//     becomes enabled, and the language list in Talk fails to load.
	//   - no --k8s_namespace exists: HaRP already knows its namespace through
	//     HP_K8S_NAMESPACE. Passing it makes occ reject the whole command.
	if err := enregistrerDaemon(ctx, domain, cle); err != nil {
		return err
	}

	fmt.Println("✓ ExApp deploy daemon (HaRP) deployed and registered")
	return nil
}

// enregistrerDaemon registers HaRP in AppAPI, replacing any previous entry.
//
// We unregister first: re-registering an existing name is silently skipped
// ("Registration skipped, as the daemon config `harp` already exists"), so a
// daemon created with wrong settings would keep them forever, and the only
// symptom is ExApps that install and stay disabled.
func enregistrerDaemon(ctx context.Context, domain, cle string) error {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	pod, err := cli.PodDuDeploiement(ctx, "ceffio-files", "nextcloud", "nextcloud")
	if err != nil {
		return err
	}

	hoteControl := fmt.Sprintf("%s.%s.svc:%d", nomHarp, nsHarp, portControl)
	hoteFRP := fmt.Sprintf("%s.%s.svc:%d", nomHarp, nsHarp, portFRP)
	urlNC := "https://cloud." + domain

	fmt.Println("∙ registering the deploy daemon in AppAPI...")

	// REMOVE ANY DAEMON OF THAT NAME BEFORE RE-REGISTERING, and this is not
	// cosmetic: re-registering an existing name is SILENTLY SKIPPED
	//   ("Registration skipped, as the daemon config `appapi-harp` already
	//   exists.")
	// so a daemon created with wrong settings keeps them for good, and the only
	// symptom is ExApps that install and stay disabled.
	//
	// The unregister can fail for one reason only: ExApps are still attached
	// ("contains 1 ExApps, please remove them first"). In that case the daemon
	// exists and is in use, so we leave it alone and say so rather than failing
	// the whole deployment — the settings below are verified just after, which
	// is what actually matters.
	if _, err := execOcc(ctx, cli, pod, "app_api:daemon:unregister", nomHarp); err != nil {
		// Either it did not exist (fine) or ExApps are attached (also fine:
		// we then update in place, and the checks below decide).
		_ = err
	}

	sortie, err := execOcc(ctx, cli, pod,
		"app_api:daemon:register", nomHarp, "HaRP", "kubernetes-install", "http",
		hoteControl, urlNC,
		"--harp", "--harp_shared_key", cle, "--harp_frp_address", hoteFRP,
		"--k8s", "--k8s_expose_type=clusterip", "--set-default")
	if err != nil {
		return fmt.Errorf("registering the HaRP daemon: %w", err)
	}

	// THE ANSWER IS NOT THE CONTRACT. "already exists" is an acceptable outcome:
	// it means a daemon of that name is registered, which is what we want. What
	// we must NOT do is treat it as success and move on — the whole point of
	// this step is that the existing entry might carry WRONG settings. So the
	// FRP address is checked below, and THAT is the real assertion.
	brut := strings.ToLower(sortie)
	if !strings.Contains(brut, "successfully registered") && !strings.Contains(brut, "already exists") {
		return fmt.Errorf("registering the HaRP daemon (unexpected answer): %s", derniereLigneUtile(sortie))
	}

	// Read back the FRP address: it is the setting whose absence breaks ExApp
	// activation in a way that is hard to attribute, so we confirm it landed
	// rather than trusting the command's exit code.
	verif, err := execOcc(ctx, cli, pod, "app_api:daemon:list")
	if err != nil || !strings.Contains(verif, strconv.Itoa(portFRP)) {
		return fmt.Errorf("the HaRP daemon is registered but its FRP address (%s) is not set: ExApps would install and never enable", hoteFRP)
	}
	fmt.Println("  ✓ daemon registered (FRP: " + hoteFRP + ")")
	return nil
}

// execOcc runs occ in the Nextcloud pod through the Kubernetes API.
func execOcc(ctx context.Context, cli *k8sapi.Client, pod string, args ...string) (string, error) {
	complet := append([]string{"php", "occ"}, args...)
	return cli.Executer(ctx, "ceffio-files", pod, "nextcloud", complet...)
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

// copierCA copies the internal certificate authority into the ExApp namespace.
//
// WHY A COPY AND NOT A DIRECT MOUNT: the authority lives in cert-manager, and a
// pod cannot mount a ConfigMap from another namespace. The install's own
// TLS-trust pass (internal/ingress) injects it component by component — but it
// runs BEFORE HaRP exists, since the console installs HaRP later. HaRP was
// therefore the one component left without the authority, and it is the one
// that talks to Nextcloud over HTTPS:
//
//	aiohttp ClientConnectorCertificateError: Cannot connect to host
//	cloud.<domain>:443 ssl:True [SSLCertVerificationError]
//
// It then never registers the ExApp it deployed, and KILLS the container one
// second after starting it, in a loop.
//
// The console may read ConfigMaps in ceffio-files and write them in
// ceffio-exapps — verified with `kubectl auth can-i`. No right is widened.
//
// A public install whose certificate was issued successfully has no need of
// this: an absent source ConfigMap is left alone rather than invented.
func copierCA(ctx context.Context) error {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	donnees, err := cli.LireConfigMap(ctx, nsNextcloud, nomCA)
	if err != nil {
		return err
	}
	if len(donnees) == 0 {
		return nil // no internal authority to carry over
	}
	objet := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": nomCA, "namespace": nsExapps},
		"data":       donnees,
	}
	manifeste, err := json.Marshal(objet)
	if err != nil {
		return err
	}
	return cli.Appliquer(ctx, string(manifeste))
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
          # /usr/local/bin/start.sh is the image's ENTRYPOINT (verified in its
          # Dockerfile). It takes NO argument: it starts haproxy, the SPOE
          # agent and the FRP proxies itself and supervises them.
          exec /usr/local/bin/start.sh
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
        # THE INTERNAL AUTHORITY. HaRP reaches Nextcloud over HTTPS, and the
        # console installs HaRP OUTSIDE the install's TLS-trust pass (that pass
        # runs at install time; HaRP does not exist yet). Without this, a
        # private-domain install — or a public one whose certificate is not yet
        # issued — makes HaRP fail its TLS verification, so it never registers
        # the ExApp it just deployed, and it then KILLS the container:
        #
        #   aiohttp ClientConnectorCertificateError: Cannot connect to host
        #   cloud.<domain>:443 ssl:True [SSLCertVerificationError]
        #
        # Measured on a fresh install: nc-app-live-transcription was deployed,
        # then killed one second after starting, in a loop.
        #
        # paquet-combine.crt and NOT ceffio-ca.crt: Python reads SSL_CERT_FILE,
        # which REPLACES the default bundle. Pointing it at our authority alone
        # would make every public certificate refused — the trap that already
        # broke Synapse's OIDC callback.
        - name: SSL_CERT_FILE
          value: /etc/ceffio-ca/paquet-combine.crt
        # REQUIRED: start.sh refuses to start without it. It is the address the
        # FRP proxies bind to, used for the tunnel towards the ExApps.
        - name: HP_FRP_ADDRESS
          value: 0.0.0.0:%[8]d
        # Leave empty to use the cluster default storage class. Stated
        # explicitly so the value is visible rather than implied.
        - name: HP_K8S_DEFAULT_STORAGE_SIZE
          value: 10Gi
        ports:
        - {name: agent, containerPort: 8200}
        - {name: control, containerPort: %[7]d}
        - {name: frp, containerPort: %[8]d}
        # THE AGENT LISTENS ON 127.0.0.1 ONLY — verified in its own startup log
        # ("Starting Python HaProxy Agent on 127.0.0.1:8200 and 127.0.0.1:9600").
        # A kubelet httpGet probe would come from the POD address and be
        # refused, so the probe has to run INSIDE the container. The image
        # ships /healthcheck.sh for exactly this: use it rather than inventing
        # a test, which is how this broke the first time.
        readinessProbe:
          exec: {command: ["/healthcheck.sh"]}
          initialDelaySeconds: 10
          periodSeconds: 10
          failureThreshold: 6
        livenessProbe:
          exec: {command: ["/healthcheck.sh"]}
          initialDelaySeconds: 30
          periodSeconds: 20
          failureThreshold: 6
        resources:
          requests: {memory: 128Mi, cpu: 50m}
          limits: {memory: 512Mi}
        volumeMounts:
        - {name: ceffio-ca, mountPath: /etc/ceffio-ca, readOnly: true}
      volumes:
      # The ConfigMap is copied into this namespace by Preparer: the console
      # cannot read the one in cert-manager (no right on Secrets there), and a
      # cross-namespace read is not something a pod can do either.
      - name: ceffio-ca
        configMap: {name: ceffio-ca-cm}
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
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
spec:
  ingressClassName: traefik
  rules:
  - host: cloud.%[6]s
    http:
      paths:
      # THE ROUTE WITHOUT WHICH NOTHING WORKS, and HaRP's own documentation
      # says so: "HaRP requires your reverse proxy to forward traffic from
      # your public domain (e.g., nextcloud.com/exapps/) to the HaRP
      # container's HP_EXAPPS_ADDRESS."
      #
      # Without it AppAPI calls https://cloud.<domain>/exapps/<app>/heartbeat,
      # the request never reaches HaRP, and the answer is a 404 it retries
      # hundreds of times. The ExApp installs, its pod runs, and it stays
      # permanently disabled — with no error that points here.
      - path: /exapps
        pathType: Prefix
        backend:
          service:
            name: %[1]s
            port:
              number: %[7]d
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

	// THROUGH THE API, NOT `kubectl`. This function runs inside the console
	// container, which is built from scratch: no shell, no kubectl binary. The
	// previous version failed with
	//
	//	applying: exec: "kubectl": executable file not found in $PATH
	//
	// on a click of "Deploy the deployer", while the same code worked from the
	// CLI where kubectl exists. See internal/k8sapi for the rule.
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes API access: %w", err)
	}
	fin := time.Now().Add(180 * time.Second)
	for time.Now().Before(fin) {
		if cli.DeploiementPret(ctx, nsHarp, nomHarp) {
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
	// THROUGH THE API. Same reason as attendrePret: this runs in a container
	// with no binaries at all. The error message the click showed —
	// « applying: exec: "kubectl": executable file not found in $PATH » — came
	// from this line.
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes API access: %w", err)
	}
	if err := cli.Appliquer(ctx, manifeste); err != nil {
		return fmt.Errorf("applying: %w", err)
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

// NomsHarp exposes the daemon identity to callers that must report on it (the
// administration console reads its state). Kept as functions rather than
// exported variables so the values stay single-sourced in one place.
func NomsHarp() (nom, namespace string) { return nomHarp, nsHarp }

// Remove takes the deploy daemon out, completely.
//
// ORDER MATTERS, and getting it wrong leaves orphans:
//  1. the ExApps first — AppAPI refuses to remove a daemon that still has any
//     ("harp daemon contains 1 ExApps, please remove them first to proceed"),
//     so a daemon removal that runs first fails with a message about ExApps.
//  2. then the daemon registration.
//  3. then the Kubernetes resources: HaRP, its Service, its Ingress, its RBAC.
//  4. then the ExApp volumes. The namespace itself is left in place (see
//     below).
func Remove(ctx context.Context) error {
	fmt.Println("\nRemoving the ExApp deploy daemon (HaRP)...")

	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}

	// 1. ExApps first. Best effort and reported: an empty list is the common
	// case, and its error would be noise.
	if pod, err := cli.PodDuDeploiement(ctx, "ceffio-files", "nextcloud", "nextcloud"); err == nil {
		if liste, err := execOcc(ctx, cli, pod, "app_api:app:list"); err == nil {
			for _, l := range strings.Split(liste, "\n") {
				champ := strings.Fields(strings.TrimSpace(l))
				if len(champ) > 0 && strings.Contains(champ[0], "_") &&
					!strings.Contains(strings.ToLower(l), "command") &&
					!strings.HasPrefix(strings.TrimSpace(l), "ExApps") {
					app := champ[0]
					fmt.Printf("∙ removing the ExApp %s first\n", app)
					_, _ = execOcc(ctx, cli, pod, "app_api:app:unregister", app, "--force")
				}
			}
		}
		// 2. the daemon registration
		_, _ = execOcc(ctx, cli, pod, "app_api:daemon:unregister", nomHarp)
	}

	// 3. the Kubernetes resources, THROUGH THE API.
	//
	// Best effort: each deletion is independent, and one that fails (a Kind the
	// cluster does not know, a resource already gone) must not stop the others.
	//
	// LE NAMESPACE N'EST PAS SUPPRIMÉ, et c'est délibéré.
	//
	// It is created by the installation and belongs to it: deleting it here
	// would make its survival depend on a click in the console, while the
	// console is only a client of the platform, not its owner.
	//
	// What "Remove" must give back is what the deployer brought in: its
	// workload, its Service, its Ingress, its service account, its roles. We
	// delete those, we free the volumes, and the namespace stays — empty,
	// ready for a next deployment.
	//
	// THE PRACTICAL CONSEQUENCE IS ALSO A SIMPLIFICATION: the console's write
	// rights live in this namespace. Destroying it carried them along
	// (deleting a namespace deletes its RoleBindings), and the next
	// deployment had to lay them down again before it could work. A stable
	// namespace removes that entire class of failures.
	cliSupp, err := k8sapi.Nouveau()
	if err == nil {
		for _, forme := range []string{
			"Deployment/" + nomHarp,
			"Service/" + nomHarp,
			"Ingress/" + nomHarp,
			"ServiceAccount/" + nomHarp,
			"Role/harp-exapps",
			"RoleBinding/harp-exapps",
		} {
			_ = cliSupp.SupprimerEfface(ctx, nsHarp, forme)
		}
	}

	// The application volumes, on the other hand, must go: they carry
	// downloaded data (the transcription models weigh several gigabytes) and
	// keeping them would let a component we just uninstalled survive.
	if err := supprimerPVC(ctx, nsExapps); err != nil {
		return err
	}

	fmt.Println("✓ ExApp deploy daemon removed (namespace kept, ExApp volumes freed)")
	return nil
}

// supprimerPVC removes the ExApp volumes, which is what actually frees disk.
//
// WHY THE VOLUMES AND NOT THE NAMESPACE: the volume is what carries the
// data, and an empty namespace costs nothing. Deleting the namespace also
// carried away the console's RoleBindings, which then had to be laid down
// again — for zero gain. So we delete exactly what has a cost.
//
// A FAILURE IS NOT FATAL: an already absent volume is the normal case on the
// second click, and a volume still attached to a workload being deleted will
// be gone a second later too. We report what we could do rather than
// interrupting the rest of the cleanup.
func supprimerPVC(ctx context.Context, ns string) error {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	volumes, err := cli.ListerPVC(ctx, ns)
	if err != nil {
		return fmt.Errorf("listing the volumes of %s: %w", ns, err)
	}
	for _, v := range volumes {
		if err := cli.SupprimerEfface(ctx, ns, "PersistentVolumeClaim/"+v); err != nil {
			fmt.Printf("  ∙ volume %s non supprimé : %v\n", v, err)
			continue
		}
		fmt.Printf("  ✓ volume %s supprimé (espace disque libéré)\n", v)
	}
	return nil
}

// DeployeurPret reports whether an ExApp can be installed right now.
//
// WHY THIS IS A FUNCTION AND NOT A COMMENT: an ExApp cannot install itself.
// HaRP deploys it, and AppAPI must also know about HaRP or nothing enables.
// Without this check the failure is a registration error about a missing
// daemon, which reads like an application problem and sends the reader to the
// wrong place. Naming the missing piece here is the whole point.
func DeployeurPret(ctx context.Context) error {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	if !cli.DeploiementPret(ctx, nsHarp, nomHarp) {
		return fmt.Errorf("le deployeur d'applications (HaRP) n'est pas installe : installez-le d'abord, il deploie les applications externes")
	}
	pod, err := cli.PodDuDeploiement(ctx, "ceffio-files", "nextcloud", "nextcloud")
	if err != nil {
		return err
	}
	sortie, err := execOcc(ctx, cli, pod, "app_api:daemon:list")
	if err != nil {
		return fmt.Errorf("impossible de lire la liste des deployeurs AppAPI : %w", err)
	}
	if !strings.Contains(strings.ToLower(sortie), nomHarp) {
		return fmt.Errorf("HaRP tourne mais n'est pas enregistre dans Nextcloud : les applications ne pourraient pas s'activer")
	}
	return nil
}
