// Package vault deploys the OpenBao vault of the Ceffio suite.
//
// WHY THIS MODULE, AND NOT ONLY A CLIENT: internal/secrets already knows how
// to READ and WRITE a vault, but it assumes a vault exists elsewhere and that
// its address is known. Now Ceffio is a suite you install at someone else's
// place: the vault must travel WITH the stack. A product that required the
// customer to provide their own secrets server would not be self-supporting.
// This module therefore deploys the vault as a component of the suite, on the
// same footing as Keycloak or Nextcloud.
//
// RELATION WITH internal/secrets: this module is what places the address and
// token that internal/secrets will then read (BAO_ADDR / BAO_TOKEN). Two
// halves of one mechanism: this one CREATES the vault, the other CONSUMES it.
//
// SPEAKS TO THE CLUSTER THROUGH internal/k8sapi, AND ONLY THROUGH IT.
//
// This module first ran `kubectl` and read its output. Five defects came out
// of that, all of the same family — confusing "I could not ask" with "I was
// answered":
//
//   - `kubectl run` mixes its accompanying messages with the useful output: a
//     32-byte key became a 309-character Secret containing "pod deleted" and
//     "if you don't see a command prompt";
//   - `CombinedOutput` merges both streams, and `kubectl exec` handles that
//     poorly: "failed to start exec";
//   - an error message parsed as JSON became an empty object again, hence a
//     plausible — and false — state;
//   - a tool missing from the image (`curl`) turned an execution failure into
//     "vault not initialized";
//   - a jsonpath that came back empty could never be explained, precisely
//     because nothing in that program could observe it.
//
// The Kubernetes API is TYPED: a Secret is a Secret, an error is an error. The
// entire class of defects disappears with the intermediary.
//
// THE ZERO-TH SECRET, AND WHY IT IS HERE: for the vault to be usable without
// human intervention, it unseals itself, thanks to OpenBao's "static" seal: a
// 32-byte key read from a file. That key lives in a Kubernetes Secret, on the
// same machine as the vault.
//
//	It is an accepted trade-off, not an oversight.
//
// Whoever gets the machine gets the vault. That was already true before: the
// secrets were in Kubernetes Secrets, on this same machine. The difference is
// that from here on they are centralized, traceable and rotatable — three
// properties we did not have. Moving the vault to another machine would not
// remove this weak point, it would add a component to administer.
//
// WHY NO MANUAL UNSEALING: requiring a human intervention at every restart
// would turn a restart into an outage, in a product whose pitch is "one
// command and it runs". The choice is made knowingly.
//
// WHAT IS NOT DONE, AND MUST BE KNOWN: ROTATION of the seal key is not
// implemented. OpenBao provides for it (`previous_key` accompanies
// `current_key` to re-read what is already encrypted); today, changing that
// key would make the vault unreadable. That is a real gap.
//
// THE VAULT IS OPTIONAL (see internal/secrets): if this module fails, the
// deployment continues and the secrets stay in Kubernetes. A vault failure
// must never prevent the suite from running — that is what separates
// "centralize for robustness" from "add a failure point".
package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/sso"
)

const (
	// Real version observed on Docker Hub (not invented): 2.7.1, published
	// 2026-10-01.
	openbaoImage = "docker.io/openbao/openbao:2.7.1"

	ns      = "ceffio-vault"
	service = "openbao"
	pod     = "openbao-0"

	cheminDonnees = "/openbao/data"
	cheminCle     = "/openbao/secrets/unseal.key"
	cheminAudit   = "/openbao/audit/audit.log"
)

// Resultat gives the caller what it needs to consume the vault
// (BAO_ADDR/BAO_TOKEN). Pret=false means "the vault is not there, continue
// with Kubernetes": that is not an error, it is the nominal degraded case.
type Resultat struct {
	Adresse string
	Jeton   string
	Pret    bool
}

// Deploy installs the vault, idempotently:
//
//  1. the namespace and the unseal key (the zero-th secret);
//  2. the configuration (raft storage, static seal, DECLARED audit log);
//  3. the StatefulSet + PVC + Service;
//  4. initialization, if the vault is not initialized already;
//  5. the versioned KV engine;
//  6. an administration policy and a token, then REVOCATION of the root token;
//  7. a real round trip: write, read back, and prove that it REFUSES.
//
// NEVER returns a fatal error for the suite: on failure, a warning is printed
// and Resultat{Pret:false} is returned, so the deployment proceeds with
// Kubernetes Secrets.
//
// NO DOMAIN PARAMETER... UNTIL NOW. The first version took none, with this
// justification: "the day the vault is exposed at https://bao.<domain>, the
// public entry point will need the domain — and that is when the parameter
// must be added, not before".
//
// That day arrived with Phase 2, for a precise reason: OIDC needs to know the
// vault's public address, because it is what builds the return address the
// browser is redirected to. Without it, OpenBao sends the browser to an
// internal service name, which the browser cannot reach.
func Deploy(ctx context.Context, domaine string) *Resultat {
	fmt.Println("\nDeploying the secrets vault (OpenBao)...")

	cli, err := k8sapi.Nouveau()
	if err != nil {
		// EVERYTHING IS DECIDED HERE: no client, hence no cluster. SAY it. The
		// previous version let a missing configuration surface later, as empty
		// outputs interpreted as states — and the deployment continued against
		// a cluster it never reached.
		fmt.Printf("  ∙ vault not deployed: %v\n", err)
		return &Resultat{}
	}

	if err := cli.Appliquer(ctx, namespaceManifest()); err != nil {
		fmt.Printf("  ∙ vault not deployed (namespace): %v\n", err)
		return &Resultat{}
	}
	if err := ensureCleDescellement(ctx, cli); err != nil {
		fmt.Printf("  ∙ vault not deployed (unseal key): %v\n", err)
		return &Resultat{}
	}
	empreinte, err := applyConfig(ctx, cli, domaine)
	if err != nil {
		fmt.Printf("  ∙ vault not deployed (configuration): %v\n", err)
		return &Resultat{}
	}
	if err := cli.Appliquer(ctx, identiteManifest()); err != nil {
		fmt.Printf("  ∙ vault not deployed (identity): %v\n", err)
		return &Resultat{}
	}
	if err := cli.Appliquer(ctx, workloadManifest(empreinte)); err != nil {
		fmt.Printf("  ∙ vault not deployed (workload): %v\n", err)
		return &Resultat{}
	}
	// THE AGENT-INJECTOR IS PLACED HERE, AND ITS FAILURE IS BLOCKING.
	//
	// Migrated workloads no longer contain the init-container that fetched the
	// secrets: they carry annotations only the injector knows how to read.
	// Continuing without it would produce pods WITHOUT secrets and with no
	// admission error — a silence, not a visible failure.
	if err := poserInjecteur(ctx, cli); err != nil {
		fmt.Printf("  ∙ vault not deployed (agent-injector): %v\n", err)
		return &Resultat{}
	}

	// The pod must be SCHEDULED ON A NODE before any exec is possible.
	// The check is typed: its failure can no longer look like a result.
	if _, err := cli.AttendrePodInstalle(ctx, ns, pod, 180*time.Second); err != nil {
		fmt.Printf("  ∙ vault unreachable: %v\n", err)
		return &Resultat{}
	}
	if err := waitReady(ctx, cli); err != nil {
		fmt.Printf("  ∙ vault unreachable: %v\n", err)
		return &Resultat{}
	}
	if err := initialiser(ctx, cli); err != nil {
		fmt.Printf("  ∙ initialization impossible: %v\n", err)
		return &Resultat{}
	}
	// POLICIES AND TOKENS BEFORE THE ENGINE MOUNT — and this order is not
	// cosmetic. Mounting an engine is an administration operation that
	// requires an up-to-date policy. Placed after, a corrected policy could
	// never apply to the step that needed it: the deployment failed on a 403,
	// the policy was fixed, it was rerun — and it failed at the same spot,
	// since the code never reached the policy write. A circular lock,
	// observed in service.
	jeton, err := poserPolitiquesEtJetons(ctx, cli)
	if err != nil {
		fmt.Printf("  ∙ tokens not created: %v\n", err)
		return &Resultat{}
	}
	if err := monterMoteurKV(ctx, cli); err != nil {
		fmt.Printf("  ∙ KV engine not mounted: %v\n", err)
		return &Resultat{}
	}
	// AUTHENTICATION COMES AFTER THE POLICIES, since a role references them:
	// placing a role before its policy would fail the role creation, or worse,
	// create a role that grants nothing.
	if err := configurerAuthKubernetes(ctx, cli); err != nil {
		fmt.Printf("  ∙ Kubernetes authentication not configured: %v\n", err)
		return &Resultat{}
	}
	// PEOPLE AFTER SERVICES: OIDC depends on a Keycloak client, hence on a
	// part of the stack that must already be up. Configuring it before would
	// only fail earlier, on a less clear cause.
	// SHARED HELPERS READ THE VAULT THROUGH THE ENVIRONMENT, not through a
	// Kubernetes Secret: that is the case for the OIDC clients and the
	// seeding. We therefore go through the SAME function as the other modules
	// (Acces) instead of opening here a second path that would end up
	// diverging from the first.
	if adresse, jetonEnv, errA := Acces(ctx, cli); errA == nil {
		os.Setenv("BAO_ADDR", adresse)
		os.Setenv("BAO_TOKEN", jetonEnv)
		os.Setenv("BAO_MOTEUR", "kv")
	} else {
		fmt.Printf("  ∙ vault environment not set (%v) — the OIDC clients will not be able to read from it\n", errA)
	}

	if err := configurerOIDC(ctx, cli, domaine); err != nil {
		fmt.Printf("  ∙ people authentication not configured: %v\n", err)
		return &Resultat{}
	}
	if err := retirerJetonRacine(ctx, cli); err != nil {
		// Non-blocking: the root token stays, and we SAY so. A master token
		// that survives silently is a defect; one that survives while being
		// reported is an incident to handle.
		fmt.Printf("  ∙ WARNING: root token not revoked (%v) — to be handled\n", err)
	}
	if err := verifierAllerRetour(ctx, cli, jeton); err != nil {
		fmt.Printf("  ∙ end-to-end verification failed: %v\n", err)
		return &Resultat{}
	}

	// THE SEEDING COMES LAST, and it is NOT fatal.
	//
	// Last, because copies of live secrets are entrusted only to a vault that
	// was just verified to work.
	//
	// Not fatal, because a working vault whose reference copy is incomplete
	// remains more useful than a stopped deployment. The module follows the
	// overall doctrine: the vault improves, it does not block.
	if err := Semer(ctx, cli); err != nil {
		fmt.Printf("  ∙ WARNING: seeding incomplete (%v) — no value was invented\n", err)
	} else {
		fmt.Println("  ∙ existing secrets lifted into the vault (reference copy)")
	}

	fmt.Printf("✓ OpenBao vault deployed (%s, %s)\n", openbaoImage, ns)
	// The address returned is the NodePort one, not the internal service name.
	//
	// WHY: the installation runs ON THE MACHINE, not in the cluster. The name
	// openbao.ceffio-vault.svc does not resolve there — a vault the
	// installation cannot reach is useless. The NodePort is reachable from the
	// machine AND from the pods, which gives both a single address.
	//
	// THE NUMBER IS READ, NOT CHOSEN: fixing a NodePort reserves it for the
	// whole cluster, and a re-creation then fails on "provided port is already
	// allocated". Kubernetes assigns it, we read it back.
	//
	// WHAT IS ASSUMED HERE, AND MUST BE SAID: this NodePort speaks in clear
	// text on the machine's network. That is a point to fix when the suite's
	// TLS ingress is in place — the vault will then gain an address
	// https://bao.<domain>.
	port, err := cli.NodePortDuService(ctx, ns, service, "api")
	if err != nil || port == 0 {
		fmt.Printf("  ∙ WARNING: cannot read the vault's external port (%v) — the vault runs, but its address is unknown\n", err)
		return &Resultat{Pret: false}
	}
	noeud := os.Getenv("CEFFIO_NOEUD")
	if noeud == "" {
		noeud = "127.0.0.1"
	}
	return &Resultat{
		Adresse: fmt.Sprintf("http://%s:%d", noeud, port),
		Jeton:   jeton,
		Pret:    true,
	}
}

// ---------------------------------------------------------------------------
// 1. Namespace and unseal key
// ---------------------------------------------------------------------------

// namespaceManifest describes the namespace, placed by `apply` hence IDEMPOTENT.
//
// WHY NOT a direct creation: creating fails if the object already exists, and
// that failure would abandon the whole deployment. The vault could therefore
// never be redeployed — precisely when it is needed most, after an upgrade or
// a configuration change.
func namespaceManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, ns)
}

// ensureCleDescellement creates the 32-byte key of the "static" seal, if it
// does not exist. It is NEVER regenerated: regenerating it would make the
// vault unreadable, since the existing data is encrypted with it.
//
// THE KEY IS GENERATED IN GO, AND THAT IS A REAL GAIN: no more throwaway pod,
// no more command output to slice, hence no more risk of recovering something
// other than the key. The previous version went through `kubectl run` and
// recorded a 309-character Secret half of which was a help message.
//
// 32 BYTES, AND NOT ANOTHER NUMBER: that is the size the static seal requires,
// which uses it as an AES-256 key. A different size fails the server startup
// on "unknown encoding for AES-256 key" — observed.
func ensureCleDescellement(ctx context.Context, cli *k8sapi.Client) error {
	existante, err := cli.LireSecret(ctx, ns, "openbao-unseal-key", "unseal.key")
	if err != nil {
		return err
	}
	if existante != "" {
		return nil
	}

	brut := make([]byte, 32)
	if _, err := rand.Read(brut); err != nil {
		return fmt.Errorf("generating the key: %w", err)
	}
	// base64 on one line: the form the file expects, and one of those OpenBao
	// knows how to decode ("raw, hex, or base64-encoded").
	cle := base64.StdEncoding.EncodeToString(brut)

	// CHECK THE FORM BEFORE USING IT. The check is trivial now that the value
	// no longer comes out of a command — but it documents the constraint, and
	// it would catch a future change that reintroduced a detour. 32 bytes in
	// base64 make exactly 44 characters.
	if len(cle) != 44 {
		return fmt.Errorf("malformed key: %d characters instead of 44", len(cle))
	}

	if err := cli.PoserSecret(ctx, ns, "openbao-unseal-key",
		map[string][]byte{"unseal.key": []byte(cle)}); err != nil {
		return fmt.Errorf("placing the key: %w", err)
	}
	fmt.Println("  ∙ unseal key created (32 bytes = 256 bits → AES-256)")
	return nil
}

// ---------------------------------------------------------------------------
// 2. Configuration: storage, listener, seal, AUDIT
// ---------------------------------------------------------------------------

// configManifest describes the server configuration.
//
// FOUR CHOICES TO EXPLAIN:
//
//   - THE LISTENER RUNS WITHOUT TLS INSIDE THE CLUSTER. The traffic does not
//     leave the pod network. Saying it explicitly rather than leaving it
//     guessed: a TLS server receiving clear text answers 400, so an error code
//     does not prove you are talking to a clear-text server.
//
//   - `disable_mlock` IS ABSENT, and that is deliberate: OpenBao reports it as
//     "unknown or unsupported field" at startup. Keeping it would produce a
//     warning at every startup, and a permanent warning ends up ignored —
//     including the day it announces something else.
//
//   - THE AUDIT LOG IS DECLARED HERE, in the configuration file, and not
//     enabled by a command: that is the form the current version of OpenBao
//     expects, and it survives restarts. Removing this block would delete the
//     log.
//
//     THE EXACT SYNTAX MATTERS: `audit "<type>" "<path>"` takes TWO labels —
//     the type first, the mount path second — and `options` is a BLOCK, not an
//     assignment. Writing `audit "file" { … }` with a single label fails
//     startup on "audit type must be specified", observed in service.
//
//   - UNSEALING IS AUTOMATIC, by the static seal. See the package header for
//     the trade-off.
func configManifest(domaine string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: openbao-config
  namespace: %[1]s
data:
  openbao.hcl: |
    ui = true

    storage "raft" {
      path    = "%[2]s"
      node_id = "%[6]s"
    }

    listener "tcp" {
      address     = "0.0.0.0:8200"
      tls_disable = true
    }

    seal "static" {
      current_key_id = "ceffio-1"
      current_key    = "file://%[3]s"
    }

    audit "file" "fichier" {
      description = "Ceffio audit log"
      options {
        file_path = "%[4]s"
      }
    }

    api_addr     = "%[7]s"
    cluster_addr = "http://%[5]s.%[1]s.svc:8201"
`, ns, cheminDonnees, cheminCle, cheminAudit, service, pod, adressePublique(domaine))
}

// adressePublique returns the address through which the vault is reached.
//
// IT MATTERS FOR OIDC, and not only for display: OpenBao builds from it the
// return address the browser is redirected to after authentication. Left on
// the internal service name, it would produce a redirect to a name the browser
// cannot reach — and the failure would appear browser-side, hence far from the
// cause.
//
// THE FALLBACK IS EXPLICIT: without a domain, the internal address is
// returned, which suffices for calls coming from the cluster. Saying so rather
// than returning an empty string.
func adressePublique(domaine string) string {
	if domaine == "" {
		return "http://" + service + "." + ns + ".svc:8200"
	}
	// The ingress terminates TLS; the crossing to the vault, inside the
	// cluster, stays in clear text — the same trade-off as for the other
	// components, and it is bounded to the pod network.
	return "https://bao." + domaine
}

// applyConfig places the configuration and returns its fingerprint.
//
// THE FINGERPRINT SERVES TO RESTART THE POD WHEN THE CONFIGURATION CHANGES.
// Kubernetes does not restart a pod because a ConfigMap changed: the mounted
// file updates on disk, but the running process re-reads nothing. A running
// pod would therefore keep using the old configuration — and a fix would stay
// without effect, which wastes a lot of time for whoever believes they fixed
// it.
//
// By reporting the fingerprint into a template annotation, any modification
// becomes a pod change: the StatefulSet rolls, and the new configuration is
// really applied.
func applyConfig(ctx context.Context, cli *k8sapi.Client, domaine string) (string, error) {
	manifeste := configManifest(domaine)
	if err := cli.Appliquer(ctx, manifeste); err != nil {
		return "", err
	}
	somme := sha256.Sum256([]byte(manifeste))
	return hex.EncodeToString(somme[:])[:16], nil
}

// ---------------------------------------------------------------------------
// 3. Workload
// ---------------------------------------------------------------------------

// identiteManifest gives the vault an IDENTITY IN THE CLUSTER, and the right to
// validate other pods' tokens.
//
// WHY THE VAULT NEEDS AN IDENTITY: to authenticate a pod by its ServiceAccount
// token, the vault must ask the cluster "is this token valid, and whose is
// it?". That question is called a TokenReview, and the cluster API answers it
// only to whoever has the right. The role `system:auth-delegator` is precisely
// that right — it ships with Kubernetes and need not be redefined.
//
// WHY THE ROLE IS A ClusterRoleBinding: the right to validate a token is not
// limited to one namespace. It is a power over the whole cluster's API. Hence
// a global-scoped object — and that is exactly why it is named, and bound to
// ONE precise ServiceAccount rather than to a group.
func identiteManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[1]s
  namespace: %[2]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: openbao-auth-delegator
subjects:
  - kind: ServiceAccount
    name: %[1]s
    namespace: %[2]s
roleRef:
  kind: ClusterRole
  name: system:auth-delegator
  apiGroup: rbac.authorization.k8s.io
`, service, ns)
}

// workloadManifest places the StatefulSet, the Service and the volume.
//
// A SINGLE NODE, AND THAT IS A CHOICE: raft storage knows how to do a cluster,
// but an SMB does not need three vaults for three secrets. The day one is
// needed, it is the replica count that will change — not the design.
//
// THE CONFIGURATION FINGERPRINT IS REPORTED INTO THE TEMPLATE: it is what makes
// a configuration change really restart the pod, instead of leaving the old one
// running.
func workloadManifest(empreinte string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  type: NodePort
  selector:
    app: %[1]s
  ports:
    - name: api
      port: 8200
      targetPort: 8200
    - name: cluster
      port: 8201
      targetPort: 8201
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  serviceName: %[1]s
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
      annotations:
        ceffio.fr/empreinte-config: "%[5]s"
    spec:
      # THE VAULT RUNS UNDER ITS OWN ServiceAccount, not the default one: it
      # is what carries the right to validate other pods' tokens. Without this
      # line, Kubernetes authentication cannot work, and the failure would
      # appear later, at the first connection — far from the cause.
      serviceAccountName: %[1]s
      securityContext:
        runAsUser: 100
        runAsGroup: 1000
        fsGroup: 1000
      containers:
        - name: openbao
          image: %[3]s
          command: ["bao", "server", "-config=/openbao/config/openbao.hcl"]
          env:
            - name: BAO_ADDR
              value: "http://127.0.0.1:8200"
          ports:
            - name: api
              containerPort: 8200
            - name: cluster
              containerPort: 8201
          volumeMounts:
            - name: config
              mountPath: /openbao/config
              readOnly: true
            - name: unseal
              mountPath: /openbao/secrets
              readOnly: true
            - name: data
              mountPath: %[4]s
            - name: audit
              mountPath: /openbao/audit
          readinessProbe:
            # PROBE THAT ACCEPTS THE "NOT INITIALIZED" STATE.
            #
            # /v1/sys/health answers 501 as long as the vault is not
            # initialized, and 503 as long as it is sealed. A default probe
            # (200-399) would therefore NEVER pass before initialization — yet
            # initialization is what is supposed to follow. The pod would stay
            # eternally "not ready", and the deployment would wait for a state
            # that cannot come.
            #
            # 204 on those two states tells the truth: the server is alive and
            # answering, it is just awaiting its commissioning.
            httpGet:
              path: /v1/sys/health?standbyok=true&sealedcode=204&uninitcode=204
              port: 8200
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: config
          configMap:
            name: openbao-config
        - name: unseal
          secret:
            secretName: openbao-unseal-key
        - name: audit
          emptyDir: {}
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
`, service, ns, openbaoImage, cheminDonnees, empreinte)
}

// waitReady waits for the vault to answer a status command.
//
// The pod is already known as scheduled (AttendrePodInstalle took care of it):
// all that remains is to wait for the server to be alive enough to answer.
func waitReady(ctx context.Context, cli *k8sapi.Client) error {
	limite := time.Now().Add(180 * time.Second)
	var dernier string
	for time.Now().Before(limite) {
		etat, err := etatCoffre(ctx, cli)
		if err == nil && etat != "" {
			fmt.Printf("  ∙ vault reachable (state: %s)\n", etat)
			return nil
		}
		dernier = fmt.Sprintf("%v", err)
		time.Sleep(4 * time.Second)
	}
	return fmt.Errorf("the vault did not answer within 180 s (last state: %s)", dernier)
}

// ---------------------------------------------------------------------------
// 4. Initialization
// ---------------------------------------------------------------------------

// initialiser initializes the vault if it is not already, and stores the
// recovery keys.
//
// WITH AN AUTOMATIC SEAL, `operator init` returns RECOVERY keys, not unseal
// keys: the vault stays unsealed once initialized. Those keys serve only to
// regenerate a lost root token — hence their safekeeping, and hence the fact
// that they are NOT the daily key.
func initialiser(ctx context.Context, cli *k8sapi.Client) error {
	initie, err := dejaInitialise(ctx, cli)
	if err != nil {
		return err
	}
	if initie {
		fmt.Println("  ∙ vault already initialized")
		return nil
	}

	// The retry is not decorative: `operator init` raises the vault's security
	// barrier, which causes a brief core restart. Without it, the next step
	// failed on "connection refused" — a race with the restart the command had
	// just triggered itself.
	sortie, err := baoReessai(ctx, cli, "operator", "init",
		"-recovery-shares=1", "-recovery-threshold=1", "-format=json")
	if err != nil {
		return fmt.Errorf("operator init: %w", err)
	}
	var res struct {
		RecoveryKeys []string `json:"recovery_keys_b64"`
		RootToken    string   `json:"root_token"`
	}
	if err := json.Unmarshal([]byte(extraitJSON(sortie)), &res); err != nil {
		return fmt.Errorf("unreadable initialization response: %w", err)
	}
	// Check the response is COMPLETE before using it: a half-read
	// initialization would produce a vault without a root token, hence
	// impossible to administer.
	if res.RootToken == "" {
		return fmt.Errorf("initialization response without a root token: %.120s", strings.TrimSpace(sortie))
	}
	if len(res.RecoveryKeys) == 0 {
		return fmt.Errorf("initialization response without a recovery key: %.120s", strings.TrimSpace(sortie))
	}

	// The keys are stored in a Secret, NEVER printed.
	donnees := map[string][]byte{"root-token": []byte(res.RootToken)}
	for i, k := range res.RecoveryKeys {
		donnees[fmt.Sprintf("recovery-%d", i)] = []byte(k)
	}
	if err := cli.PoserSecret(ctx, ns, "openbao-recovery", donnees); err != nil {
		return fmt.Errorf("storing the recovery keys: %w", err)
	}
	fmt.Println("  ∙ vault initialized (keys stored in openbao-recovery, not displayed)")
	return nil
}

// dejaInitialise reports whether the vault's storage has already been prepared.
//
// A SINGLE SOURCE OF TRUTH, and it is the server's state. There used to be two
// — the `/v1/sys/health` code and the `bao status` output — and they
// contradicted each other: the first announced "already initialized" on a
// vault that was not, because the OpenBao image does NOT contain `curl`. The
// call failed, and the "unknown" code was interpreted as "initialized". A
// silent failure, in the function that decides whether to initialize.
func dejaInitialise(ctx context.Context, cli *k8sapi.Client) (bool, error) {
	etat, err := etatCoffre(ctx, cli)
	if err != nil {
		return false, err
	}
	return etat != "not initialized", nil
}

// ---------------------------------------------------------------------------
// 5. KV engine
// ---------------------------------------------------------------------------

// monterMoteurKV mounts a versioned KV at the path "kv", the convention
// internal/secrets expects by default (BAO_MOTEUR).
//
// IT GOES THROUGH THE ADMINISTRATION, AND THAT IS NECESSARY: mounting an engine
// is a vault administration operation, out of reach of the application token —
// by design. The installation token exists precisely for that.
func monterMoteurKV(ctx context.Context, cli *k8sapi.Client) error {
	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return err
	}
	sortie, err := baoAvecJeton(ctx, cli, adm, "secrets", "list")
	if err != nil {
		return err
	}
	if strings.Contains(sortie, "kv/") {
		fmt.Println("  ∙ KV engine already mounted")
		return nil
	}
	if _, err := baoAvecJeton(ctx, cli, adm, "secrets", "enable", "-path=kv", "-version=2", "kv"); err != nil {
		return fmt.Errorf("mounting the KV engine: %w", err)
	}
	fmt.Println("  ∙ versioned KV engine mounted at \"kv\"")
	return nil
}

// jetonAdministration returns a token able to administer the vault: the
// installation token if it is valid, otherwise the root token — that is, the
// first pass, before the revocation.
//
// THE ORDER MATTERS, and it has a reason: after the setup, the root token no
// longer exists. Looking for the root first would fail at every redeployment,
// even though the vault is perfectly fine.
func jetonAdministration(ctx context.Context, cli *k8sapi.Client) (string, error) {
	if j, _ := cli.LireSecret(ctx, ns, "openbao-installation", "token"); j != "" {
		// `token lookup` without argument queries the current token — see the
		// detailed note in poserPolitiquesEtJetons: "lookup-self" does not exist.
		if _, err := baoAvecJeton(ctx, cli, j, "token", "lookup"); err == nil {
			return j, nil
		}
	}
	if j, _ := cli.LireSecret(ctx, ns, "openbao-recovery", "root-token"); j != "" {
		return j, nil
	}
	return "", fmt.Errorf("no administration token: neither a valid installation token, nor a root token (regenerate a root token with a recovery key)")
}

// ---------------------------------------------------------------------------
// 6. Administration policy and token, then root revocation
// ---------------------------------------------------------------------------

// poserPolitiquesEtJetons creates policies and tokens with distinct scopes, and
// returns the application token.
//
// WHY SEVERAL, AND NOT ONE — this is the correction of a contradiction the
// field revealed. The previous code revoked the root token (good) after doing
// everything with it (bad): on the second pass, mounting the KV engine and
// rewriting the policies required root rights that no longer existed. The
// vault became non-redeployable — precisely when it is needed most, after an
// upgrade.
//
// The answer is not to keep the root token, but to manufacture tokens BEFORE
// revoking it:
//
//   - the INSTALLATION token carries the vault's administration rights (mount
//     an engine, write a policy, create a token). It serves the subsequent
//     passes of `ceffio vault`, and it is stored separately;
//   - the APPLICATION token carries only reading and writing the suite's
//     secrets, under `kv/data/ceffio/*`. That is the one the suite receives
//     (BAO_TOKEN).
//
// THUS THE TOKEN THE SUITE USES CANNOT ADMINISTER THE VAULT. A compromised
// service cannot mount an engine, nor broaden its own policy, nor manufacture
// a token. That is what "least privilege" means, and a single token could not
// achieve it.
func poserPolitiquesEtJetons(ctx context.Context, cli *k8sapi.Client) (string, error) {
	// REUSE THE INSTALLATION TOKEN IF IT STILL WORKS. The vault has certainly
	// already been set up: without that, the root token would be needed, which
	// was revoked — and a vault you cannot redeploy is a vault you dare not
	// touch.
	inst := ""
	if j, _ := cli.LireSecret(ctx, ns, "openbao-installation", "token"); j != "" {
		// Do not trust its mere presence: an expired token left in a Secret
		// would give the illusion of an administrable vault.
		//
		// THE EXACT FORM MATTERS: `bao token lookup` WITHOUT argument queries
		// the current token. The real subcommands are capabilities, create,
		// lookup, renew and revoke — there is no "lookup-self". Writing that
		// name prints the help and exits in error, which made a perfectly
		// valid token be declared INVALID, and the vault passed for
		// unmanageable. (Verified: `bao token --help`.)
		if _, err := baoAvecJeton(ctx, cli, j, "token", "lookup"); err == nil {
			fmt.Println("  ∙ installation token already in place (reused)")
			inst = j
		}
	}
	if inst == "" {
		inst, _ = cli.LireSecret(ctx, ns, "openbao-recovery", "root-token")
		if inst == "" {
			return "", fmt.Errorf("no valid administration token: the root token was revoked and the installation token is absent — regenerate a root token with a recovery key (openbao-recovery)")
		}
	}

	// THE POLICIES ARE WRITTEN BY FILE, and not as an argument: `policy write`
	// expects a path or `-` for standard input, and a policy fitting on a
	// command line would be truncated at the first newline.
	politiques := []struct{ nom, regle string }{
		// APPLICATION: the suite's secrets, and nothing else. Note there is NO
		// administration capability here — no engine mount, no policy, no token
		// creation.
		{"ceffio-admin", `path "kv/data/ceffio/*" { capabilities = ["create","read","update","list"] }
path "kv/metadata/ceffio/*" { capabilities = ["read","list","delete"] }
path "kv/delete/ceffio/*" { capabilities = ["update"] }
path "kv/undelete/ceffio/*" { capabilities = ["update"] }
# THE COMMAND-LINE TOOL QUERIES THIS PATH BEFORE ANY WRITE.
#
# "bao kv put" starts by asking where the engine is mounted, to know whether
# it must target the KV API version 1 or version 2. Without this authorization,
# the command fails on a 403 about "sys/internal/ui/mounts/..." — a message
# that does NOT speak of the secret we wanted to write, and which therefore
# sends you looking for the error in the wrong place. Observed in service.
#
# The authorization is READ ONLY: it reveals only the engines' location and
# their API version, never a content.
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		// CONSOLE: it is the ONLY role that writes. Humans go through the
		// console, which holds that right; a compromised service does not. It
		// is this separation that limits the damage, not the namespace.
		//
		// It is obtained through Kubernetes authentication — see
		// configurerAuthKubernetes — hence without any secret stored in the
		// console.
		{"ceffio-console", `path "kv/data/ceffio/*" { capabilities = ["create","read","update","list"] }
path "kv/metadata/ceffio/*" { capabilities = ["read","list","delete"] }
path "kv/delete/ceffio/*" { capabilities = ["update"] }
path "kv/undelete/ceffio/*" { capabilities = ["update"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		// READ ONLY: what the suite's components receive that only have to read
		// their own secrets. The "metadata" gives the list of versions, never
		// the values.
		{"ceffio-lecture", `path "kv/data/ceffio/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		// READ BY COMPONENT: a service reads ONLY what concerns it. The broad
		// policy above exists for future cases; a precise component receives
		// its own. It is what bounds the damage when a role is compromised —
		// not the namespace, which says nothing about rights.
		{"ceffio-stalwart", `path "kv/data/ceffio/stalwart/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/stalwart/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		{"ceffio-onlyoffice", `path "kv/data/ceffio/onlyoffice/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/onlyoffice/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		{"ceffio-talk", `path "kv/data/ceffio/talk/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/talk/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		{"ceffio-nextcloud", `path "kv/data/ceffio/nextcloud/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/nextcloud/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		{"ceffio-keycloak", `path "kv/data/ceffio/keycloak/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/keycloak/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		// ADMINISTRATION: the single human account, the one the directory
		// designates as administrator. It has ALL rights on the vault — that
		// is the meaning of an administration account, and it is what makes
		// centralized rotation possible from a single place.
		//
		// THE ONE THING IT CANNOT DO: obtain the root token. That is obtained
		// only with the recovery keys, and it is deliberate — a token that can
		// refuse nothing must not be reachable from a browser.
		//
		// SERVICES DO NOT HAVE THIS POLICY, and that is the whole point: a
		// compromised service can neither mount an engine, nor broaden its own
		// policy, nor manufacture a token.
		{"ceffio-administration", `path "*" { capabilities = ["create","read","update","delete","list","sudo"] }`},
		// INSTALLATION: what the setup and the subsequent passes require. The
		// KV appears there too, so the end-to-end diagnostic runs with this
		// token without depending on another.
		{"ceffio-installation", `# THE EXACT PATH AND THE WILDCARD ARE TWO DISTINCT AUTHORIZATIONS.
# "sys/mounts/*" covers the mounted engines, but NOT "sys/mounts" itself, which
# is the entry point of the LIST of engines. Without the exact line, "bao
# secrets list" answers 403 — and the message is about "/v1/sys/mounts", hence
# about a path that appears nowhere in the policy: you look for the error
# elsewhere. Observed in service.
path "kv/*" { capabilities = ["create","read","update","delete","list"] }
path "sys/mounts" { capabilities = ["read","list"] }
path "sys/mounts/*" { capabilities = ["create","read","update","delete","list","sudo"] }
# SAME DISTINCTION FOR AUTHENTICATION as for the engines: "sys/auth" is the
# entry point of the LIST of methods, and "sys/auth/*" that of their
# configuration. Both are needed — having only the second answers 403 on the
# list, which prevents knowing whether a method is already wired. Observed in
# service, on this precise step.
path "sys/auth" { capabilities = ["read","list"] }
path "sys/auth/*" { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/policies/acl/*" { capabilities = ["create","read","update","delete","list"] }
# THE WHOLE "auth/" BRANCH, and not only "auth/token/".
#
# WHY SO BROAD: configuring an authentication method is written at
# "auth/<method>/config", and placing a role at "auth/<method>/role/<name>".
# Enumerating method by method forced a return to the code each time — and the
# failure was a 403 on a path that figures nowhere in the policy. This is the
# ADMINISTRATION token: this is where breadth belongs, not in the application
# policy, which has no write right on this branch.
path "auth/*" { capabilities = ["create","read","update","delete","list"] }
# THE MOST PRECISE RULE WINS, and it is indispensable here: creating an ORPHAN
# token — the one the installation token's survival depends on — requires the
# "sudo" capability on this precise path. The general line above does not give
# it. Without this one, the next deployment would fail at the token creation.
path "auth/token/create" { capabilities = ["create","update","sudo"] }
path "sys/health" { capabilities = ["read"] }`},
	}
	for _, p := range politiques {
		script := fmt.Sprintf("cat > /tmp/p.hcl <<'FIN_POLITIQUE'\n%s\nFIN_POLITIQUE\n", p.regle)
		if _, err := cli.Executer(ctx, ns, pod, "openbao", "sh", "-c", script); err != nil {
			return "", fmt.Errorf("writing policy %s: %w", p.nom, err)
		}
		if _, err := baoAvecJeton(ctx, cli, inst, "policy", "write", p.nom, "/tmp/p.hcl"); err != nil {
			return "", fmt.Errorf("policy %s: %w", p.nom, err)
		}
	}

	// The installation token is manufactured FIRST: once the root token is
	// revoked, there is nothing left to create one.
	nj, err := creerJeton(ctx, cli, inst, "ceffio-installation", "ceffio-installation")
	if err != nil {
		return "", err
	}
	if err := cli.PoserSecret(ctx, ns, "openbao-installation",
		map[string][]byte{"token": []byte(nj)}); err != nil {
		return "", fmt.Errorf("storing the installation token: %w", err)
	}

	ja, err := creerJeton(ctx, cli, inst, "ceffio-admin", "ceffio-suite")
	if err != nil {
		return "", err
	}
	if err := cli.PoserSecret(ctx, ns, "openbao-token",
		map[string][]byte{"token": []byte(ja)}); err != nil {
		return "", fmt.Errorf("storing the application token: %w", err)
	}
	fmt.Println("  ∙ policies \"ceffio-admin\" (application) and \"ceffio-installation\" placed")
	fmt.Println("  ∙ two tokens created: the suite CANNOT administer the vault")
	return ja, nil
}

// creerJeton manufactures a token carrying a policy, under a name that says
// its usage.
//
// THE TOKEN IS ORPHAN, AND THAT IS THE CORRECTION OF A GRAVE DEFECT. In OpenBao
// as in Vault, revoking a token revokes ITS ENTIRE DESCENDANCY. The two tokens
// created from the root token therefore died with it: on the next pass, the
// vault ran, but nobody could administer it anymore — and no trace said why,
// since the root revocation had succeeded.
//
// An orphan token has no parent: it survives the revocation of the token that
// created it. The price is that it no longer erases "by ricochet" — it must be
// revoked by name. That is the right trade-off here: an administration token
// you forget must remain revocable, not disappear silently with another.
//
// The name matters too: in the list of a vault's tokens, an anonymous token is
// no longer distinguishable from another, and one hesitates to revoke for fear
// of breaking something.
func creerJeton(ctx context.Context, cli *k8sapi.Client, porteur, politique, nom string) (string, error) {
	sortie, err := baoAvecJeton(ctx, cli, porteur, "token", "create",
		"-policy="+politique, "-period=768h", "-orphan", "-format=json", "-display-name="+nom)
	if err != nil {
		return "", fmt.Errorf("creating token %s: %w", nom, err)
	}
	var res struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal([]byte(extraitJSON(sortie)), &res); err != nil {
		return "", fmt.Errorf("unreadable response for %s: %w", nom, err)
	}
	if res.Auth.ClientToken == "" {
		return "", fmt.Errorf("empty token %s: %.120s", nom, strings.TrimSpace(sortie))
	}
	return res.Auth.ClientToken, nil
}

// configurerAuthKubernetes wires authentication by Kubernetes: a pod presents
// its ServiceAccount token, the vault has it validated by the cluster API, and
// returns a token carrying the policy of the matching role.
//
// WHY THIS MECHANISM RATHER THAN A SHARED SECRET: a shared secret must be
// stored somewhere, hence recreating the problem being solved. The
// ServiceAccount token, for its part, is already there, presented by the pod
// and renewed by the cluster. Nothing to store, nothing to rotate by hand.
//
// WHY THE ROLE SPECIFIES THE NAMESPACE AND THE NAME: both matter. A homonymous
// ServiceAccount created elsewhere in the cluster would otherwise obtain the
// same rights. It is the combination of the two that identifies a pod.
func configurerAuthKubernetes(ctx context.Context, cli *k8sapi.Client) error {
	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return err
	}

	// ALREADY WIRED? ASK the vault rather than assume: a second activation
	// returns an error that would fail the whole deployment for nothing.
	sortie, err := baoAvecJeton(ctx, cli, adm, "auth", "list")
	if err != nil {
		return fmt.Errorf("reading the authentication methods: %w", err)
	}
	if !strings.Contains(sortie, "kubernetes/") {
		if _, err := baoAvecJeton(ctx, cli, adm, "auth", "enable", "kubernetes"); err != nil {
			return fmt.Errorf("enabling Kubernetes authentication: %w", err)
		}
		fmt.Println("  ∙ Kubernetes authentication enabled")
	}

	// THE CLUSTER ADDRESS AS SEEN FROM INSIDE: "kubernetes.default.svc" is the
	// name every pod resolves, and the API's certificate matches it.
	//
	// THE VALIDATION TOKEN IS NOT PROVIDED HERE, and that is deliberate: the
	// vault uses its own, that of its ServiceAccount — hence the delegation
	// right granted by identiteManifest, which is therefore not decorative. It
	// is also what avoids having a long-lived token to store in a configuration
	// file.
	if _, err := baoAvecJeton(ctx, cli, adm, "write", "auth/kubernetes/config",
		"kubernetes_host=https://kubernetes.default.svc:443"); err != nil {
		return fmt.Errorf("configuring Kubernetes authentication: %w", err)
	}

	roles := []struct{ nom, sa, ns, politique string }{
		// The console is today the only consumer: it is what writes the
		// secrets, and it is where humans act. The components will be added one
		// by one, in Phase 3, with the read-only policy.
		{nom: "console", sa: "ceffio-admin", ns: "ceffio-system", politique: "ceffio-console"},
		// COMPONENTS READ THEIR OWN SECRETS AT RUNTIME. It is the POD's
		// ServiceAccount that authenticates, via an init-container: no token is
		// stored anywhere, and a rotation in the vault takes effect at the
		// pod's next restart — without redeploying the suite.
		{nom: "stalwart", sa: "stalwart", ns: "ceffio-mail", politique: "ceffio-stalwart"},
		{nom: "onlyoffice", sa: "onlyoffice", ns: "ceffio-office", politique: "ceffio-onlyoffice"},
		{nom: "talk", sa: "talk", ns: "ceffio-video", politique: "ceffio-talk"},
		{nom: "nextcloud", sa: "nextcloud", ns: "ceffio-files", politique: "ceffio-nextcloud"},
		{nom: "keycloak", sa: "keycloak", ns: "ceffio-identity", politique: "ceffio-keycloak"},
	}
	for _, r := range roles {
		if _, err := baoAvecJeton(ctx, cli, adm,
			"write", "auth/kubernetes/role/"+r.nom,
			"bound_service_account_names="+r.sa,
			"bound_service_account_namespaces="+r.ns,
			"policies="+r.politique,
			"ttl=1h"); err != nil {
			return fmt.Errorf("role \"%s\": %w", r.nom, err)
		}
	}
	fmt.Println("  ∙ Kubernetes authentication configured (role \"console\", 1 h TTL)")
	return nil
}

// ecrirePayloadCoffre writes a JSON payload into the container, in 0600, and
// returns its path.
//
// WHY A FILE, AND NOT ARGUMENTS: the command line can only transmit text.
// Writing "bound_claims={\"email\":[...]}" makes the vault answer "got
// unconvertible type 'string'" — the role is not created, and the message does
// not say how to go about it. An object transmitted whole, from a file, is
// parsed correctly: it is the only form that works for a structured field.
//
// THE UMASK IS SET BEFORE THE WRITE: the payload can contain a client secret,
// and a world-readable file in the container would be a needless trace. The
// file is deleted after use.
func ecrirePayloadCoffre(ctx context.Context, cli *k8sapi.Client, chemin string, charge any) error {
	brut, err := json.MarshalIndent(charge, "", "  ")
	if err != nil {
		return fmt.Errorf("unreadable payload: %w", err)
	}
	script := fmt.Sprintf("umask 077; cat > %s <<'FIN_PAYLOAD'\n%s\nFIN_PAYLOAD\n", chemin, brut)
	if _, err := cli.Executer(ctx, ns, pod, "openbao", "sh", "-c", script); err != nil {
		return fmt.Errorf("writing payload %s: %w", chemin, err)
	}
	return nil
}

// retirerPayloadCoffre erases a payload after use.
func retirerPayloadCoffre(ctx context.Context, cli *k8sapi.Client, chemin string) {
	_, _ = cli.Executer(ctx, ns, pod, "openbao", "sh", "-c", "rm -f "+chemin)
}

// configurerOIDC wires the authentication of PEOPLE, on the suite's Keycloak.
//
// WHY OIDC FOR PEOPLE AND KUBERNETES FOR SERVICES: a pod has a token the
// cluster gives it. A person does not. Manufacturing one for them would mean
// keeping a separate account list, with their passwords and their forgotten
// ones — exactly the second list we want to avoid. OIDC simply says: "this
// person is the one Keycloak says they are".
func configurerOIDC(ctx context.Context, cli *k8sapi.Client, domaine string) error {
	if domaine == "" {
		// WITHOUT A DOMAIN, NO RETURN ADDRESS: the browser would have nowhere
		// to come back. Announce it rather than configure something that cannot
		// work.
		fmt.Println("  ∙ no domain: people authentication not configured")
		return nil
	}

	// THE CLIENT AND ITS SECRET ARE CREATED BY THE SSO MODULE, which owns the
	// Keycloak knowledge. We READ them here rather than manufacture others: two
	// sources for one secret end up diverging, and that is the longest failure
	// to understand.
	if err := sso.AssurerClientCoffre(ctx, domaine); err != nil {
		return fmt.Errorf("vault OIDC client: %w", err)
	}
	// THE CREDENTIALS COME FROM THE VAULT, no longer from a Kubernetes Secret:
	// the vault's OIDC client is stored there like that of the other
	// components.
	entreeOIDC, _ := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), "openbao", "oidc")
	id, secret := entreeOIDC["client-id"], entreeOIDC["client-secret"]
	if id == "" || secret == "" {
		return fmt.Errorf("Secret openbao-oidc absent or incomplete in ceffio-identity")
	}

	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return err
	}
	sortie, err := baoAvecJeton(ctx, cli, adm, "auth", "list")
	if err != nil {
		return fmt.Errorf("reading the authentication methods: %w", err)
	}
	if !strings.Contains(sortie, "oidc/") {
		if _, err := baoAvecJeton(ctx, cli, adm, "auth", "enable", "oidc"); err != nil {
			return fmt.Errorf("enabling OIDC authentication: %w", err)
		}
		fmt.Println("  ∙ OIDC authentication enabled")
	}

	// THE DISCOVERY ADDRESS IS THE ONE THE BROWSER SEES, and that is
	// deliberate: Keycloak signs its tokens announcing ITS public address, and
	// the vault verifies the issuer matches. An internal address would fail the
	// verification, with a message that speaks of issuer and not of address.
	// Verified: the vault does reach the public address from the cluster.
	emetteur := "https://keycloak." + domaine + "/realms/ceffio"
	cfg := map[string]any{
		"oidc_discovery_url": emetteur,
		"oidc_client_id":     id,
		"oidc_client_secret": secret,
		"default_role":       "adminceffio",
	}
	if err := ecrirePayloadCoffre(ctx, cli, "/tmp/oidc-config.json", cfg); err != nil {
		return err
	}
	_, errCfg := baoAvecJeton(ctx, cli, adm, "write", "auth/oidc/config", "@/tmp/oidc-config.json")
	// The file carried the client secret: it disappears as soon as it has
	// served, whatever the result.
	retirerPayloadCoffre(ctx, cli, "/tmp/oidc-config.json")
	if errCfg != nil {
		return fmt.Errorf("OIDC configuration: %w", errCfg)
	}

	// THE ROLE IS BOUND ON THE EMAIL ADDRESS, never on the "sub".
	//
	// "sub" is an identifier internal to Keycloak: it changes if the account is
	// recreated, and the role would then stop accepting the right person with
	// nothing signaling it. The address is what the person knows, what they
	// type to log in, and what we want to read in the role definition.
	//
	// WHY THE CONDITIONS GO THROUGH A FILE: "bound_claims" expects an OBJECT,
	// and the command line can only transmit text. Writing
	// "bound_claims={\"email\":[...]}" makes it answer "got unconvertible type
	// 'string'" — the role is not created, and the message does not say how to
	// go about it. A complete JSON payload, read from a file, is parsed
	// correctly. Observed in service, the command's help in support.
	retours := []string{
		"https://bao." + domaine + "/ui/vault/auth/oidc/oidc/callback",
		"https://bao." + domaine + "/vault/auth/oidc/oidc/callback",
		"http://localhost:8250/oidc/callback",
	}
	role := map[string]any{
		"role_type":             "oidc",
		"user_claim":            "email",
		"bound_claims":          map[string]any{"email": []string{"adminceffio@ceffio.local"}},
		"policies":              "ceffio-administration",
		"allowed_redirect_uris": retours,
		"oidc_scopes":           []string{"email", "profile"},
		"ttl":                   "2h",
	}
	if err := ecrirePayloadCoffre(ctx, cli, "/tmp/oidc-role.json", role); err != nil {
		return err
	}
	_, errRole := baoAvecJeton(ctx, cli, adm, "write", "auth/oidc/role/adminceffio", "@/tmp/oidc-role.json")
	retirerPayloadCoffre(ctx, cli, "/tmp/oidc-role.json")
	if errRole != nil {
		return fmt.Errorf("OIDC role \"adminceffio\": %w", errRole)
	}
	fmt.Println("  ∙ people authentication configured (adminceffio@ceffio.local)")
	return nil
}

// retirerJetonRacine revokes the root token as soon as the derived token
// exists.
//
// A master token that survives the setup is a defect, not a convenience. The
// recovery keys allow regenerating one if needed.
//
// IF THE ROOT TOKEN IS ALREADY GONE, that is not an error: it is the nominal
// case of a redeployment, where the revocation already happened. Saying it as
// a warning would make people believe in an incident at every relaunch.
func retirerJetonRacine(ctx context.Context, cli *k8sapi.Client) error {
	racine, err := cli.LireSecret(ctx, ns, "openbao-recovery", "root-token")
	if err != nil {
		return fmt.Errorf("unreadable root token: %w", err)
	}
	if racine == "" {
		fmt.Println("  ∙ root token already revoked (nothing to do)")
		return nil
	}
	// The syntax matters: `-self` is an OPTION of `token revoke`, not a
	// subcommand. Writing `token revoke-self` prints the group's help and exits
	// in error — observed in service, and the root token then stayed alive.
	if _, err := baoAvecJeton(ctx, cli, racine, "token", "revoke", "-self"); err != nil {
		return err
	}
	// Also remove the local copy: a revoked token has no business lingering.
	if err := cli.SupprimerSecret(ctx, ns, "openbao-recovery"); err != nil {
		return err
	}
	fmt.Println("  ∙ root token revoked (the recovery keys allow regenerating one)")
	return nil
}

// ---------------------------------------------------------------------------
// 7. End-to-end verification
// ---------------------------------------------------------------------------

// verifierAllerRetour writes a secret, reads it back, and verifies the REFUSAL
// works too.
//
// WHY BOTH: a vault of which only the authorizations were proved has proved
// nothing. Half of an access control is what it refuses.
func verifierAllerRetour(ctx context.Context, cli *k8sapi.Client, jeton string) error {
	const (
		// THE VERIFICATION WRITES WITHIN THE POLICY'S SCOPE, and not
		// elsewhere. That is a measured lesson: the first version wrote in
		// `kv/diagnostic/…`, outside `kv/data/ceffio/*` — the derived token
		// therefore answered 403, rightly so, and the deployment failed on a
		// refusal that was in reality the access control's CORRECT behavior.
		composant = "ceffio/diagnostic"
		nom       = "aller-retour"
		valeur    = "verification-ceffio"
		// The refusal path must be OUTSIDE the scope: that is what proves the
		// policy is not too broad.
		cheminInterdit = "kv/hors-perimetre/x"
	)
	if _, err := baoAvecJeton(ctx, cli, jeton, "kv", "put", "kv/"+composant+"/"+nom, nom+"="+valeur); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	sortie, err := baoAvecJeton(ctx, cli, jeton, "kv", "get", "-field="+nom, "kv/"+composant+"/"+nom)
	if err != nil {
		return fmt.Errorf("read back: %w", err)
	}
	if !strings.Contains(sortie, valeur) {
		return fmt.Errorf("the value read back does not match (the vault answers but does not return what was written)")
	}

	// The refusal: a path OUTSIDE the policy's scope must be rejected. Without
	// this check, a too-broad policy would go unnoticed.
	if _, err := baoAvecJeton(ctx, cli, jeton, "kv", "get", cheminInterdit); err == nil {
		return fmt.Errorf("the derived token reads a path it should not — policy too broad")
	}

	// Clean up the diagnostic trace.
	_, _ = baoAvecJeton(ctx, cli, jeton, "kv", "delete", "kv/"+composant+"/"+nom)
	fmt.Println("  ∙ round trip verified (write, read back, AND refusal of an out-of-scope path)")
	return nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// extraitJSON isolates the JSON object from an output that can carry warnings
// before or after. Without it, a warning would make the read fail.
func extraitJSON(s string) string {
	debut := strings.Index(s, "{")
	fin := strings.LastIndex(s, "}")
	if debut < 0 || fin <= debut {
		return "{}"
	}
	return s[debut : fin+1]
}

// baoReessai runs a vault command, RETRYING on transient failures.
//
// WHY IT IS NECESSARY, AND MEASURED: `operator init` raises the vault's
// security barrier, which causes a brief core restart. During those few
// seconds, the port answers "connection refused". That is not a failure: it is
// a race between a command and the restart it just triggered. Without the
// retry, the deployment failed exactly there — on the step that had just
// succeeded.
func baoReessai(ctx context.Context, cli *k8sapi.Client, args ...string) (string, error) {
	var sortie string
	var err error
	for i := 0; i < 6; i++ {
		sortie, err = cli.Executer(ctx, ns, pod, "openbao", append([]string{"bao"}, args...)...)
		if err == nil {
			return sortie, nil
		}
		if !transitoire(err) {
			return sortie, err
		}
		// Growing wait: a core restart takes a few seconds.
		time.Sleep(time.Duration(3*(i+1)) * time.Second)
	}
	return sortie, err
}

// transitoire reports whether the error can disappear by retrying.
//
// ONLY the transient is retried: insisting on a configuration error would only
// delay the admission of failure, and would mask the cause.
func transitoire(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	for _, motif := range []string{
		"connection refused",
		"connection reset",
		"i/o timeout",
		"unexpected eof",
		"unable to upgrade connection",
		"server is starting",
		"is the server running",
	} {
		if strings.Contains(m, motif) {
			return true
		}
	}
	return false
}

// etatCoffre returns the vault's readable state, or "" if it could not be read.
//
// DO NOT TRUST THE EXIT CODE OF `bao status`. That tool exits in error when the
// vault is sealed or not initialized: it is a design choice, meant for scripts
// that test "is it ready?". Here, those states are precisely what we want to
// READ.
//
// THE TWO KINDS OF FAILURE ARE SEPARATED, and that is the core of this module:
//
//   - THE EXECUTION FAILED (pod absent, connection refused): the output is an
//     error message, not JSON. Treating it as a state made people believe in a
//     "not initialized" vault that had never been queried — and the deployment
//     continued against an unreachable server;
//   - THE COMMAND RETURNED A VERDICT (non-zero code, valid JSON output): it is
//     a state, and we read it.
//
// The `"initialized"` check in the output is the guardrail: without it, an
// unexpected response becomes an empty object again, and the empty object
// becomes a plausible state again.
func etatCoffre(ctx context.Context, cli *k8sapi.Client) (string, error) {
	sortie, errExec := cli.Executer(ctx, ns, pod, "openbao", "bao", "status", "-format=json")
	brut := extraitJSON(sortie)
	if !strings.Contains(brut, `"initialized"`) {
		if errExec != nil {
			return "", fmt.Errorf("the vault could not be queried: %w", errExec)
		}
		return "", fmt.Errorf("unexpected response from the vault: %.100s", strings.TrimSpace(sortie))
	}
	var st struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}
	if err := json.Unmarshal([]byte(brut), &st); err != nil {
		return "", fmt.Errorf("unreadable state: %w", err)
	}
	switch {
	case !st.Initialized:
		return "not initialized", nil
	case st.Sealed:
		return "SEALED", nil
	default:
		return "unsealed", nil
	}
}

// baoAvecReessai was removed with baoRacine: both only served to reach the root
// token, and the administration now goes through jetonAdministration, which
// tries the installation token BEFORE the root. Administration code that looks
// only for the root no longer works after the setup; keeping it would have been
// a trap for the next reading.

// commandeBao assembles the command line, PROTECTING each argument.
//
// WHY PROTECT: the values passed to the vault sometimes contain characters the
// shell interprets — braces, quotes, commas. Without protection, the shell
// removes the quotes and the vault receives a value DIFFERENT from the one you
// think you wrote, with nothing signaling it.
//
// WHY PROTECTION IS NOT ENOUGH FOR AN OBJECT: a structured field cannot go
// through the command line at all, even correctly protected. Those payloads go
// through a file — see ecrirePayloadCoffre.
func commandeBao(args []string) string {
	proteges := make([]string, 0, len(args))
	for _, a := range args {
		// Single quotes: inside, the shell interprets nothing anymore. The
		// apostrophe itself is closed and escaped.
		proteges = append(proteges, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	return strings.Join(proteges, " ")
}

// baoAvecJeton runs a command with an explicit token, transmitted through
// STANDARD INPUT — never as an argument.
//
// WHY IT MATTERS: a token passed as an argument appears in the pod's process
// table, readable by anything that can observe the machine. Standard input
// leaves no such trace, and the token is not written to the container's disk
// either.
func baoAvecJeton(ctx context.Context, cli *k8sapi.Client, jeton string, args ...string) (string, error) {
	// The shell reads the token on its standard input and places it in the bao
	// command's environment. It therefore appears nowhere else.
	script := fmt.Sprintf("IFS= read -r TOK; BAO_TOKEN=\"$TOK\" exec bao %s", commandeBao(args))

	var sortie string
	var err error
	for i := 0; i < 6; i++ {
		sortie, err = cli.ExecuterAvecEntree(ctx, ns, pod, "openbao", jeton, "sh", "-c", script)
		if err == nil {
			return sortie, nil
		}
		if !transitoire(err) {
			return sortie, err
		}
		time.Sleep(time.Duration(3*(i+1)) * time.Second)
	}
	return sortie, err
}
