// Package media orchestre le déploiement de la couche visioconférence (Phase 10) :
// Jitsi Meet (web + Prosody + Jicofo + Jitsi Videobridge) sur le domaine meet.<domain>.
//
// Les secrets (mots de passe d'auth XMPP) sont générés au runtime, jamais en clair
// dans Git (§111). Une ConfigMap/PVC partagé « jitsi-config » porte la config +
// certificats XMPP auto-signés générés par Prosody (lus par Jicofo et la JVB).
package media

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Versions pinnées : build de release Jitsi cohérent sur les 4 images (ghcr.io/jitsi).
const (
	webImage     = "ghcr.io/jitsi/web:stable-11146-2"
	prosodyImage = "ghcr.io/jitsi/prosody:stable-11146-2"
	jicofoImage  = "ghcr.io/jitsi/jicofo:stable-11146-2"
	jvbImage     = "ghcr.io/jitsi/jvb:stable-11146-2"
	ns           = "ceffio-video"
)

// Deploy installe la couche visioconférence (Phase 10), de façon idempotente :
//  1. secrets XMPP (jicofo/jvb/component) + PVC partagé jitsi-config
//  2. Deployments prosody, jicofo, jvb, web + Services (web:80, prosody:5222/5280,
//     jvb: colibri 4443 + UDP 10000 en LoadBalancer pour les médias)
//  3. attente du frontend web
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDéploiement de la couche visioconférence (Phase 10) — Jitsi Meet...")

	meet := "meet." + domain
	if err := ensureSecrets(ctx); err != nil {
		return err
	}
	nodeIP, err := nodeInternalIP(ctx)
	if err != nil {
		return err
	}
	if err := applyManifest(ctx, meet, nodeIP); err != nil {
		return err
	}
	if err := waitWebReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Couche visioconférence déployée (Jitsi Meet sur https://" + meet + ")")
	return nil
}

func ensureSecrets(ctx context.Context) error {
	if secretExists(ctx, "jitsi-secrets") {
		return nil
	}
	fmt.Println("∙ secrets XMPP Jitsi générés (jicofo, jvb, component)")
	jicofo, err := genSecret(18)
	if err != nil {
		return err
	}
	jvb, err := genSecret(18)
	if err != nil {
		return err
	}
	comp, err := genSecret(18)
	if err != nil {
		return err
	}
	return createSecret(ctx, "jitsi-secrets", map[string]string{
		"jicofo-auth":      jicofo,
		"jvb-auth":         jvb,
		"component-secret": comp,
	})
}

func applyManifest(ctx context.Context, meet, nodeIP string) error {
	fmt.Println("∙ Jitsi web/prosody/jicofo/jvb (stable-11146-2) + Service UDP 10000")
	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: jitsi-config
  namespace: %[1]s
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 2Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prosody
  namespace: %[1]s
  labels: {app: prosody}
spec:
  replicas: 1
  selector: {matchLabels: {app: prosody}}
  template:
    metadata: {labels: {app: prosody}}
    spec:
      containers:
      - name: prosody
        image: %[2]s
        env:
        - {name: XMPP_DOMAIN, value: %[11]s}
        - {name: XMPP_AUTH_DOMAIN, value: "auth.%[11]s"}
        - {name: XMPP_INTERNAL_MUC_DOMAIN, value: "internal-muc.%[11]s"}
        - {name: XMPP_MUC_DOMAIN, value: "conference.%[11]s"}
        - {name: JICOFO_COMPONENT_SECRET, valueFrom: {secretKeyRef: {name: jitsi-secrets, key: component-secret}}}
        - {name: JICOFO_AUTH_USER, value: focus}
        - {name: JICOFO_AUTH_PASSWORD, valueFrom: {secretKeyRef: {name: jitsi-secrets, key: jicofo-auth}}}
        - {name: JVB_AUTH_USER, value: videobridge}
        - {name: JVB_AUTH_PASSWORD, valueFrom: {secretKeyRef: {name: jitsi-secrets, key: jvb-auth}}}
        - {name: ENABLE_AUTH, value: "1"}
        - {name: AUTH_TYPE, value: internal}
        - {name: TZ, value: Europe/Paris}
        ports:
        - {name: c2s, containerPort: 5222}
        - {name: http-bind, containerPort: 5280}
        - {name: s2s, containerPort: 5269}
        - {name: component, containerPort: 5347}
        volumeMounts:
        - {name: config, mountPath: /config}
        resources: {limits: {memory: 512Mi}}
      volumes:
      - {name: config, persistentVolumeClaim: {claimName: jitsi-config}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jicofo
  namespace: %[1]s
  labels: {app: jicofo}
spec:
  replicas: 1
  selector: {matchLabels: {app: jicofo}}
  template:
    metadata: {labels: {app: jicofo}}
    spec:
      containers:
      - name: jicofo
        image: %[3]s
        env:
        - {name: XMPP_SERVER, value: prosody}
        - {name: XMPP_DOMAIN, value: %[11]s}
        - {name: XMPP_AUTH_DOMAIN, value: "auth.%[11]s"}
        - {name: XMPP_INTERNAL_MUC_DOMAIN, value: "internal-muc.%[11]s"}
        - {name: XMPP_MUC_DOMAIN, value: "conference.%[11]s"}
        - {name: JICOFO_AUTH_USER, value: focus}
        - {name: JICOFO_AUTH_PASSWORD, valueFrom: {secretKeyRef: {name: jitsi-secrets, key: jicofo-auth}}}
        - {name: TZ, value: Europe/Paris}
        volumeMounts:
        - {name: config, mountPath: /config}
        resources: {limits: {memory: 512Mi}}
      volumes:
      - {name: config, persistentVolumeClaim: {claimName: jitsi-config}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jvb
  namespace: %[1]s
  labels: {app: jvb}
spec:
  replicas: 1
  selector: {matchLabels: {app: jvb}}
  template:
    metadata: {labels: {app: jvb}}
    spec:
      containers:
      - name: jvb
        image: %[4]s
        env:
        - {name: XMPP_SERVER, value: prosody}
        - {name: XMPP_DOMAIN, value: %[11]s}
        - {name: XMPP_AUTH_DOMAIN, value: "auth.%[11]s"}
        - {name: XMPP_INTERNAL_MUC_DOMAIN, value: "internal-muc.%[11]s"}
        - {name: JVB_AUTH_USER, value: videobridge}
        - {name: JVB_AUTH_PASSWORD, valueFrom: {secretKeyRef: {name: jitsi-secrets, key: jvb-auth}}}
        - {name: JVB_ADVERTISE_IPS, value: %[10]s}
        - {name: PUBLIC_URL, value: "https://%[11]s"}
        - {name: TZ, value: Europe/Paris}
        ports:
        - {name: media, containerPort: 10000, protocol: UDP}
        - {name: colibri, containerPort: 4443}
        volumeMounts:
        - {name: config, mountPath: /config}
        resources: {limits: {memory: 1Gi}}
      volumes:
      - {name: config, persistentVolumeClaim: {claimName: jitsi-config}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: %[1]s
  labels: {app: web}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - name: web
        image: %[5]s
        env:
        - {name: PUBLIC_URL, value: "https://%[11]s"}
        - {name: XMPP_SERVER, value: prosody}
        # Upstream XMPP pour /http-bind et /xmpp-websocket : par défaut le web image
        # proxy vers http://xmpp.meet.jitsi:5280 (non résolu). On pointe prosody en FQDN :
        # le résolveur nginx (kube-dns) ne résout PAS le nom nu prosody, seulement le FQDN.
        - {name: XMPP_BOSH_URL_BASE, value: "http://prosody.ceffio-video.svc.cluster.local:5280"}
        - {name: XMPP_DOMAIN, value: %[11]s}
        - {name: XMPP_AUTH_DOMAIN, value: "auth.%[11]s"}
        - {name: XMPP_MUC_DOMAIN, value: "conference.%[11]s"}
        - {name: XMPP_INTERNAL_MUC_DOMAIN, value: "internal-muc.%[11]s"}
        - {name: JICOFO_AUTH_USER, value: focus}
        - {name: JICOFO_AUTH_PASSWORD, valueFrom: {secretKeyRef: {name: jitsi-secrets, key: jicofo-auth}}}
        - {name: JVB_AUTH_USER, value: videobridge}
        - {name: JVB_AUTH_PASSWORD, valueFrom: {secretKeyRef: {name: jitsi-secrets, key: jvb-auth}}}
        - {name: ENABLE_AUTH, value: "1"}
        - {name: AUTH_TYPE, value: internal}
        - {name: TZ, value: Europe/Paris}
        ports:
        - {name: http, containerPort: 8000}
        volumeMounts:
        - {name: config, mountPath: /config}
        resources: {limits: {memory: 512Mi}}
      volumes:
      - {name: config, persistentVolumeClaim: {claimName: jitsi-config}}
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: %[1]s
spec:
  selector: {app: web}
  ports:
  - {name: http, port: 8000, targetPort: 8000}
---
apiVersion: v1
kind: Service
metadata:
  name: prosody
  namespace: %[1]s
spec:
  selector: {app: prosody}
  ports:
  - {name: c2s, port: 5222, targetPort: 5222}
  - {name: http-bind, port: 5280, targetPort: 5280}
---
apiVersion: v1
kind: Service
metadata:
  name: jvb
  namespace: %[1]s
spec:
  selector: {app: jvb}
  ports:
  - {name: colibri, port: 4443, targetPort: 4443}
  - {name: media, port: 10000, targetPort: 10000, protocol: UDP}
  type: LoadBalancer
`, ns, prosodyImage, jicofoImage, jvbImage, webImage, meet, "", "", "", nodeIP, meet)
	return apply(ctx, manifest)
}

// waitWebReady attend que le frontend Jitsi réponde (200 sur /).
func waitWebReady(ctx context.Context) error {
	fmt.Println("∙ attente du frontend Jitsi (web) Ready...")
	err := exec.CommandContext(ctx, "kubectl", "rollout", "status", "deploy/web", "-n", ns, "--timeout=240s").Run()
	if err != nil {
		return err
	}
	// Vérification fonctionnelle : le frontend sert le HTML de Jitsi Meet.
	for i := 0; i < 30; i++ {
		o, _ := exec.CommandContext(ctx, "kubectl", "exec", "deploy/web", "-n", ns, "--",
			"sh", "-c", "curl -fs -o /dev/null -w '%{http_code}' http://localhost:8000/").Output()
		if strings.TrimSpace(string(o)) == "200" {
			fmt.Println("  ✓ frontend Jitsi répond (HTTP 200)")
			return nil
		}
		exec.CommandContext(ctx, "kubectl", "wait", "--for=condition=ready", "pod", "-n", ns, "-l", "app=web", "--timeout=5s").Run()
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("frontend Jitsi web injoignable après retries")
}

func nodeInternalIP(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "node", "-o",
		`jsonpath={.items[0].status.addresses[?(@.type=="InternalIP")].address}`).Output()
	if err != nil {
		return "", err
	}
	if ip := strings.TrimSpace(string(out)); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("IP interne du nœud introuvable")
}

// ---------------- helpers (répliqués des autres couches) ----------------

func apply(ctx context.Context, manifest string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func secretExists(ctx context.Context, name string) bool {
	err := exec.CommandContext(ctx, "kubectl", "get", "secret", name, "-n", ns).Run()
	return err == nil
}

func createSecret(ctx context.Context, name string, data map[string]string) error {
	args := []string{"kubectl", "create", "secret", "generic", name, "-n", ns, "--dry-run=client", "-o", "yaml"}
	for k, v := range data {
		args = append(args, "--from-literal="+k+"="+v)
	}
	args = append(args, "|", "kubectl", "apply", "-f", "-")
	cmd := exec.CommandContext(ctx, "sh", "-c", strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
