package console

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	deployNS   = "ceffio-system"
	deployName = "ceffio-admin"
	imageName  = "localhost/ceffio-console"
	imageTag   = "0.1.0"
	imageRef   = imageName + ":" + imageTag
)

// Deploy installe la console d'administration DANS le cluster (Phase 11) :
//   - image OCI locale (binaire + page web embarquée) importée dans containerd
//   - Deployment ceffio-admin + ServiceAccount + Role (lecture pods/ingress/certs)
//   - Secret ceffio-console-key (clé admin persistée) + env KC_ADMIN
//   - Service ClusterIP + Ingress admin.<domain> + certificat
//
// Remplace l'ancien modèle (systemd + Endpoints→nœud).
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDéploiement de la console d'administration (Phase 11)...")

	if err := buildAndImportImage(ctx); err != nil {
		return err
	}
	if err := ensureConsoleKey(ctx); err != nil {
		return err
	}
	if err := applyConsoleManifest(ctx, domain); err != nil {
		return err
	}
	if err := waitConsoleReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Console d'administration déployée (https://admin." + domain + ")")
	return nil
}

// buildAndImportImage compile le binaire linux, construit l'image OCI et l'importe
// dans containerd (crictl / ctr). Idempotent : saute si l'image est déjà présente.
func buildAndImportImage(ctx context.Context) error {
	if imagePresent(ctx) {
		fmt.Println("∙ image console déjà présente (" + imageRef + ")")
		return nil
	}
	fmt.Println("∙ build + import image console " + imageRef)

	// 1. Cross-compile linux/amd64 du binaire (console embarque sa page web).
	tmp, err := os.MkdirTemp("", "ceffio-console-build-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	bin := tmp + "/ceffio"
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "github.com/ceffio-suite/ceffio/cmd/ceffio")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build console: %w", err)
	}

	// 2. Dockerfile minimal (binaire + CA certs) → image.
	dockerfile := `FROM scratch
COPY ceffio /usr/local/bin/ceffio
COPY --from=alpine:3.20 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/ceffio"]
`
	if err := os.WriteFile(tmp+"/Dockerfile", []byte(dockerfile), 0o644); err != nil {
		return err
	}
	tar := tmp + "/image.tar"
	build := exec.CommandContext(ctx, "docker", "build", "-t", imageRef, "-f", tmp+"/Dockerfile", tmp)
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("docker build: %w", err)
	}
	save := exec.CommandContext(ctx, "docker", "save", "-o", tar, imageRef)
	if err := save.Run(); err != nil {
		return fmt.Errorf("docker save: %w", err)
	}

	// 3. Import dans containerd (k3s : socket /run/k3s/containerd/containerd.sock).
	imp := exec.CommandContext(ctx, "sh", "-c",
		"sudo ctr -n k8s.io -a /run/k3s/containerd/containerd.sock images import "+tar+" || sudo crictl -r unix:///run/k3s/containerd/containerd.sock --image-endpoint unix:///run/k3s/containerd/containerd.sock load "+tar)
	imp.Stdout = os.Stdout
	imp.Stderr = os.Stderr
	if err := imp.Run(); err != nil {
		return fmt.Errorf("import containerd: %w", err)
	}
	return nil
}

func imagePresent(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "sh", "-c",
		"sudo ctr -n k8s.io -a /run/k3s/containerd/containerd.sock images ls -q | grep -F '"+imageRef+"'").CombinedOutput()
	return err == nil && strings.Contains(string(out), imageName)
}

// ensureConsoleKey crée le secret ceffio-console-key (clé admin persistée, générée une fois).
func ensureConsoleKey(ctx context.Context) error {
	if secretExists(ctx, "ceffio-console-key") {
		return nil
	}
	key, err := genSecret(32)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", "kubectl create secret generic ceffio-console-key -n "+deployNS+
		" --from-literal=key='"+key+"' --dry-run=client -o yaml | kubectl apply -f -")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// applyConsoleManifest applique RBAC + Deployment + Service + Ingress.
func applyConsoleManifest(ctx context.Context, domain string) error {
	manifest := `apiVersion: v1
kind: ServiceAccount
metadata:
  name: ceffio-admin
  namespace: ` + deployNS + `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ceffio-admin
  namespace: ` + deployNS + `
rules:
- apiGroups: [""]
  resources: [pods]
  verbs: [get, list, watch]
- apiGroups: [networking.k8s.io]
  resources: [ingresses]
  verbs: [get, list, watch]
- apiGroups: [cert-manager.io]
  resources: [certificates]
  verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ceffio-admin
  namespace: ` + deployNS + `
subjects:
- kind: ServiceAccount
  name: ceffio-admin
roleRef:
  kind: Role
  name: ceffio-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ceffio-admin
  namespace: ` + deployNS + `
  labels: {app: ceffio-admin}
spec:
  replicas: 1
  selector: {matchLabels: {app: ceffio-admin}}
  template:
    metadata: {labels: {app: ceffio-admin}}
    spec:
      serviceAccountName: ceffio-admin
      containers:
      - name: console
        image: ` + imageRef + `
        imagePullPolicy: IfNotPresent
        args: ["console", "--domain", "` + domain + `", "--addr", ":8088"]
        env:
        - {name: CEFFIO_KEY, valueFrom: {secretKeyRef: {name: ceffio-console-key, key: key}}}
        - {name: KC_ADMIN, valueFrom: {secretKeyRef: {name: keycloak-admin, key: username, optional: true}}}
        - {name: KC_ADMIN_PASSWORD, valueFrom: {secretKeyRef: {name: keycloak-admin, key: password, optional: true}}}
        ports:
        - {name: http, containerPort: 8088}
        readinessProbe:
          tcpSocket: {port: 8088}
          initialDelaySeconds: 5
          periodSeconds: 10
        resources: {limits: {memory: 128Mi}}
---
apiVersion: v1
kind: Service
metadata:
  name: ceffio-admin
  namespace: ` + deployNS + `
spec:
  selector: {app: ceffio-admin}
  ports:
  - {name: http, port: 8088, targetPort: 8088}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin
  namespace: ` + deployNS + `
  annotations:
    cert-manager.io/cluster-issuer: ceffio-ca-issuer
spec:
  ingressClassName: traefik
  tls:
  - hosts: [admin.` + domain + `]
    secretName: admin-tls
  rules:
  - host: admin.` + domain + `
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ceffio-admin
            port:
              number: 8088
`
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitConsoleReady(ctx context.Context) error {
	fmt.Println("∙ attente du pod console Ready...")
	return exec.CommandContext(ctx, "kubectl", "rollout", "status", "deploy/ceffio-admin", "-n", deployNS, "--timeout=180s").Run()
}

// genSecret est réutilisé (même convention que les autres couches).
func secretExists(ctx context.Context, name string) bool {
	return exec.CommandContext(ctx, "kubectl", "get", "secret", name, "-n", deployNS).Run() == nil
}
