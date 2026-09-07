package console

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Deploy rend la console durable et reproductible :
//   - Linux (RuntimeK3s) : clé admin persistée + unité systemd ceffio-console qui
//     exécute ce binaire (copié sous /usr/local/bin/ceffio) sur 0.0.0.0:8088.
//   - K8s : Service + Endpoints (→ nœud) + Ingress admin.<domain> + certificat.
//
// Le binaire auto-déployé est celui en cours d'exécution (os.Executable).
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDéploiement de la console d'administration (Phase 11)...")

	nodeIP, err := nodeInternalIP(ctx)
	if err != nil {
		return err
	}

	// 1) K8s : Service + Endpoints + Ingress admin.<domain>.
	if err := applyDeploy(ctx, domain, nodeIP); err != nil {
		return err
	}

	// 2) Operande sur le nœud (Linux) : binaire + clé + unité systemd.
	if systemctlAvailable() {
		if err := installOperand(domain); err != nil {
			return err
		}
	}

	fmt.Println("✓ Console d'administration déployée (https://admin." + domain + ")")
	return nil
}

func applyDeploy(ctx context.Context, domain, nodeIP string) error {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: ceffio-admin
  namespace: ceffio-system
spec:
  ports:
  - {name: http, port: %[1]d, targetPort: %[1]d}
---
apiVersion: v1
kind: Endpoints
metadata:
  name: ceffio-admin
  namespace: ceffio-system
subsets:
- addresses: [{ip: %[2]s}]
  ports: [{name: http, port: %[1]d}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin
  namespace: ceffio-system
  annotations:
    cert-manager.io/cluster-issuer: ceffio-ca-issuer
spec:
  ingressClassName: traefik
  tls:
  - hosts: [admin.%[3]s]
    secretName: admin-tls
  rules:
  - host: admin.%[3]s
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ceffio-admin
            port:
              number: %[1]d
`, ConsPort, nodeIP, domain)
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// installOperand copie le binaire courant sous /usr/local/bin/ceffio, persiste la clé
// admin dans /etc/ceffio/console.key (générée une fois), et pose + démarre l'unité
// systemd ceffio-console.
func installOperand(domain string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("exécutable courant: %w", err)
	}
	if dest := "/usr/local/bin/ceffio"; self != dest {
		if err := exec.Command("cp", self, dest).Run(); err != nil {
			if err := exec.Command("install", "-m", "0755", self, dest).Run(); err != nil {
				return fmt.Errorf("copie binaire console: %w", err)
			}
		}
	}

	etc := "/etc/ceffio"
	if err := os.MkdirAll(etc, 0o700); err != nil {
		return err
	}
	keyFile := etc + "/console.key"
	key, err := os.ReadFile(keyFile)
	if err != nil || strings.TrimSpace(string(key)) == "" {
		k, e := genSecret(32)
		if e != nil {
			return e
		}
		if e := os.WriteFile(keyFile, []byte(k+"\n"), 0o600); e != nil {
			return e
		}
		key = []byte(k)
	}
	key = []byte(strings.TrimSpace(string(key)))

	unit := fmt.Sprintf(`[Unit]
Description=Ceffio Admin Console
After=network.target

[Service]
Type=simple
Environment=CEFFIO_KEY=%s
ExecStart=/usr/local/bin/ceffio console --domain %s --addr 0.0.0.0:%d --key ${CEFFIO_KEY}
Restart=always

[Install]
WantedBy=multi-user.target
`, key, domain, ConsPort)
	unitFile := "/etc/systemd/system/ceffio-console.service"
	if err := os.WriteFile(unitFile, []byte(unit), 0o644); err != nil {
		return err
	}
	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "ceffio-console"},
		{"systemctl", "restart", "ceffio-console"},
	}
	for _, c := range cmds {
		if err := exec.Command(c[0], c[1:]...).Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(c, " "), err)
		}
	}
	fmt.Println("✓ opérande console active (systemd), clé admin → " + keyFile)
	return nil
}

func systemctlAvailable() bool {
	return filepathExists("/usr/bin/systemctl") || filepathExists("/bin/systemctl")
}

func filepathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func nodeInternalIP(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "node", "-o",
		`jsonpath={.items[0].status.addresses[?(@.type=="InternalIP")].address}`).Output()
	if err != nil {
		return "", err
	}
	// Le nœud expose parfois IPv4 + IPv6 → ne garder que l'IPv4 (endpoint/ICE).
	for _, tok := range strings.Fields(string(out)) {
		if strings.Contains(tok, ".") {
			return tok, nil
		}
	}
	return "", fmt.Errorf("adresse IPv4 interne du nœud introuvable")
}
