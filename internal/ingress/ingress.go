// Package ingress rend la suite joignable depuis un navigateur : issuers TLS
// cert-manager (CA auto-signée pour les domaines sans ACME public — dev/PME)
// et Ingresses Traefik avec hosts propres (*.<domain>).
//
// Prérequis : cert-manager installé (Phase 2) et un contrôleur Ingress
// "traefik" (natif k3s ; sur k3d, prévoir un contrôleur compatible).
package ingress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"os/exec"
	"strings"
)

// Deploy applique de façon idempotente la CA + les Ingresses pour le domaine.
// domain : domaine de base, ex. "company.fr" → cloud.company.fr, chat.company.fr...
func Deploy(ctx context.Context, domain string) error {
	fmt.Printf("\nIngress / TLS (Phase 9) pour domain=%s...\n", domain)
	if err := apply(ctx, caManifest()); err != nil {
		return err
	}
	if err := apply(ctx, ingressesManifest(domain)); err != nil {
		return err
	}
	fmt.Println("✓ Ingress / TLS configuré (Traefik + ClusterIssuer CA + hosts *." + domain + ")")
	return nil
}

// AdoptURLs rend les apps pleinement utilisables via les URLs publiques de
// l'ingress : homeserver réel pour Element, public_baseurl Synapse, protocole
// https Nextcloud, redirect URIs SSO et URL du connecteur ONLYOFFICE.
func AdoptURLs(ctx context.Context, domain string) error {
	fmt.Printf("\nAdoption des URLs publiques *.%s...\n", domain)
	cloud := "cloud." + domain
	office := "office." + domain

	// 3) Nextcloud : protocole https + URL publique + SSRF + proxy derrière Traefik.
	// Le HttpClient de Nextcloud bloque par défaut les adresses privées (SSRF) :
	// or Keycloak/ONLYOFFICE sont en IP de cluster → autoriser les serveurs locaux.
	if err := occSet(ctx, "config:system:set", "allow_local_remote_servers", "--type", "boolean", "--value", "true"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:system:set", "trusted_proxies", "0", "--value", "10.42.0.0/16"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:system:set", "overwritehost", "--value", cloud); err != nil {
		return err
	}
	if err := occSet(ctx, "config:system:set", "overwriteprotocol", "--value", "https"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:system:set", "overwrite.cli.url", "--value", "https://"+cloud); err != nil {
		return err
	}

	// 4) Redirection SSO Keycloak du client nextcloud vers le https.
	if err := ssoRedirect(ctx, domain); err != nil {
		return err
	}

	// 5) Connecteur ONLYOFFICE → URL publique. Clés EXACTES (casse CamelCase,
	// sinon "L'application ONLYOFFICE n'est pas configuré").
	if err := occSet(ctx, "config:app:set", "onlyoffice", "DocumentServerUrl", "--value", "https://"+office+"/"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:app:set", "onlyoffice", "DocumentServerInternalUrl", "--value", "https://"+office+"/"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:app:set", "onlyoffice", "StorageUrl", "--value", "https://"+cloud+"/"); err != nil {
		return err
	}

	// 6) Keycloak : hostname public + URL frontend https + proxy headers — sinon
	// ses redirections navigateur pointent vers l'hostname interne codé en dur.
	if err := adoptKeycloakHost(ctx, domain); err != nil {
		return err
	}

	// 6b) Traefik derrière un proxy amont. Sans cela, un pare-feu qui termine le
	// TLS (OPNsense, Caddy, nginx) transmet en HTTP et Traefik annonce
	// X-Forwarded-Proto: http → les applications redirigent en http:// depuis un
	// client https. Constaté en production sur Keycloak.
	if err := ProxyAmont(ctx); err != nil {
		return err
	}

	// 6c) Retirer les anciens domaines des configurations. Une installation migrée
	// garde sinon l'ancien nom codé en dur (constaté : demo.local dans Keycloak,
	// Element, Synapse) et redirige vers un domaine qui n'existe plus.
	for _, ancien := range DomainesConnus(domain) {
		if err := NettoyerAncienDomaine(ctx, ancien, domain); err != nil {
			return err
		}
	}

	// 7) Confiance TLS interne — TOUJOURS, pas seulement en demo.
	//
	// Le durcissement était enfermé dans `if isDemo(domain)` : sur un domaine
	// public il était donc sauté, et l'injection de CA de l'installation
	// d'origine (faite sur demo.local) restait en place — avec son SSL_CERT_FILE
	// amputé des autorités publiques. Conséquence : le callback OIDC de Synapse
	// vers Keycloak échouait sur « certificate verify failed » alors que le
	// certificat présenté était un Let's Encrypt valide.
	//
	// Les services s'appellent entre eux par leur nom PUBLIC en https (derrière
	// Traefik), donc l'autorité interne doit être reconnue dans les deux cas.
	// Seuls les hostAliases sont propres à la demo : sur un domaine public le DNS
	// résout réellement, et les écraser enverrait le trafic au mauvais endroit.
	if err := InjecterConfianceTLS(ctx, domain, isDemo(domain)); err != nil {
		return err
	}

	fmt.Println("✓ URLs publiques adoptées dans Nextcloud, ONLYOFFICE, Keycloak + redirect SSO")
	return nil
}

// adoptKeycloakHost force l'hostname public de Keycloak (redirections navigateur)
// avec une URL frontend https et les proxy headers de Traefik. Idempotent.
func adoptKeycloakHost(ctx context.Context, domain string) error {
	host := "keycloak." + domain
	url := "https://" + host
	cmd := k8s.Command(ctx, "kubectl", "set", "env", "-n", "ceffio-identity", "deploy/keycloak",
		"KC_HOSTNAME="+host, "KC_HOSTNAME_URL="+url,
		"KC_HOSTNAME_STRICT=false", "KC_PROXY_HEADERS=xforwarded")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	rcmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/keycloak", "-n", "ceffio-identity", "--timeout=240s")
	rcmd.Stdout = os.Stdout
	rcmd.Stderr = os.Stderr
	return rcmd.Run()
}

// isDemo → domaine privé `.local` : pas de DNS réel ni CA publique → durcissement
// hostAliases + injection CA. Un domaine public n'en a pas besoin.
func isDemo(domain string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(domain)), ".local")
}

// InjecterConfianceTLS rend l'autorité interne reconnaissable par les services,
// pour que leurs appels serveur→serveur en https public aboutissent.
//
// S'applique TOUJOURS (domaine public comme demo) : les applications s'appellent
// par leur nom public, et ce certificat est signé par notre autorité.
//
// avecHostAliases est réservé à la demo : là seulement, le DNS ne résout pas les
// noms publics et il faut les router de force vers Traefik. Sur un domaine
// public, poser des hostAliases serait nuisible — le trafic doit passer par le
// vrai DNS, pas être détourné vers le cluster.
func InjecterConfianceTLS(ctx context.Context, domain string, avecHostAliases bool) error {
	if avecHostAliases == false {
		fmt.Println("Confiance TLS interne (CA ceffio injectée, sans hostAliases — domaine public)...")
	} else {
		fmt.Println("Confiance TLS interne + hostAliases→Traefik (demo)...")
	}
	tip, err := svcIP(ctx, "traefik", "kube-system")
	if err != nil {
		return fmt.Errorf("IP Traefik: %w", err)
	}
	ca, err := caCert(ctx)
	if err != nil {
		return err
	}
	kc := "keycloak." + domain
	cloud := "cloud." + domain
	office := "office." + domain

	// En domaine public, hosts reste VIDE : cela purge les hostAliases posés du
	// temps de demo.local (un « hostAliases: null » les retire) et laisse le vrai
	// DNS faire son travail.
	hostsAutres := []string{kc, office}
	hostsOffice := []string{cloud, office, kc}
	if !avecHostAliases {
		hostsAutres, hostsOffice = nil, nil
	}

	// Nextcloud (PHP) : CA via php.ini pointant sur la CA montée (persistant pour PHP).
	if err := createCAConfigs(ctx, "ceffio-files", ca); err != nil {
		return err
	}
	// SSL_CERT_FILE REMPLACE la liste par défaut (voir la note Synapse plus bas) :
	// on pointe sur le paquet COMBINÉ, sinon Nextcloud perd toute confiance dans
	// les certificats publics et ses appels sortants échouent.
	if err := patchApp(ctx, "ceffio-files", "nextcloud", "nextcloud", tip,
		hostsAutres, []envKV{{"SSL_CERT_FILE", cheminPaquetCombine}}, true); err != nil {
		return err
	}

	// ONLYOFFICE (Node.js) : NODE_EXTRA_CA_CERTS.
	// Celui-ci AJOUTE à la liste des autorités, il ne la remplace pas — on peut
	// donc pointer sur notre seule autorité sans perdre les certificats publics.
	// NE PAS « uniformiser » avec le paquet combiné : ce serait correct aussi,
	// mais inutilement plus lourd.
	if err := createCAConfigs(ctx, "ceffio-office", ca); err != nil {
		return err
	}
	if err := patchApp(ctx, "ceffio-office", "onlyoffice", "onlyoffice", tip,
		hostsOffice, []envKV{{"NODE_EXTRA_CA_CERTS", "/etc/ceffio-ca/ceffio-ca.crt"}}, false); err != nil {
		return err
	}
	if avecHostAliases {
		fmt.Println("✓ Confiance TLS interne appliquée (hostAliases→" + tip + ")")
	} else {
		fmt.Println("✓ Confiance TLS interne appliquée (domain public, pas de hostAliases)")
	}
	return nil
}

type envKV struct{ name, value string }

// cheminPaquetCombine : fichier contenant les autorités du SYSTÈME plus notre
// autorité interne. À utiliser partout où l'on pose SSL_CERT_FILE, qui REMPLACE
// la liste par défaut au lieu de s'y ajouter.
const cheminPaquetCombine = "/etc/ceffio-ca/paquet-combine.crt"

// svcIP lit le ClusterIP d'un Service.
func svcIP(ctx context.Context, name, ns string) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "svc", name, "-n", ns, "-o", "jsonpath={.spec.clusterIP}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// paquetCombine assemble les autorités du SYSTÈME et notre autorité interne en
// un seul fichier PEM.
//
// Pourquoi : SSL_CERT_FILE (Python, OpenSSL) désigne LA liste des autorités de
// confiance, il ne s'y ajoute pas. Y mettre notre seule autorité interne rend
// tout certificat public invalide — c'est exactement ce qui cassait le callback
// OIDC (Keycloak présente un Let's Encrypt valide, Synapse le refusait).
//
// Le paquet combine donc les deux : rien n'est perdu, notre autorité est
// reconnue.
func paquetCombine() (string, error) {
	systeme := ""
	for _, f := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/cert.pem",
	} {
		if b, err := os.ReadFile(f); err == nil && len(b) > 0 {
			systeme = string(b)
			break
		}
	}
	if systeme == "" {
		return "", fmt.Errorf("aucun paquet d'autorités système trouvé")
	}
	if !strings.HasSuffix(systeme, "\n") {
		systeme += "\n"
	}
	// Notre autorité est ajoutée APRÈS le paquet système.
	out, err := caCert(context.Background())
	if err != nil {
		return "", err
	}
	return systeme + out, nil
}

// caCert lit le certificat CA de la chaîne signée par cert-manager (ceffio-ca-tls).
func caCert(ctx context.Context) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", "ceffio-ca-tls", "-n", "cert-manager", "-o", "jsonpath={.data.ca\\.crt}").Output()
	if err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// createCAConfigs crée les ConfigMaps ceffio-ca-cm (CA) + ceffio-phpini (php.ini) dans le ns.
func createCAConfigs(ctx context.Context, ns, ca string) error {
	// Deux fichiers dans le ConfigMap :
	//   ceffio-ca.crt — notre seule autorité. Pour les mécanismes qui AJOUTENT
	//     (NODE_EXTRA_CA_CERTS de Node, openssl.cafile de PHP, curl.cainfo).
	//   paquet-combine.crt — autorités système + la nôtre. Obligatoire pour
	//     SSL_CERT_FILE, qui REMPLACE la liste par défaut : pointer sur notre
	//     seule autorité ferait refuser tout certificat public (cause du
	//     « certificate verify failed » sur le callback OIDC de Synapse).
	paquet, err := paquetCombine()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap ceffio-ca-cm -n "+ns+
			" --from-file=ceffio-ca.crt=/dev/stdin"+
			" --from-file=paquet-combine.crt=/tmp/paquet-combine.crt"+
			" --dry-run=client -o yaml | kubectl apply -f -")
	if err := os.WriteFile("/tmp/paquet-combine.crt", []byte(paquet), 0o644); err != nil {
		return err
	}
	cmd.Stdin = strings.NewReader(ca)
	cmd.Env = k8s.Env()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	os.Remove("/tmp/paquet-combine.crt")
	// openssl.cafile et curl.cainfo REMPLACENT la liste par défaut (même piège
	// que SSL_CERT_FILE) : le paquet combiné, pour ne pas perdre les autorités
	// publiques dont PHP a besoin pour ses appels sortants.
	ini := "openssl.cafile=" + cheminPaquetCombine + "\ncurl.cainfo=" + cheminPaquetCombine + "\n"
	cmd2 := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap ceffio-phpini -n "+ns+" --from-file=zz-ceffio.ini=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -")
	cmd2.Stdin = strings.NewReader(ini)
	cmd2.Env = k8s.Env()
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	return cmd2.Run()
}

// patchApp applique hostAliases + volume CA + env (+ php.ini) via merge patch (idempotent).
func patchApp(ctx context.Context, ns, deploy, container, traefikIP string, hosts []string, envs []envKV, withPHPIni bool) error {
	// hosts vide = pas de hostAliases. On en pose SEULEMENT en demo : sur un
	// domaine public, forcer la résolution vers le cluster court-circuiterait le
	// vrai DNS et enverrait le trafic au mauvais endroit.
	var ha []map[string]any
	if len(hosts) > 0 {
		ha = []map[string]any{{"ip": traefikIP, "hostnames": hosts}}
	}
	vols := []map[string]any{{"name": "ceffio-ca", "configMap": map[string]string{"name": "ceffio-ca-cm"}}}
	env := []map[string]string{}
	for _, e := range envs {
		env = append(env, map[string]string{"name": e.name, "value": e.value})
	}
	mounts := []map[string]string{{"name": "ceffio-ca", "mountPath": "/etc/ceffio-ca"}}
	if withPHPIni {
		vols = append(vols, map[string]any{"name": "ceffio-phpini", "configMap": map[string]string{"name": "ceffio-phpini"}})
		// subPath sur le FICHIER : l'entrypoint Nextcloud écrit redis-session.ini dans
		// conf.d au boot — monter un ConfigMap répertoire read-only sur ce dossier casse
		// l'entrypoint (Read-only file system). subPath ne monte que le fichier zz-ceffio.ini.
		mounts = append(mounts, map[string]string{"name": "ceffio-phpini", "mountPath": "/usr/local/etc/php/conf.d/zz-ceffio.ini", "subPath": "zz-ceffio.ini"})
	}
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"hostAliases": ha,
					"volumes":     vols,
					"containers": []any{
						map[string]any{
							"name":         container,
							"env":          env,
							"volumeMounts": mounts,
						},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(patch)
	cmd := k8s.Command(ctx, "kubectl", "patch", "deploy", deploy, "-n", ns, "--type=strategic", "-p", string(b))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	r := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/"+deploy, "-n", ns, "--timeout=200s")
	r.Stdout = os.Stdout
	r.Stderr = os.Stderr
	return r.Run()
}

func rewriteConfig(ctx context.Context, ns, cm, key, old, repl, target string) error {
	data, err := cmData(ctx, ns, cm, key)
	if err != nil {
		return err
	}
	if old != "" && strings.Contains(data, old) {
		data = strings.ReplaceAll(data, old, repl)
		if err := applyCMData(ctx, ns, cm, key, data); err != nil {
			return err
		}
		if err := rolloutRestart(ctx, target); err != nil {
			return err
		}
	}
	return nil
}

func appendNonDuplicate(ctx context.Context, ns, cm, key, line, needle, target string) error {
	data, err := cmData(ctx, ns, cm, key)
	if err != nil {
		return err
	}
	if strings.Contains(data, needle) {
		return nil // déjà présent
	}
	if err := applyCMData(ctx, ns, cm, key, data+"\n"+line); err != nil {
		return err
	}
	return rolloutRestart(ctx, target)
}

// ssoRedirect ajoute les redirect URIs https des clients OIDC via kcadm.
func ssoRedirect(ctx context.Context, domain string) error {
	for _, client := range []struct{ id, base string }{
		{id: "nextcloud", base: "cloud." + domain},
	} {
		uri := "https://" + client.base + "/*"
		if err := kcadmRedirect(ctx, client.id, uri); err != nil {
			return err
		}
	}
	return nil
}

// --- helpers ---

func occSet(ctx context.Context, args ...string) error {
	full := append([]string{"exec", "-n", "ceffio-files", "deploy/nextcloud", "-c", "nextcloud", "--", "php", "occ"}, args...)
	cmd := k8s.Command(ctx, "kubectl", full...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmData(ctx context.Context, ns, name, key string) (string, error) {
	tpl := "{.data." + strings.ReplaceAll(key, ".", "\\.") + "}"
	out, err := k8s.Command(ctx, "kubectl", "get", "cm", name, "-n", ns, "-o", "jsonpath="+tpl).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func applyCMData(ctx context.Context, ns, name, key, data string) error {
	tmp, err := os.CreateTemp("", "cm-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := os.WriteFile(tmp.Name(), []byte(data), 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap "+name+" -n "+ns+" --from-file="+key+"="+tmp.Name()+" --dry-run=client -o yaml | kubectl apply -f -")
	cmd.Env = k8s.Env()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// rolloutRestart redemarre un deployment.
//
// Le namespace peut etre passe explicitement : « deploy/traefik » vit dans
// kube-system, hors de la table ci-dessous, et la version anterieure ECHOUAIT
// sur un target absent de la table — ce qui interrompait tout le deploiement
// en cours (constate sur ProxyAmont, qui arretait la sequence avant la console).
func rolloutRestart(ctx context.Context, target string) error {
	explicite := ""
	if strings.Contains(target, "@") {
		parties := strings.SplitN(target, "@", 2)
		target, explicite = parties[0], parties[1]
	}
	deploy := strings.TrimPrefix(target, "deploy/")
	ns := explicite
	if ns == "" {
		ns = map[string]string{
			"nextcloud": "ceffio-files", "onlyoffice": "ceffio-office",
			"keycloak": "ceffio-identity",
			"traefik":  "kube-system",
		}[deploy]
	}
	if ns == "" {
		return fmt.Errorf("namespace inconnu pour %q (utiliser « deploy/nom@namespace »)", target)
	}
	cmd := k8s.Command(ctx, "kubectl", "rollout", "restart", "deploy/"+deploy, "-n", ns)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runKcadm(ctx context.Context, args ...string) (string, error) {
	// Injecte -r ceffio après le verbe (les clients SSO vivent dans le realm applicatif).
	quoted := make([]string, 0, len(args)+3)
	for i, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		if i == 0 {
			quoted = append(quoted, "'-r'", "'ceffio'")
		}
	}
	cmdStr := `/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1 && /opt/keycloak/bin/kcadm.sh ` + strings.Join(quoted, " ")
	full := []string{"exec", "-n", "ceffio-identity", "deploy/keycloak", "-c", "keycloak", "--", "sh", "-c", cmdStr}
	out, err := k8s.Command(ctx, "kubectl", full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// kcadmRedirect ajoute un redirect URI au client OIDC Keycloak sans écraser les existants.
func kcadmRedirect(ctx context.Context, clientID, uri string) error {
	out, err := runKcadm(ctx, "get", "clients", "-q", "clientId="+clientID, "--fields", "id,redirectUris")
	if err != nil {
		return fmt.Errorf("get client %s: %w (%s)", clientID, err, out)
	}
	var list []struct {
		ID           string   `json:"id"`
		RedirectUris []string `json:"redirectUris"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return fmt.Errorf("parse client %s: %w (%s)", clientID, err, out)
	}
	if len(list) == 0 {
		return fmt.Errorf("client %s introuvable dans le realm ceffio", clientID)
	}
	c := list[0]
	seen := map[string]bool{uri: true}
	uris := []string{uri}
	for _, u := range c.RedirectUris {
		if u != "" && !seen[u] {
			uris = append(uris, u)
			seen[u] = true
		}
	}
	val, _ := json.Marshal(uris)
	_, err = runKcadm(ctx, "update", "clients/"+c.ID, "-s", "redirectUris="+string(val))
	return err
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// caManifest : CA auto-signée (issuer bootstrap → certificat CA → issuer CA)
// pour signer les certificats des Ingresses. Se fait une fois, idempotent.
func caManifest() string {
	return `apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ceffio-selfsigned
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ceffio-ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: ceffio-ca
  secretName: ceffio-ca-tls
  duration: 87600h
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: ceffio-selfsigned
    kind: ClusterIssuer
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ceffio-ca-issuer
spec:
  ca:
    secretName: ceffio-ca-tls
`
}

// appRoute décrit une route applicative : host "<sub>.<domain>", service cible.
type appRoute struct {
	sub, namespace, service string
	port                    int
}

func ingressesManifest(domain string) string {
	routes := []appRoute{
		{sub: "cloud", namespace: "ceffio-files", service: "nextcloud", port: 80},
		{sub: "keycloak", namespace: "ceffio-identity", service: "keycloak", port: 8080},
		{sub: "office", namespace: "ceffio-office", service: "onlyoffice", port: 80},
		// Talk : le signaling server est joint par le NAVIGATEUR (pas seulement
		// en interne) — il doit donc être exposé, et en WebSocket.
		{sub: "spreed", namespace: "ceffio-video", service: "talk-signaling", port: 8081},
		// Le coffre a besoin d'une adresse PUBLIQUE, et pas pour l'affichage :
		// l'authentification OIDC renvoie le navigateur vers une adresse de
		// retour, qui doit être joignable et en TLS. Un coffre accessible
		// seulement par un port en clair ne peut pas authentifier d'humain.
		{sub: "bao", namespace: "ceffio-vault", service: "openbao", port: 8200},
	}
	var sb strings.Builder
	for _, r := range routes {
		// Annotations supplémentaires, propres à certaines routes.
		//
		// POURQUOI ICI ET PAS DANS UN CHAMP DE appRoute : une seule route a
		// besoin d'annotations aujourd'hui (le signaling, dont les connexions
		// WebSocket durent des heures). Un champ dans la structure suggérerait
		// que toutes les routes en ont, alors que l'immense majorité n'en a pas.
		//
		// ATTENTION AU YAML : une ligne d'annotation mal formée ou un index
		// Fprintf mal numéroté produit un manifeste invalide, et kubectl refuse
		// TOUT le lot (pas seulement la route concernée). Les index ci-dessous
		// sont explicites pour cette raison.
		ann := ""
		if r.sub == "spreed" {
			ann = "    traefik.ingress.kubernetes.io/proxy-read-timeout: \"3600\"\n" +
				"    traefik.ingress.kubernetes.io/proxy-send-timeout: \"3600\""
		}
		host := r.sub + "." + domain
		fmt.Fprintf(&sb, `---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %[1]s
  namespace: %[2]s
  annotations:
    cert-manager.io/cluster-issuer: ceffio-ca-issuer
%[5]s
spec:
  ingressClassName: traefik
  tls:
    - hosts: [%[3]s]
      secretName: %[1]s-tls
  rules:
    - host: %[3]s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %[4]s
                port:
                  number: %[6]d
`, r.sub, r.namespace, host, r.service, ann, r.port)
	}
	return sb.String()
}
