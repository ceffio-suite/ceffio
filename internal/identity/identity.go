// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package identity orchestrates the deployment of the identity layer (Phase 4):
// the dedicated PostgreSQL user/secret, Keycloak (official pinned Quay image)
// wired to the `keycloak` database, and the creation of the `ceffio` realm.
//
// Secrets: all generated at runtime (crypto/rand), stored in Kubernetes Secrets
// — never in clear text in Git (doc principle §111).
package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"os"
	"strings"
	"time"
)

// Pinned versions (discovered via the Quay API, not invented).
const (
	keycloakImage = "quay.io/keycloak/keycloak:26.7.3"
	ns            = "ceffio-identity"
	// PostgreSQL: CNPG pod (to create the role) and rw service (to connect).
	pgPod     = "ceffio-pg-1"
	pgNSPod   = "ceffio-data"
	dbName    = "keycloak"
	dbUser    = "keycloak"
	dbService = "ceffio-pg-rw.ceffio-data.svc"

	// Nextcloud vit dans son propre namespace. Le confondre avec celui de
	// PostgreSQL a produit « deployments.apps "nextcloud" not found », une
	// erreur qui accuse un déploiement absent alors que le sujet est un
	// namespace.
	nsFiles = "ceffio-files"
)

// Deploy installs the identity layer (Phase 4), idempotently:
//  1. dedicated PostgreSQL role + password for Keycloak
//  2. Keycloak admin secret (generated)
//  3. Keycloak deployment (postgres) + service
//  4. creation of the "ceffio" realm via kcadm + verification
func Deploy(ctx context.Context) error {
	fmt.Println("\nDeploying the identity layer (Phase 4)...")

	if err := ensureKeycloakDB(ctx); err != nil {
		return err
	}
	if err := ensureServiceAccount(ctx); err != nil {
		return err
	}
	if err := ensureAdminSecret(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx); err != nil {
		return err
	}
	if err := waitKeycloakReady(ctx); err != nil {
		return err
	}
	if err := ensureRealm(ctx); err != nil {
		return err
	}
	if err := verifyRealm(ctx); err != nil {
		return err
	}

	// THE ADMINISTRATOR ACCOUNT ITSELF, created HERE and not from the console.
	//
	// POURQUOI À L'INSTALLATION : le realm et le compte sont deux choses, et
	// seule la première était faite. L'opérateur se retrouvait avec un realm
	// vide — vérifié, `kcadm get users -r ceffio` rendait `[ ]` — et une
	// interface qui affichait
	//
	//	missing from the directory
	//	missing from Nextcloud
	//	WITHOUT admin rights
	//	inactive account
	//
	// La rotation depuis la console savait poser un mot de passe mais pas créer
	// le compte, ce qui supposait que l'installation l'ait fait. Elle ne le
	// faisait pas. Une plateforme fraîchement installée doit être utilisable
	// sans qu'on ait à cliquer sur un bouton pour que son administrateur existe.
	if err := ensureCompteAdmin(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Identity layer deployed (ceffio realm)")
	return nil
}

// ensureKeycloakDB guarantees the PostgreSQL role lives IN THE VAULT, and nowhere else.
//
// The password is REUSED if it exists: regenerating it would leave Keycloak with
// a password the database rejects, and the outage would only appear at restart.
func ensureKeycloakDB(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "db")
	switch {
	case err == nil:
		entree = actuelle
	case secrets.EntreeAbsente(err):
	default:
		return fmt.Errorf("vault unreadable for keycloak/db: %w", err)
	}
	if entree["password"] != "" {
		return nil
	}
	fmt.Println("∙ creating the dedicated PostgreSQL role for Keycloak")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	// SQL passed on stdin (never as a command argument).
	sql := fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s';\nALTER DATABASE %s OWNER TO %s;\n",
		dbUser, pw, dbName, dbUser)
	if err := psqlExec(ctx, sql); err != nil {
		return err
	}
	entree["username"] = dbUser
	entree["password"] = pw
	return secrets.EcrireDansCoffre(ctx, coffre, "keycloak", "db", entree)
}

// ensureAdminSecret guarantees the admin account lives IN THE VAULT.
func ensureAdminSecret(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{"username": "admin"}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "admin")
	switch {
	case err == nil:
		for k, v := range actuelle {
			entree[k] = v
		}
	case secrets.EntreeAbsente(err):
	default:
		return fmt.Errorf("vault unreadable for keycloak/admin: %w", err)
	}
	if entree["password"] != "" {
		return nil
	}
	fmt.Println("∙ Keycloak admin password generated (absent from the vault)")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	entree["password"] = pw
	return secrets.EcrireDansCoffre(ctx, coffre, "keycloak", "admin", entree)
}

// ensureServiceAccount lays down the identity that the vault role designates (see the
// equivalent note on the Nextcloud side: laid down separately so as not to shift the
// arguments of an already-numbered manifest).
func ensureServiceAccount(ctx context.Context) error {
	return apply(ctx, fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: keycloak
  namespace: %s
`, ns))
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ Keycloak " + keycloakImage)
	// TWO SOURCES FOR ONE FILE: the database and the admin account.
	annotations := vault.AnnotationsAgent(8, "keycloak", "kv/data/ceffio/keycloak/db",
		vault.GabaritMulti([]vault.Source{
			{Chemin: "kv/data/ceffio/keycloak/db", Paires: [][2]string{
				{"KC_DB_USERNAME", vault.ChampCoffre("username")},
				{"KC_DB_PASSWORD", vault.ChampCoffre("password")},
			}},
			{Chemin: "kv/data/ceffio/keycloak/admin", Paires: [][2]string{
				{"KC_BOOTSTRAP_ADMIN_USERNAME", vault.ChampCoffre("username")},
				{"KC_BOOTSTRAP_ADMIN_PASSWORD", vault.ChampCoffre("password")},
			}},
		}))

	manifest := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: %s
  labels:
    app: keycloak
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
      # SECRETS ARE LAID DOWN BY THE OPENBAO INJECTOR (vault.AnnotationsAgent).
      annotations:
%s
    spec:
      # THIS ServiceAccount IS THE ONE THE VAULT ROLE DESIGNATES.
      serviceAccountName: keycloak
      containers:
        - name: keycloak
          image: %s
          # THE IMAGE ENTRYPOINT IS kc.sh: we call it back explicitly, with the
          # same arguments as before ("start-dev").
          command: ["/bin/bash", "-c"]
          args:
            - |
              set -a
              . /secrets/env
              set +a
              exec /opt/keycloak/bin/kc.sh start-dev
          env:
            - name: KC_DB
              value: postgres
            - name: KC_DB_URL
              value: jdbc:postgresql://%s:5432/%s
            - name: KC_HEALTH_ENABLED
              value: "true"
            - name: KC_METRICS_ENABLED
              value: "true"
            # KC_HOSTNAME is NOT set here: its value was frozen on the old domain
            # (auth.ceffio.local), and Keycloak uses it to build the endpoints it
            # ANNOUNCES — so the SSO redirect went to a nonexistent domain. It is
            # the ingress phase (adoptKeycloakHost) that sets KC_HOSTNAME /
            # KC_HOSTNAME_URL with the current domain. A hardcoded duplicate here
            # would only contradict it.
            - name: KC_HOSTNAME_STRICT
              value: "false"
          ports:
            - name: http
              containerPort: 8080
            - name: management
              containerPort: 9000
          readinessProbe:
            httpGet:
              path: /health/ready
              port: management
            periodSeconds: 10
            failureThreshold: 6
          livenessProbe:
            httpGet:
              path: /health/live
              port: management
            initialDelaySeconds: 120
            periodSeconds: 15
            failureThreshold: 6
          resources:
            requests:
              memory: 1536Mi
              cpu: 250m
            limits:
              memory: 3Gi
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: %s
spec:
  selector:
    app: keycloak
  ports:
    - name: http
      port: 8080
      targetPort: 8080
`, ns, annotations, keycloakImage, dbService, dbName, ns)
	return apply(ctx, manifest)
}

func waitKeycloakReady(ctx context.Context) error {
	fmt.Println("∙ waiting for Keycloak Ready...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/keycloak", "-n", ns, "--timeout=600s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keycloak not ready: %w", err)
	}
	return nil
}

// ensureRealm creates the "ceffio" realm via kcadm, idempotently: we only create
// it if the realm is not already in the database. The admin is re-read from the
// pod environment (no secret to pass).
func ensureRealm(ctx context.Context) error {
	out, err := queryKeycloakDB(ctx, `SELECT count(*) FROM realm WHERE name='ceffio';`)
	if err == nil && strings.TrimSpace(out) == "1" {
		fmt.Println("∙ ceffio realm already present, nothing to do")
		return nil
	}
	fmt.Println("∙ creating the ceffio realm (kcadm)")
	if err := creerRealm(ctx); err != nil {
		return err
	}
	return nil
}

// creerRealm creates the "ceffio" realm via kcadm.
//
// ADMIN CREDENTIALS COME FROM THE VAULT and travel through STANDARD INPUT,
// never through the command line.
//
// THIS CODE USED TO READ $KC_BOOTSTRAP_ADMIN_* FROM THE POD ENVIRONMENT, and
// that can no longer work: the migration to the OpenBao injector removed those
// variables from the Deployment. They now live only in /secrets/env, which the
// CONTAINER'S STARTUP COMMAND sources for its own process. A `kubectl exec`
// opens a NEW shell that inherits none of it, so the variables were EMPTY,
// kcadm answered "Invalid user credentials", and the whole identity layer
// stopped there — with an error that pointed at a password problem that did
// not exist.
//
// The reasoning is the one already applied in internal/sso (runKcadm); this
// file had simply not been updated to match.
func creerRealm(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "admin")
	if err != nil {
		return fmt.Errorf("Keycloak admin credentials unreadable in the vault: %w", err)
	}
	utilisateur, motdepasse := entree["username"], entree["password"]
	if utilisateur == "" || motdepasse == "" {
		return fmt.Errorf("incomplete keycloak/admin vault entry (username and password required)")
	}

	// IFS= read -r keeps the password intact (no trimming, no backslash
	// interpretation) while it comes in on stdin.
	script := `IFS= read -r motdepasse; ` +
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master ` +
		`--user '` + strings.ReplaceAll(utilisateur, "'", `'\''`) + `' --password "$motdepasse" >/dev/null && ` +
		`/opt/keycloak/bin/kcadm.sh create realms -s "realm=ceffio" -s enabled=true ` +
		`-s registrationAllowed=false -s loginWithEmailAllowed=true -s duplicateEmailsAllowed=false ` +
		`-s resetPasswordAllowed=true -s editUsernameAllowed=false -s sslRequired=external`

	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-n", ns, "deploy/keycloak", "-c", "keycloak",
		"--", "sh", "-c", script)
	cmd.Stdin = strings.NewReader(motdepasse + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("creating the ceffio realm: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// verifyRealm checks that the "ceffio" realm actually exists in the database.
func verifyRealm(ctx context.Context) error {
	fmt.Println("∙ verifying the ceffio realm")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := queryKeycloakDB(ctx, `SELECT count(*) FROM realm WHERE name='ceffio';`)
		if err == nil && strings.TrimSpace(out) == "1" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("ceffio realm not found in the database after 30s")
}

func psqlExec(ctx context.Context, sql string) error {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres",
		"-n", pgNSPod, pgPod, "--", "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql: %w: %s", err, out)
	}
	return nil
}

func queryKeycloakDB(ctx context.Context, sql string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-c", "postgres",
		"-n", pgNSPod, pgPod, "--", "psql", "-U", "postgres", "-d", dbName, "-tAc", sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("psql: %w: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func secretExists(ctx context.Context, name string) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns).CombinedOutput()
	return err == nil && strings.Contains(string(out), name)
}

func createSecret(ctx context.Context, name string, kv map[string]string) error {
	args := []string{"create", "secret", "generic", name, "-n", ns, "--dry-run=client", "-o", "yaml"}
	for k, v := range kv {
		args = append(args, "--from-literal="+k+"="+v)
	}
	out, err := k8s.Command(ctx, "kubectl", args...).Output()
	if err != nil {
		return fmt.Errorf("secret dry-run: %w", err)
	}
	return apply(ctx, string(out))
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ---------------------------------------------------------------------------
// Administrator account
// ---------------------------------------------------------------------------

// compteAdminIdentifiant is the single identifier used everywhere: Keycloak,
// Nextcloud, the mail server and the console.
//
// ONE FORM, EVERYWHERE. The operator asked for this explicitly: no
// adminceffio@local here and adminceffio@domain elsewhere, because that forces
// remembering two shapes of the same account. The mail domain is a real domain
// and the address is never used to send mail — OpenBao's OIDC role binds to it
// as a STABLE CLAIM.
const (
	compteAdminIdentifiant = "adminceffio"
	compteAdminEmail       = "adminceffio@ceffio.local"
	compteAdminGroupe      = "admin"

	// The names Keycloak requires at first sign-in. They are not the operator's
	// real name — we do not know it — but a filled value, so the platform is
	// usable IMMEDIATELY after installation instead of blocking on a form.
	// Changeable from the account page afterwards.
	compteAdminPrenom = "Administrateur"
	compteAdminNom    = "Ceffio"
)

// ensureCompteAdmin creates the platform administrator, in the directory AND in
// Nextcloud, with THE SAME password.
//
// IT IS IDEMPOTENT BY CONSTRUCTION: an account that already exists is left
// alone and its password is NOT regenerated. That matters because this function
// runs on every `ceffio install`, including re-runs on a live platform — and
// rotating the administrator's password because someone re-ran the installer
// would lock them out of their own interface without warning.
//
// THE PASSWORD IS STORED IN THE VAULT, unlike the rotation button which only
// keeps a fingerprint. The difference is deliberate: here the operator has just
// installed and has nothing yet, so the password must be shown once and be
// recoverable from the summary; the rotation button exists precisely to make a
// password that is NOT kept.
func ensureCompteAdmin(ctx context.Context) error {
	fmt.Println("∙ administrator account (" + compteAdminIdentifiant + ")")

	coffre := secrets.DepuisEnvironnement()
	if coffre == nil || !coffre.Dispo() {
		return fmt.Errorf("the vault is required to create the administrator account")
	}

	// ALREADY DONE? The vault entry is the marker: it is written only when the
	// account is created, so its presence means a previous run succeeded.
	// Reading the account from Keycloak instead would be guessing — the account
	// could have been deleted by hand while the password stayed in the vault.
	// LE COMPTE EXISTE DÉJÀ : on ne régénère PAS le mot de passe, mais on ne
	// sort pas non plus.
	//
	// SORTIR ICI ÉTAIT UN DÉFAUT : les champs obligatoires de Keycloak
	// (firstName, lastName) ne sont pas remplis par `create users` d'une
	// version antérieure, et un `return` immédiat rendait impossible la
	// réparation d'un realm déjà provisionné. L'opérateur restait bloqué sur
	// « Please specify this field. » à la première connexion, sans aucun moyen
	// de s'en sortir par une réinstallation.
	//
	// La réparation est donc TOUJOURS exécutée : elle est idempotente, et sur
	// un compte sain elle ne change rien.
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "sso", "adminceffio")
	existant := err == nil && entree["password"] != ""
	if existant {
		fmt.Println("  ∙ account already created, password left unchanged")
	}

	mdp := ""
	if existant {
		mdp = entree["password"]
	} else {
		var errGen error
		mdp, errGen = motDePasseAdmin()
		if errGen != nil {
			return fmt.Errorf("generating the administrator password: %w", errGen)
		}
	}

	// 1. KEYCLOAK FIRST: it is the source of identity, and its failure must stop
	//    everything rather than leave a password in the vault for an account
	//    that does not exist. It also REPAIRS an existing account's mandatory
	//    fields.
	if err := creerCompteKeycloak(ctx, mdp); err != nil {
		return err
	}

	// 2. NEXTCLOUD: the local account, so direct sign-in works when SSO is
	//    unavailable. A platform whose only way in is a dependency is a platform
	//    that can be locked out by that dependency.
	if err := creerCompteNextcloud(ctx, mdp); err != nil {
		// Not fatal, and reported: Keycloak is what the interface uses, and
		// failing the whole installation over the fallback path would be a bad
		// trade. The console can create it later.
		fmt.Printf("  ⚠ Nextcloud account not created: %v\n", err)
		fmt.Println("    (the console can create it later from Administration)")
	}

	// 3. THE VAULT LAST, as the completion marker. Written before the accounts
	//    existed, a crash in between would leave a password for nothing.
	// On n'écrit que si le compte vient d'être créé : réécrire une entrée
	// identique créerait une version de plus dans l'historique du coffre à
	// chaque réinstallation, sans rien apporter.
	if !existant {
		if err := secrets.EcrireDansCoffre(ctx, coffre, "sso", "adminceffio", map[string]string{
			"username": compteAdminIdentifiant,
			"email":    compteAdminEmail,
			"password": mdp,
		}); err != nil {
			return fmt.Errorf("storing the administrator password: %w", err)
		}
		fmt.Println("  ✓ administrator created (password shown in the summary)")
	} else {
		fmt.Println("  ✓ administrator fields repaired (name, email)")
	}
	return nil
}

// motDePasseAdmin generates a password suited to being typed BY A HUMAN.
//
// The alphabet has no ambiguous pair (0/O, 1/l/I): the operator reads this once
// off a terminal and types it into a browser, and an unreadable character turns
// a successful installation into a support call.
func motDePasseAdmin() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*"
	out := make([]byte, 0, 24)
	for len(out) < 24 {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		out = append(out, alphabet[int(b[0])%len(alphabet)])
	}
	return string(out), nil
}

// creerCompteKeycloak creates the administrator user in the ceffio realm.
//
// IT GOES THROUGH kcadm, like creerRealm, and for the same reason: the admin
// credentials live in the vault and are read HERE, on the installation machine,
// then passed on standard input — never as a command-line argument, which the
// process table would expose.
//
// CREATED WITH NO REALM ROLE, deliberately. This account is a USER of the realm,
// not an administrator OF Keycloak: its rights in the operator's sense come from
// the SSO configuration and from OpenBao's policy. Granting realm-admin would
// let it rewrite the entire directory, and nothing needs that.
//
// THE EMAIL IS NOT DECORATION: OpenBao's OIDC role binds to
// adminceffio@ceffio.local as a claim. Without it the SSO login would
// authenticate against a realm that does not recognise this identity, and the
// vault would refuse the connection.
func creerCompteKeycloak(ctx context.Context, mdp string) error {
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "admin")
	if err != nil {
		return fmt.Errorf("Keycloak admin credentials unreadable in the vault: %w", err)
	}
	utilisateur, motdepasse := entree["username"], entree["password"]
	if utilisateur == "" || motdepasse == "" {
		return fmt.Errorf("incomplete keycloak/admin vault entry")
	}
	if len(mdp) == 0 {
		return fmt.Errorf("empty administrator password")
	}

	// The account is created with `create users`, and the PASSWORD IS SET IN A
	// SECOND PASS: kcadm refuses to create a user with a credential in one call.
	//
	// idempotent: `create users` fails if the account exists, and that failure
	// is ignored — this function runs on re-installs, where the account is
	// already there and only the password matters.
	// FIRST NAME AND LAST NAME ARE REQUIRED BY KEYCLOAK, and omitting them is
	// not a cosmetic detail: the first sign-in shows an "Update Account
	// Information" form that DEMANDS both, with "Please specify this field."
	// under each — the operator cannot reach the platform until they fill in
	// something the installation could have set.
	//
	// `kcadm create users -s key=value` accepts these fields; they were simply
	// not passed. Verified on the live realm: the created account had id,
	// username, email, enabled and emailVerified, and NOTHING else.
	//
	// THE UPDATE PASS IS NOT REDUNDANT: `create users` fails silently on an
	// existing account (its output is discarded, `|| true`), so a realm
	// provisioned by an earlier version would keep its empty names forever.
	// The explicit `update users` repairs those, which is what makes this
	// function correct on a re-install and not only on a fresh machine.
	script := `IFS= read -r motdepasse; IFS= read -r mdpadmin; ` +
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master ` +
		`--user '` + strings.ReplaceAll(utilisateur, "'", `'\''`) + `' --password "$motdepasse" >/dev/null && ` +
		`(/opt/keycloak/bin/kcadm.sh create users -r ceffio ` +
		`-s username=` + compteAdminIdentifiant + ` -s enabled=true -s emailVerified=true ` +
		`-s "email=` + compteAdminEmail + `" ` +
		`-s "firstName=` + compteAdminPrenom + `" -s "lastName=` + compteAdminNom + `" ` +
		`>/dev/null 2>&1 || true) && ` +
		// L'IDENTIFIANT TECHNIQUE DOIT ÊTRE RÉCUPÉRÉ, PAS DEVINÉ : `kcadm
		// update` attend l'UUID, et lui passer le nom d'utilisateur répond
		//
		//	Resource not found for url: .../users/adminceffio
		//
		// Mesuré sur le realm vivant. L'échec était avalé par le `|| true`
		// destiné à rendre l'étape idempotente, donc l'installation annonçait
		// « administrator fields repaired » sans que rien ne soit réparé — le
		// pire des états, puisqu'il décourage d'aller vérifier.
		//
		// On extrait l'id de la réponse JSON, en shell, sans dépendre d'un
		// outil qui pourrait manquer dans l'image Keycloak.
		`id=$(/opt/keycloak/bin/kcadm.sh get users -r ceffio -q username=` + compteAdminIdentifiant +
		` --fields id --format csv --noquotes 2>/dev/null | tr -d "\r" | tail -1) && ` +
		`if [ -n "$id" ]; then ` +
		`/opt/keycloak/bin/kcadm.sh update users/"$id" -r ceffio ` +
		`-s "firstName=` + compteAdminPrenom + `" -s "lastName=` + compteAdminNom + `" ` +
		`-s "email=` + compteAdminEmail + `" -s emailVerified=true -s enabled=true; ` +
		`else echo "administrator id not found in realm ceffio" >&2; exit 1; fi && ` +
		// LE MOT DE PASSE N'EST POSÉ QUE S'IL Y EN A UN.
		//
		// Sur un compte existant, la fonction reçoit le mot de passe DÉJÀ
		// stocké — elle ne le régénère pas. Mais si cette lecture échouait et
		// rendait une chaîne vide, `set-password --new-password ""` EFFACERAIT
		// le mot de passe du compte : l'opérateur se retrouverait sans aucun
		// moyen de se connecter, sur une plateforme pourtant installée.
		//
		// Le test est dans le shell et non en Go, parce que c'est là que la
		// valeur existe.
		`if [ -n "$mdpadmin" ]; then ` +
		`/opt/keycloak/bin/kcadm.sh set-password -r ceffio --username ` + compteAdminIdentifiant +
		` --new-password "$mdpadmin"; fi`

	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-n", ns, "deploy/keycloak", "-c", "keycloak",
		"--", "sh", "-c", script)
	cmd.Stdin = strings.NewReader(motdepasse + "\n" + mdp + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("creating the administrator in Keycloak: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// creerCompteNextcloud creates the local administrator account, so direct
// sign-in keeps working when Keycloak is unavailable.
//
// occ CANNOT SET A PASSWORD WITHOUT ONE, and --password-from-env needs OC_PASS
// exported in the SAME shell — measured, `user:add --password-from-env` with an
// empty OC_PASS answers "--password-from-env given, but NC_PASS/OC_PASS is
// empty!" and creates nothing.
//
// THE admin GROUP IS ADDED AFTER THE PASSWORD, and the order matters: adding a
// member to a group that does not exist yet fails, and the account would then
// exist without its rights — present but powerless, which the interface reports
// as healthy.
func creerCompteNextcloud(ctx context.Context, mdp string) error {
	// ON ATTEND QUE LE POD RÉPONDE, et c'est le point qui a échoué au premier
	// essai : le déploiement peut exister et son pod ne pas être prêt — une
	// image en cours de téléchargement, un init-container en cours. `kubectl
	// exec` répond alors « not found », ce qui laisse croire à un déploiement
	// absent alors que le sujet est un délai.
	//
	// On ne rend PAS cette attente bloquante pour l'installation : elle est
	// bornée, et son échec est rapporté par l'appelant, qui peut le traiter
	// comme non fatal.
	attente := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/nextcloud", "-n", nsFiles, "--timeout=600s")
	if err := attente.Run(); err != nil {
		return fmt.Errorf("Nextcloud not ready: %w", err)
	}

	script := `export OC_PASS=` + shellQuote(mdp) + `; ` +
		`php occ group:add ` + compteAdminGroupe + ` >/dev/null 2>&1 || true; ` +
		`php occ user:add --password-from-env ` + compteAdminIdentifiant + ` >/dev/null 2>&1 || true; ` +
		`php occ group:adduser ` + compteAdminGroupe + ` ` + compteAdminIdentifiant + ` >/dev/null 2>&1 || true; ` +
		`php occ user:info ` + compteAdminIdentifiant + ` >/dev/null 2>&1 || { echo "account absent after creation"; exit 1; }`

	cmd := k8s.Command(ctx, "kubectl", "exec", "-n", nsFiles, "deploy/nextcloud", "-c", "nextcloud",
		"--", "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("creating the administrator in Nextcloud: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureCompteNextcloud creates the local Nextcloud administrator, reading the
// password from the vault.
//
// EXPORTED BECAUSE THE CALLER IS NOT IN THIS PACKAGE, and because the ordering
// constraint lives there: the identity layer runs before Nextcloud exists, so
// this step is driven from the installation sequence, right after the files
// layer. The password is NOT regenerated — it was decided once, when the
// Keycloak account was created, so both doors accept the SAME one.
//
// Idempotent: an existing account is left alone.
func EnsureCompteNextcloud(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	if coffre == nil || !coffre.Dispo() {
		return fmt.Errorf("the vault is required to read the administrator password")
	}
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "sso", "adminceffio")
	if err != nil {
		return fmt.Errorf("administrator password unreadable in the vault: %w", err)
	}
	mdp := entree["password"]
	if mdp == "" {
		return fmt.Errorf("no administrator password in the vault")
	}
	return creerCompteNextcloud(ctx, mdp)
}

// shellQuote wraps a value in single quotes for `sh -c`, escaping any single
// quote inside it.
//
// A PASSWORD CONTAINS PUNCTUATION BY CONSTRUCTION — the generated alphabet
// includes ! @ # $ % & * — and unquoted it would be interpreted by the shell:
// `$` would expand, `!` and `*` would be substituted, and the password APPLIED
// would not be the one DISPLAYED. The operator would then be locked out by a
// password they read correctly.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
