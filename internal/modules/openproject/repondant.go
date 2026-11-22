// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package openproject

import (
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/version"
)

// THE RESPONDER IS THE ONE PIECE OF THE SIGN-IN THAT WAS MISSING.
//
// Header SSO does not stop at "the proxy named a user": auth_source_sso.rb calls
// LdapAuthSource.find_user(login), which opens an LDAP connection to the auth
// source the account is linked to. A source pointing at nothing makes every
// sign-in fail, and the log says only:
//
//	Error during authentication: Connection refused - connect(2) for 127.0.0.1:389
//
// So the module ships the responder: it answers the ONE search OpenProject makes
// (attr_login=<login> AND objectClass=*) with one entry naming that login. It is
// stateless and read-only — no directory, no password, no e-mail — and it is
// reachable from the application pod only.
//
// WHY IT IS A PROCESS OF THE CEFFIO IMAGE and not a deployment of OpenLDAP or
// lldap: a real directory would need a second volume, a backup story, a
// synchronization of Keycloak's users into it, and would still hold no secret to
// check. The lookup needs one answer, built from the query.

// Image is the responder's image: the Ceffio image itself, which carries the
// `ldap-responder` subcommand.
//
// THE SAME REASONING AS THE CAPTURE RELAY AND THE PUBLIC-IP REPORTER: the image is
// already published, pinned by digest, scanned with the rest of the release, and
// present in containerd on an offline machine — a second artefact would add a
// second supply chain for a two-hundred-line responder.
func imageLDAPResponder() string {
	return "ghcr.io/ceffio-suite/ceffio:" + version.ImageTag()
}

// hoteRespondant is the in-cluster address the OpenProject auth source points at.
func hoteRespondant() string { return nomRepondant + "." + nsProjets + ".svc" }

// manifesteRepondant renders the responder: its Deployment, its Service and the
// policy that keeps the lookup private.
//
// NO SERVICE ACCOUNT OF ITS OWN: the responder reads nothing — no secret, no
// vault entry, no Kubernetes object — so it runs under the module's existing
// account, which carries a read-only vault role it never uses.
//
// NO PROBE OTHER THAN TCP, AND NO SHELL: the Ceffio image is FROM scratch, so an
// exec probe has nothing to exec. A TCP probe says the listener is up, which is
// exactly what the lookup needs.
//
// THE POLICY IS PART OF THE SAME ANSWER as the application's: a responder any pod
// could query would be an oracle for "does this login exist" across the cluster.
// What it answers is not a secret — the login comes back in the query — but the
// set of clients that can reach it is still the module's business.
func manifesteRepondant() string {
	return fmt.Sprintf(`apiVersion: apps/v1
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
      # NO INJECTOR ANNOTATION, and none is needed: the pod reads no secret, so
      # it has nothing to be given. The injector only mutates pods that ask for
      # it; this one does not ask.
    spec:
      serviceAccountName: %[3]s
      securityContext:
        runAsNonRoot: true
        runAsUser: %[4]d
        runAsGroup: %[4]d
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: responder
          image: %[5]s
          # THE TAG IS A PIN, NOT A BRANCH: nothing moves under it, so a pull is
          # only ever a first start on a machine that never had the image.
          imagePullPolicy: IfNotPresent
          args: ["ldap-responder", "--listen", ":%[6]d", "--attribute", "uid"]
          ports:
            - name: ldap
              containerPort: %[6]d
          readinessProbe:
            tcpSocket:
              port: ldap
            periodSeconds: 10
          livenessProbe:
            tcpSocket:
              port: ldap
            initialDelaySeconds: 5
            periodSeconds: 20
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              memory: 16Mi
              cpu: 10m
            limits:
              memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
    app.kubernetes.io/part-of: ceffio
spec:
  selector:
    app: %[1]s
  ports:
    - name: ldap
      port: %[6]d
      targetPort: ldap
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %[1]s-only-from-app
  namespace: %[2]s
  labels:
    app.kubernetes.io/part-of: ceffio
spec:
  podSelector:
    matchLabels:
      app: %[1]s
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: %[7]s
      ports:
        - protocol: TCP
          port: %[6]d
`, nomRepondant, nsProjets, nomServiceAccount, uidRepondant, imageLDAPResponder(),
		portRepondant, nomApp)
}
