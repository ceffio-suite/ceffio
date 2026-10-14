// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package talk deploys Nextcloud Talk with its High Performance Backend (HPB).
//
// WHY THIS MODULE: Talk replaces both chat (ex-Synapse/Element) and
// videoconferencing (ex-Jitsi). It is a Nextcloud application — so
// authentication is native (Nextcloud's own, itself wired to Keycloak) and
// there is no authentication bridge left to maintain.
//
// ARCHITECTURE — four services, all in the ceffio-video namespace:
//
//	Talk          Nextcloud app (enabled via "occ app:enable spreed")
//	signaling     coordination: who is there, who joins what (Go, lightweight)
//	Janus         SFU: carries the WebRTC media (it is the one that matters)
//	NATS          messaging between signaling instances (scalability)
//	coturn        TURN relay: indispensable for restrictive networks
//
// Correspondence with the old Jitsi stack, for those who know it:
//
//	Interface        Jitsi Meet      → Talk
//	Coordination     Prosody (XMPP)  → signaling + NATS
//	Media transport  JVB (SFU)       → Janus
//	coturn           integrated      → separate service
//
// ISOLATION: these two suites share NO network resource — no media range, no
// TURN port, no secret. See docs/plan-talk-hpb.md §4bis.
package talk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// Pinned versions. Nothing follows `latest`: a component that follows a moving
// tag can be neither audited nor upgraded reproducibly.
const (
	ns = "ceffio-video"

	// HPB images.
	signalingImage = "docker.io/strukturag/nextcloud-spreed-signaling:2.1.1"
	natsImage      = "docker.io/library/nats:2.15"
	coturnImage    = "docker.io/coturn/coturn:4.18"

	// STUN server in charge of discovering the public address Janus must
	// announce, when it is not provided at deploy time.
	//
	// PUBLIC, imperatively: a local-network server (coturn, for example)
	// sees the request arrive from the inside and answers with the PRIVATE
	// address — measured: "Our public address is <cluster-ip>". The
	// detection then "succeeds" by announcing an address unreachable from
	// the Internet.
	//
	// The image's entrypoint resolves this name to IPv4 before writing it
	// into the configuration: left as a hostname, Janus resolves it to IPv6
	// on a dual-stack machine and only announces an IPv6 address.
	stunPublic = "stun.l.google.com"
	stunPort   = 19302

	// Network — ports DEDICATED to Ceffio, with no overlap with the other RTC
	// suites on the network (which occupy 50000-60000, 30000-40000 and 3478).
	plageMediaDebut = 20000
	plageMediaFin   = 20100 // 100 ports: plenty for an SMB
	portTurn        = 3479  // 3478 = other RTC suite, do not touch it
	portTurnTLS     = 5349
	portSignaling   = 8081 // internal HTTP of the signaling server
	portJanusAPI    = 8088 // Janus HTTP API (used by the signaling)
	portJanusWS     = 8188 // Janus WebSocket transport
)

// The Janus image is READ FROM THE VERSION REGISTRY, not duplicated here.
// It was duplicated, and the two copies had drifted (1.3.0-1 in the registry,
// 1.4.0-1 here): `upgrade --plan` compared against a version that was not the
// one deployed. The registry is the single source of truth. It is a var, not a
// const: its value comes from a function call (registry lookup) evaluated at
// package init.
var janusImage = janusImageDuRegistre()

// Deploy installs Talk + HPB, idempotently.
//
// NO PUBLIC ADDRESS IS ASKED FOR, and this is deliberate: it is needed in
// three places (Janus's ICE candidates, the coturn relay's, and the TURN
// address the signaling hands to browsers), but none of them needs it to be
// provided.
//
//   - Janus and coturn discover it themselves at startup, via STUN, with the
//     client present in their respective images;
//   - the signaling announces a public NAME (talk.<domain>), which survives
//     an address change where a frozen value would stop working silently.
//
// A parameter to know BEFORE deploying was a useless dependency, and a
// hardcoded value in the installation is a deferred outage.
func Deploy(ctx context.Context) error {
	fmt.Println("\nDeploying Talk + High Performance Backend (Phase 10)...")

	// 1. Secrets first: the Deployments reference them.
	if err := ensureSecrets(ctx); err != nil {
		return err
	}
	if err := deployServiceAccount(ctx); err != nil {
		return err
	}
	if err := deployNATS(ctx); err != nil {
		return err
	}
	// coturn BEFORE Janus: Janus references it as its STUN/TURN server.
	if err := deployCoturn(ctx); err != nil {
		return err
	}
	if err := ensurePullSecret(ctx); err != nil {
		return err
	}
	if err := deployJanus(ctx); err != nil {
		return err
	}
	if err := deploySignaling(ctx); err != nil {
		return err
	}
	// 2. Wire Nextcloud to the HPB (via occ, never by hand).
	if err := brancherNextcloud(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Talk + HPB deployed (messaging and videoconferencing in Nextcloud)")
	return nil
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// ensureSecrets guarantees the HPB secrets IN THE VAULT, AND NOWHERE ELSE.
//
// They are NEVER in the manifests nor in Git. Since the vault became the
// single source, they are no longer in a Kubernetes Secret either: the two
// workloads that consume them — coturn and the signaling — read them through
// their agent at startup. A value copied to two places ends up diverging, and
// the divergence is paid at the moment the service no longer understands its
// own data.
func ensureSecrets(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()

	donnees := map[string]string{}
	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "talk", "signaling")
	switch {
	case err == nil:
		donnees = existant
	case secrets.EntreeAbsente(err):
		// First install: the generation below takes care of it.
	default:
		// An unreachable vault is not a reason to fabricate new values: the
		// connected clients would keep using the old ones, and nothing would
		// understand anything anymore.
		return fmt.Errorf("vault unreadable for talk/signaling: %w", err)
	}

	for _, a := range []struct {
		cle      string
		longueur int
	}{
		{"hash-key", 32},
		{"block-key", 16},
		{"partage", 32},
		{"turn-secret", 32},
	} {
		if donnees[a.cle] != "" {
			continue
		}
		g, err := genSecret(a.longueur)
		if err != nil {
			return err
		}
		donnees[a.cle] = g
		fmt.Printf("∙ Talk secret %q generated (absent from the vault)\n", a.cle)
	}
	return secrets.EcrireDansCoffre(ctx, coffre, "talk", "signaling", donnees)
}

// ---------------------------------------------------------------------------
// Vault agent
// ---------------------------------------------------------------------------

// deployServiceAccount lays down what is common to the two workloads that read
// the vault: the ServiceAccount the vault validates, and the agent's
// configuration.
//
// WHY A SINGLE CONFIGURATION FOR TWO WORKLOADS: coturn and the signaling read
// the SAME vault entry, so their templates are identical. A duplicated file
// would end up diverging from the other — and the divergence, here, would
// make the signaling and Nextcloud no longer share the same secret.
func deployServiceAccount(ctx context.Context) error {
	manifeste := fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: talk
  namespace: %[1]s
`, ns)
	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// NATS
// ---------------------------------------------------------------------------

func deployNATS(ctx context.Context) error {
	fmt.Println("∙ NATS " + natsImage + " (signaling coordination)")
	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: nats
  namespace: %[1]s
  labels: {app: nats}
spec:
  replicas: 1
  selector: {matchLabels: {app: nats}}
  template:
    metadata: {labels: {app: nats}}
    spec:
      containers:
      - name: nats
        image: %[2]s
        ports:
        - {name: client, containerPort: 4222}
        resources: {limits: {memory: 256Mi, cpu: 500m}}
---
apiVersion: v1
kind: Service
metadata:
  name: nats
  namespace: %[1]s
spec:
  selector: {app: nats}
  ports:
  - {name: client, port: 4222, targetPort: 4222}
`, ns, natsImage)
	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// coturn
// ---------------------------------------------------------------------------

// deployCoturn deploys the TURN relay.
//
// It serves TWO things:
//  1. media relay for users whose network blocks direct UDP (corporate 4G,
//     hotel networks) — without it, they have no path;
//  2. STUN server for Janus, which can then discover its public address on
//     its own (automatic detection, to enable).
//
// The authentication secret is shared with the signaling server, which
// generates the temporary TURN credentials for the clients.
func deployCoturn(ctx context.Context) error {
	fmt.Println("∙ coturn " + coturnImage + " (TURN relay, port " + fmt.Sprint(portTurn) + ")")

	// THE PUBLIC ADDRESS IS DISCOVERED AT STARTUP, NEVER FROZEN.
	//
	// coturn must announce an address reachable from the Internet in its
	// relay candidates (--external-ip option). Without it, it announces its
	// own, private one — measured: "UDP reflexive addr: <cluster-ip>" — and
	// a participant behind a restrictive NAT receives an address they cannot
	// reach, exactly in the case where the relay is useful.
	//
	// But this address must NOT be in the installation: it changes (ISP,
	// move) and a deployment carrying it in hard stops working silently the
	// day it changes. No infrastructure value enters the repository.
	//
	// coturn therefore discovers it itself at startup, with the STUN client
	// present in its image, against the same server as the one given to
	// Janus — a single source of truth for the whole platform.
	//
	// If the detection fails (filtered UDP), the option is simply omitted:
	// the relay then only serves inside the network, which is better than an
	// invented address — and the warning is explicit in the logs.
	// No command substitution nor braces in this script: Kubernetes
	// interprets $(...) and ${...} in a container's arguments, which would
	// damage the script. We only use simple variables and a redirection to a
	// temporary file.
	script := fmt.Sprintf(`turnutils_stunclient -p %[1]d %[2]s 2>&1 \
    | sed -n 's/.*UDP reflexive addr: \([0-9.]*\):.*/\1/p' \
    | head -1 > /tmp/public-address.txt || true

ADDRESS=""
read ADDRESS < /tmp/public-address.txt || true
EXTERNAL_ARG=""
if [ -n "$ADDRESS" ]; then
    EXTERNAL_ARG="--external-ip=$ADDRESS"
    echo "coturn: public address detected = $ADDRESS"
else
    echo "coturn: WARNING - public address not detected (STUN %[2]s:%[1]d unreachable)." >&2
    echo "coturn: relay candidates will carry the private address;" >&2
    echo "coturn: the relay will only serve inside the network." >&2
fi

exec turnserver \
    --realm=%[3]s \
    --use-auth-secret \
    --static-auth-secret="$TURN_SECRET" \
    --lt-cred-mech \
    --fingerprint \
    --no-software-attribute \
    --no-multicast-peers \
    --no-stdout-log \
    --log-file=stdout \
    --stale-nonce=600 \
    --min-port=49152 \
    --max-port=49200 \
    --listening-port=%[4]d \
    $EXTERNAL_ARG
`, stunPort, stunPublic, "talk."+domaineDe(ctx), portTurn)

	// THE SECRETS ARE SET BY THE OPENBAO INJECTOR: coturn only needs the TURN
	// secret, the one Nextcloud also holds.
	annCoturn := vault.AnnotationsAgent(8, "talk", "kv/data/ceffio/talk/signaling",
		vault.GabaritExports("kv/data/ceffio/talk/signaling",
			[2]string{"TURN_SECRET", vault.ChampCoffre("turn-secret")},
		))

	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: coturn
  namespace: %[1]s
  labels: {app: coturn}
spec:
  # Recreate: same reason as Janus — hostNetwork pod, hence the host's ports
  # are occupied. See the detailed comment on the Janus deployment.
  strategy: {type: Recreate}
  replicas: 1
  selector: {matchLabels: {app: coturn}}
  template:
    metadata:
      labels: {app: coturn}
      # THE SECRETS ARE SET BY THE OPENBAO INJECTOR.
      annotations:
%[6]s
    spec:
      # hostNetwork: same reason as Janus — the TURN relay range
      # (49152-49200) cannot be expressed as a NodePort, which only accepts a
      # single port. The pod therefore listens directly on the VM's IP.
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      # IT IS THIS ServiceAccount THAT THE VAULT ROLE DESIGNATES.
      serviceAccountName: talk
      containers:
      - name: coturn
        image: %[2]s
        # Startup wrapper: it loads the secrets rendered by the agent,
        # discovers the public address, then passes it on to coturn.
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
%[3]s
        ports:
        - {name: turn, containerPort: %[4]d, protocol: UDP}
        - {name: turn-tcp, containerPort: %[4]d, protocol: TCP}
        - {name: turns, containerPort: %[5]d, protocol: TCP}
        resources: {limits: {memory: 1Gi, cpu: "1"}}
---
# NodePort, NOT ClusterIP: these ports must be reachable from the Internet,
# via the firewall's redirection rules toward the VM's IP. A ClusterIP only
# listens on k3s's internal network — the packets arrive at the VM and no one
# takes them (symptom: everything is "Running", nothing goes through).
apiVersion: v1
kind: Service
metadata:
  name: coturn
  namespace: %[1]s
spec:
  selector: {app: coturn}
  ports:
  - {name: turn, port: %[4]d, targetPort: %[4]d, protocol: UDP}
  - {name: turn-tcp, port: %[4]d, targetPort: %[4]d, protocol: TCP}
  - {name: turns, port: %[5]d, targetPort: %[5]d, protocol: TCP}
`, ns, coturnImage, indentYaml(script, 10), portTurn, portTurnTLS, annCoturn)
	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// Janus
// ---------------------------------------------------------------------------

// ensurePullSecret creates the authentication secret to pull the Janus image
// from GHCR.
//
// WHY A PULL SECRET: the Janus image is published on GHCR (private
// repository). Kubernetes cannot pull it without credentials. We prefer a
// pull secret to making the image public: the image concerns no one, and the
// deployer keeps control of who can fetch it.
//
// The token is provided via an environment variable at deploy time
// (GHCR_TOKEN) — it is NEVER written in the code nor in a manifest.
func ensurePullSecret(ctx context.Context) error {
	// THE SECRET'S EXISTENCE IS CHECKED BEFORE THE TOKEN, not after.
	//
	// Otherwise any re-run without the environment variable fails, while the
	// secret is already in place and sufficient — and the failure cuts the
	// deployment at this spot: the following components are never applied,
	// without anything saying so. That is exactly what happened to Talk's
	// signaling.
	if secretExiste(ctx, "ghcr-pull") {
		return nil
	}
	// ghcr.io/ceffio-suite/janus-gateway is PUBLIC since 2026-10-14: anonymous
	// pulls succeed (verified from the cluster: crictl pull with no
	// credentials returns a manifest). The token path below is kept as a
	// fallback for private forks and air-gapped mirrors, where the image is
	// republished under a different name.
	token := os.Getenv("GHCR_TOKEN")
	if token == "" {
		return fmt.Errorf("GHCR_TOKEN missing: the Janus image is on GHCR (private) and " +
			"the cluster must be able to pull it. Provide a token with read:packages")
	}
	fmt.Println("∙ GHCR pull secret created")

	// The .dockerconfigjson file Kubernetes expects.
	auth := base64.StdEncoding.EncodeToString([]byte("ceffio-suite:" + token))
	cfg := fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":%q}}}`, auth)

	manifeste := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: ghcr-pull
  namespace: %s
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: %s
`, ns, base64.StdEncoding.EncodeToString([]byte(cfg)))

	return appliquer(ctx, manifeste)
}

// deployJanus deploys the SFU.
//
// This is the component that CARRIES the media: each participant sends their
// stream once, Janus redistributes it to everyone. Without it, Talk caps at
// ~4-6 participants (direct connections between browsers).
func deployJanus(ctx context.Context) error {
	fmt.Printf("∙ Janus %s (SFU, UDP media %d-%d)\n", janusImage, plageMediaDebut, plageMediaFin)

	// THE PUBLIC ADDRESS IS DISCOVERED BY JANUS ITSELF, AT STARTUP.
	//
	// Janus must announce to the browsers an address they can reach. Behind a
	// NAT its interfaces are private: if it announces them as-is in the ICE
	// candidates, the media never gets through from the Internet.
	//
	// It is NOT provided at deploy time: a parameter to know before deploying
	// is a dependency, and a hardcoded value stops working silently the day
	// the ISP changes the address. Janus therefore queries a PUBLIC STUN
	// server at startup and announces the address it deduces from it.
	//
	// The STUN server MUST be reachable from the Internet. Pointed at coturn,
	// which runs on the same network, it returns the PRIVATE address —
	// measured: "Our public address is <cluster-ip>". The detection then
	// "succeeds" by announcing an unreachable address, which is worse than a
	// clean failure.
	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: janus
  namespace: %[1]s
  labels: {app: janus}
spec:
  # Recreate, NOT RollingUpdate. The pod is on hostNetwork: it occupies the
  # VM's ports (media 20000-20100, API 8088, WS 8188). A progressive deploy
  # is then IMPOSSIBLE — the new pod cannot start while the old one holds
  # those ports, and the old one is only removed once the new one is ready.
  # Measured: "FailedScheduling: 1 node(s) didn't have free ports for the
  # requested pod ports", deployment blocked indefinitely.
  strategy: {type: Recreate}
  replicas: 1
  selector: {matchLabels: {app: janus}}
  template:
    metadata: {labels: {app: janus}}
    spec:
      # hostNetwork: the pod goes out directly on the VM's IP, without going
      # through kube-proxy. Indispensable for the MEDIA: a NodePort Service
      # can only expose ONE port, not a range of 101 ports. WebRTC media
      # needs the whole 20000-20100 range open end to end, and the firewall
      # redirects toward the VM's IP — so the pod must listen on that IP.
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      imagePullSecrets:
      - name: ghcr-pull
      containers:
      - name: janus
        image: %[2]s
        env:
        - {name: JANUS_RTP_PORT_RANGE, value: "%[4]d-%[5]d"}
        # PUBLIC STUN server: source of the public address announced to the
        # browsers. The entrypoint resolves it to IPv4 (a hostname resolved
        # to IPv6 would make it announce an IPv6 address, unreachable in
        # IPv4).
        - {name: JANUS_STUN_SERVER, value: %[7]q}
        - {name: JANUS_STUN_PORT, value: "%[8]d"}
        ports:
        - {name: api, containerPort: 8088, protocol: TCP}
        - {name: ws, containerPort: 8188, protocol: TCP}
        resources: {limits: {memory: 2Gi, cpu: "2"}}
---
# NodePort for the WHOLE media range: it is the video stream itself that goes
# through here. The signaling tells the browsers about these ports (via the
# announced public address), which must therefore be open end to end —
# firewall AND Kubernetes.
apiVersion: v1
kind: Service
metadata:
  name: janus
  namespace: %[1]s
spec:
  selector: {app: janus}
  ports:
  - {name: api, port: 8088, targetPort: 8088, protocol: TCP}
  - {name: ws, port: 8188, targetPort: 8188, protocol: TCP}
`, ns, janusImage, "", plageMediaDebut, plageMediaFin, portTurn, stunPublic, stunPort)
	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// Signaling server
// ---------------------------------------------------------------------------

// turnURL builds the list of TURN servers handed TO THE BROWSERS by the
// signaling server.
//
// The address must be reachable from the Internet, otherwise the relay is
// unusable. We give a public NAME rather than an address: it survives a
// public-address change, and it is the same as the one declared on the
// Nextcloud side. This is the only place where the public address appears,
// and it appears there as a name, never as a frozen value.
func turnURL(domaine string) string {
	hote := "talk." + domaine
	udp := fmt.Sprintf("turn:%s:%d?transport=udp", hote, portTurn)
	tcp := fmt.Sprintf("turn:%s:%d?transport=tcp", hote, portTurn)
	return udp + "," + tcp
}

// deploySignaling deploys the signaling server.
//
// Role: tell the participants who is present and where to connect. It carries
// NO media — it is a metadata router, very lightweight. It is the equivalent
// of Prosody in the Jitsi stack, with NATS for the coordination.
//
// Two settings condition whether calls actually WORK: the backend section
// (without it, no client connection is accepted) and the TURN address handed
// to the browsers (without it, the relay is unreachable from the Internet).
// See the comments in the configuration.
func deploySignaling(ctx context.Context) error {
	fmt.Println("∙ signaling " + signalingImage + " (coordination, goes through Janus)")

	// Configuration: the signaling knows Janus, NATS, and the secret shared
	// with Nextcloud (which calls it to authenticate the sessions).
	// Signaling configuration. The structure is NOT guessable: it was recorded
	// from the upstream repo's server.conf.in, after a first version written
	// from memory failed at startup ("hash key is not set").
	//
	// The three errors avoided here:
	//   - hashkey/blockkey go in [sessions], NOT in [clients];
	//   - the app secret is called internalsecret ([clients]), and the backend
	//     name is declared in [backend] backends=... ;
	//   - there is NO [backend.<name>] section in static mode — that is an
	//     etcd-mode setting.
	config := fmt.Sprintf(`[http]
listen = 0.0.0.0:%[1]d

[app]
debug = false

# Session keys: 32 bytes required (the server refuses to start otherwise,
# with an explicit message "hash key should be 32 or 64 bytes").
[sessions]
hashkey = $(HASH_KEY)
blockkey = $(BLOCK_KEY)

# Secret shared with Nextcloud: IT is the one that authenticates the requests
# between the Nextcloud instance and this server. Must be identical on both
# sides.
[clients]
internalsecret = $(SHARED_SECRET)

# Coordination between instances (only one here, but NATS is required).
[nats]
url = nats://nats:4222

# The SFU: Janus, joined over WebSocket.
[mcu]
type = janus
url = ws://janus:8188

# Backend: the Nextcloud instance that calls us.
[backend]
backends = nextcloud
allowall = false
secret = $(SHARED_SECRET)

# THE BACKEND ITSELF — WITHOUT THIS SECTION, NO CLIENT CAN CONNECT.
#
# The section name must match EXACTLY an identifier listed in "backends"
# above. Its absence produces no fatal error: the server starts, serves its
# pages, accepts requests — and silently refuses any client connection:
#
#   backend_storage_static.go:116: WARNING: No backends configured,
#     client connections will not be possible.
#
# The symptom is misleading: the caller believes it is a media problem (TURN,
# ICE) while the server accepts no session. Nextcloud's logs, on their side,
# stay perfectly normal — both clients exchange presence and messages, only
# the media never establishes.
[nextcloud]
urls = https://cloud.%[3]s

# TURN relay, with temporary credentials generated by this server.
#
# THE ADDRESS HERE IS THE ONE THE BROWSERS WILL CONTACT. It must therefore be
# reachable from the Internet. A cluster-internal name ("coturn") does NOT
# resolve in the browser: the relay would then be unusable in the only case
# where it serves — the participant behind a restrictive NAT.
#
# We use the platform's public name rather than the IP address: it stays
# valid if the public address changes. It is the SAME name as the one
# declared on the Nextcloud side for its own TURN servers.
[turn]
apikey = $(SHARED_SECRET)
secret = $(TURN_SECRET)
servers = %[2]s
`, portSignaling, turnURL(domaineDe(ctx)), domaineDe(ctx))

	annSignaling := vault.AnnotationsAgent(8, "talk", "kv/data/ceffio/talk/signaling",
		vault.GabaritExports("kv/data/ceffio/talk/signaling",
			[2]string{"HASH_KEY", vault.ChampCoffre("hash-key")},
			[2]string{"BLOCK_KEY", vault.ChampCoffre("block-key")},
			[2]string{"SHARED_SECRET", vault.ChampCoffre("partage")},
			[2]string{"TURN_SECRET", vault.ChampCoffre("turn-secret")},
		))

	manifeste := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: talk-signaling-config
  namespace: %[1]s
data:
  server.conf: |
%[2]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: talk-signaling
  namespace: %[1]s
  labels: {app: talk-signaling}
spec:
  replicas: 1
  selector: {matchLabels: {app: talk-signaling}}
  template:
    metadata:
      labels: {app: talk-signaling}
      # THE SECRETS ARE SET BY THE OPENBAO INJECTOR.
      annotations:
%[5]s
    spec:
      # IT IS THIS ServiceAccount THAT THE VAULT ROLE DESIGNATES.
      serviceAccountName: talk
      containers:
      - name: signaling
        image: %[3]s
        # The rendered file is loaded BEFORE the server: the signaling refuses
        # to start without its session keys ("hash key is not set"), so a
        # missing secret is visible right away.
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
          exec /usr/bin/nextcloud-spreed-signaling -config /config/server.conf
        volumeMounts:
        - {name: config, mountPath: /config}
        ports:
        - {name: http, containerPort: %[4]d, protocol: TCP}
        resources: {limits: {memory: 512Mi, cpu: 500m}}
      volumes:
      - name: config
        configMap: {name: talk-signaling-config}
---
apiVersion: v1
kind: Service
metadata:
  name: talk-signaling
  namespace: %[1]s
spec:
  selector: {app: talk-signaling}
  ports:
  - {name: http, port: %[4]d, targetPort: %[4]d, protocol: TCP}
`, ns, indentYaml(config, 4), signalingImage, portSignaling, annSignaling)

	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// Nextcloud wiring
// ---------------------------------------------------------------------------

// brancherNextcloud enables the Talk app and wires it to the HPB.
//
// EVERYTHING GOES THROUGH "occ": never a manual change in the database,
// never a hand-edited configuration file. It is the only way to obtain a
// state Nextcloud considers coherent.
func brancherNextcloud(ctx context.Context) error {
	fmt.Println("∙ enabling Talk + wiring to the HPB")

	// 1. Install then enable the app (idempotent: "install" fails if
	//    already present, we ignore it; "enable" has no effect if already
	//    enabled).
	_ = occ(ctx, "app:install", "spreed")
	if err := occ(ctx, "app:enable", "spreed"); err != nil {
		return fmt.Errorf("enabling Talk: %w", err)
	}

	// 2. Declare the external signaling server. Without this step, Talk runs
	//    in direct connections (~4-6 participants) and ignores the HPB.
	url := fmt.Sprintf("https://spreed.%s/standalone-signaling", domaineDe(ctx))
	if err := occ(ctx, "config:app:set", "spreed", "signaling_server_url", "--value", url); err != nil {
		return fmt.Errorf("signaling URL: %w", err)
	}

	// 3. The signaling secrets, READ FROM THE VAULT — single source since the
	//    Kubernetes Secrets disappeared. The signaling reads the same entry
	//    through its agent: the two sides cannot diverge.
	entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), "talk", "signaling")
	if err != nil {
		return fmt.Errorf("Talk secrets unreadable in the vault: %w", err)
	}
	secret := entree["partage"]
	if secret == "" {
		return fmt.Errorf("shared secret missing from the vault's talk/signaling entry")
	}
	if err := occ(ctx, "config:app:set", "spreed", "signaling_server_secret", "--value", secret); err != nil {
		return fmt.Errorf("signaling secret: %w", err)
	}

	// 4. Declare the TURN servers (native, no external dependency).
	serveurs := fmt.Sprintf("turn:talk.%s:%d?transport=udp,turn:talk.%s:%d?transport=tcp",
		domaineDe(ctx), portTurn, domaineDe(ctx), portTurn)
	if err := occ(ctx, "config:app:set", "spreed", "turn_servers", "--value", serveurs); err != nil {
		return fmt.Errorf("TURN servers: %w", err)
	}
	turnSecret := entree["turn-secret"]
	if turnSecret == "" {
		return fmt.Errorf("TURN secret missing from the vault's talk/signaling entry")
	}
	if err := occ(ctx, "config:app:set", "spreed", "turn_secret", "--value", turnSecret); err != nil {
		return fmt.Errorf("TURN secret: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// occ runs an occ command in the Nextcloud pod.
func occ(ctx context.Context, args ...string) error {
	complet := append([]string{"exec", "-n", "ceffio-files", "deploy/nextcloud", "-c", "nextcloud", "--",
		"php", "occ"}, args...)
	cmd := k8s.Command(ctx, "kubectl", complet...)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// domaineDe infers the deployment domain from the existing ingresses.
//
// We do not pass it as a parameter: the only host with authority is the one
// actually configured in the cluster. Reading the ingress avoids duplicating
// information that could diverge.
func domaineDe(ctx context.Context) string {
	cmd := k8s.Command(ctx, "kubectl", "get", "ingress", "-n", "ceffio-files", "cloud",
		"-o", "jsonpath={.spec.rules[0].host}")
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	if err != nil {
		return "ceffio.local"
	}
	h := strings.TrimSpace(string(out))
	if i := strings.Index(h, "."); i > 0 {
		return h[i+1:]
	}
	return h
}

func appliquer(ctx context.Context, manifeste string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(manifeste)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func secretExiste(ctx context.Context, nom string) bool {
	cmd := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", ns)
	cmd.Env = k8s.Env()
	return cmd.Run() == nil
}

func lireSecret(ctx context.Context, nom, cle string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", ns,
		"-o", "jsonpath={.data."+cle+"}")
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("reading secret %s/%s: %w", nom, cle, err)
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

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

// indentYaml indents a text block to insert it into a YAML ConfigMap.
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

// janusImageDuRegistre returns the Janus image as declared in the version
// registry — the single source of truth shared with `ceffio status` and
// `ceffio upgrade --plan`.
//
// It PANICS on a missing or unqualified entry, deliberately: the registry is
// checked by TestOpenBaoDeclare-style tests, and a deployment silently using
// an empty image string would fail much later, much more obscurely.
func janusImageDuRegistre() string {
	c, ok := version.ParNom("janus")
	if !ok || c.Image == "" {
		panic("janus is missing from the version registry (internal/version)")
	}
	return c.Image
}
