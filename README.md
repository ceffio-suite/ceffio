<p align="center">
  <img src="assets/ceffio-banner-1280.png" alt="Ceffio — logo" width="100%">
</p>

<p align="center">
  <a href="https://github.com/ceffio-suite/ceffio/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ceffio-suite/ceffio/ci.yml?branch=main&label=CI&logo=github" alt="CI status (main)"></a>
  <a href="https://github.com/ceffio-suite/ceffio/releases/latest"><img src="https://img.shields.io/github/v/release/ceffio-suite/ceffio?logo=github" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/ceffio-suite/ceffio?color=blue" alt="Apache-2.0 license"></a>
  <a href="https://github.com/ceffio-suite/ceffio/blob/main/go.mod"><img src="https://img.shields.io/badge/Go-1.27-00ADD8?logo=go" alt="Go 1.27"></a>
  <a href="https://github.com/ceffio-suite/ceffio/graphs/contributors"><img src="https://img.shields.io/github/contributors/ceffio-suite/ceffio" alt="Contributors"></a>
  <a href="https://goreportcard.com/report/github.com/ceffio-suite/ceffio"><img src="https://goreportcard.com/badge/github.com/ceffio-suite/ceffio" alt="Go Report Card"></a>
</p>

Your **sovereign collaborative suite**: open source, self-hosted.

Ceffio replaces Microsoft 365 / Teams for a company, an administration, or an
organisation — SSO identity, files, collaborative documents, mail and
videoconferencing — deployed on Kubernetes **with a single command**, with no
subscription and no dependency on a third-party service.

```bash
curl -fsSL https://raw.githubusercontent.com/ceffio-suite/ceffio/main/installer/install.sh \
  | sh -s -- install --domain example.com
```

Or build from sources:

```bash
git clone https://github.com/ceffio-suite/ceffio.git
cd ceffio && make build
sudo ./bin/ceffio install --domain example.com
```

> "Ceffio" is an anagram of "office".

## What Ceffio is (and is not)

Ceffio **is not a fork** of those applications. It is a **unified integration
layer** — installation, configuration, SSO, provisioning, lifecycle, security,
monitoring, backup/restore, upgrades, air-gap — built around proven open
source projects:

| Domain       | Component                          |
|--------------|------------------------------------|
| Identity/SSO | Keycloak                           |
| Files        | Nextcloud                          |
| Chat         | Nextcloud Talk                     |
| Video        | Nextcloud Talk + Janus (HPB)       |
| Office       | ONLYOFFICE                         |
| Mail         | Stalwart                           |
| Data         | PostgreSQL (CloudNativePG) + Redis |
| Secrets      | OpenBao                            |
| Ingress/TLS  | Traefik + cert-manager             |
| Console      | Ceffio administration console      |

The product promise is that all of this is **self-supporting in one command**:
SSO works across every app from the start, credentials are generated and
sealed in the vault — never asked for in a prompt, never left in a file.

### Why Talk instead of Element + Jitsi

An earlier version of Ceffio assembled **Matrix (Synapse + Element)** for chat
and **Jitsi** for video. That stack was **removed**, for three reasons:

1. **Two authentication systems to synchronise.** Matrix and Jitsi each have
   their own; they had to be wired to Keycloak through dedicated bridges
   (OpenID tokens, a user-verification service). Every bridge is a failure
   source, and one misconfigured authentication loop is enough to make video
   unusable.
2. **A double operational surface** for the administrator: two stacks, two
   lifecycles, two backup sets.
3. **Talk is native to Nextcloud**: its authentication is Nextcloud's, itself
   wired to Keycloak. There is no bridge left to maintain, and chat and video
   live in the same tool as the files.

That choice is what makes the product genuinely "self-supporting in one
command": fewer moving parts, therefore fewer things to break.

## Architecture

```
ceffio CLI  +  administration console
      │
  Ceffio Operator
      │
  Kubernetes API  →  Helm  →  upstream applications
```

The brain of the product is: **Go CLI + Operator + Helm + CRDs**. Shell is
used only for bootstrapping.

## The layers

Each layer is a Go package that deploys and configures one part of the stack.
This decomposition is what makes upgrading possible: every layer knows what it
runs, so before and after can be compared.

| Layer | Package | Contents |
|---|---|---|
| Platform | `internal/platform` | K3s, Ingress, cert-manager |
| Data | `internal/data` | CloudNativePG, PostgreSQL, Redis |
| Identity | `internal/identity` | Keycloak, realm, OIDC clients |
| Files | `internal/files` | Nextcloud |
| Office | `internal/office` | ONLYOFFICE + Nextcloud connector |
| Mail | `internal/mail` | Stalwart |
| **Talk + HPB** | `internal/talk` | Janus (SFU), signaling, coturn, NATS |
| Secrets | `internal/vault` | OpenBao + injector |
| Console | `internal/console` | Administration console |
| Ingress | `internal/ingress` | Routes and certificates |

### Talk's High Performance Backend

Talk works alone up to roughly 4–6 participants, in direct
browser-to-browser connections. Beyond that you need a **SFU**: a server that
receives each stream once and redistributes it to everyone. That is this
fourth component's role.

    Talk (Nextcloud app)   interface, chat, room management
    signaling              who is present, who joins what
    Janus                  media transport (the SFU)
    NATS                   coordination between signaling instances
    coturn                 TURN/STUN relay

Two design points that required correction under real conditions:

- **`hostNetwork` on Janus and coturn.** A Kubernetes `NodePort` Service can
  expose only **one** port, never a range — while WebRTC media needs a whole
  open range end to end. Without `hostNetwork`, everything reports "Running"
  and nothing flows.
- **The public address must be announced.** Behind NAT, a Janus that announces
  its private addresses in the ICE candidates produces a black screen: the
  browser cannot reach it. The public address is **discovered automatically**,
  never supplied at deployment: Janus and the TURN relay obtain it themselves
  at startup via STUN, and the signaling server announces a public name
  (`talk.<domain>`), which survives an address change — where a hard-coded
  value would silently stop working.

## Installation

The deployment is **idempotent**: running it again breaks nothing, it updates
what needs updating. That is what makes a reinstall after an incident safe.

Prerequisites:

- A Linux host with root access (Ceffio installs K3s itself)
- Go 1.27+ only when building from sources
- Media ports reachable from the Internet **and** forwarded: see "Media and
  firewall" below

## The CLI

| Command | Role |
|---|---|
| `ceffio install` | deploy the full stack |
| `ceffio status` | state of the deployed services |
| `ceffio doctor` | diagnostics (prerequisites, coherence, health) |
| `ceffio backup` | backup (databases, secrets, volumes) |
| `ceffio restore` | restore from a backup |
| `ceffio upgrade --plan` | show what would change, before changing it |
| `ceffio users` | provision accounts (Keycloak + applications) |
| `ceffio console` | administration console |
| `ceffio vault` | the secrets vault (OpenBao) |
| `ceffio dns` | check DNS configuration (A, AAAA, MX, SPF, DKIM, DMARC, PTR) |
| `ceffio expose` | publish the suite behind the firewall |
| `ceffio uninstall` | uninstall and destroy the cluster |

## Secrets: the vault is the only source

All application credentials (database passwords, admin accounts, OIDC client
secrets, JWT signing keys) live in **OpenBao**, deployed by `ceffio install`
itself. Pods read their secrets **at startup** through the OpenBao agent
injector; no application credential exists as a Kubernetes Secret anymore.
Rotation happens in one place, and the administration console reads and
rotates through the same vault. Human logins go through OIDC (Keycloak);
services authenticate to the vault through Kubernetes auth — two doors, never
a shared token in a file.

## The administration console

A web interface for daily operations: service states, certificates with their
expiry dates, SSO account management. It reads the cluster's real state — it
does not guess it. See [`internal/console/README.md`](internal/console/README.md)
and the image repository
[`ceffio-suite/ceffio-console`](https://github.com/ceffio-suite/ceffio-console).

## Media and firewall

This is the part most often gotten wrong, because it depends on the network
topology rather than on the code. Three families of ports must be reachable
**from the Internet**:

| Ports | Protocol | Role |
|---|---|---|
| `20000-20100` | UDP | Janus media (the video itself) |
| `3479` | UDP + TCP | TURN relay — essential on restrictive networks |
| `5349` | TCP | TURN secured (fallback when UDP is blocked) |

These ranges are **specific to Ceffio**: they do not overlap another LiveKit
or Janus instance on the same network, so a failure of one does not affect
the other.

Two verified pitfalls:

- **On a firewall that handles ranges, leave the internal port empty.** pf
  (OpenBSD/OPNsense) reads `rdr-to IP port N` as "map everything onto N":
  filling that field with a single port silently collapses the whole range
  onto it, while still reporting "saved".
- **Forward from the right device.** If the VM sits behind a router which in
  turn sits behind the ISP box, rules placed on the router cannot work: they
  belong on the box. Always test from the Internet, never from the local
  network — an internal test proves nothing.

## Releases

Every release is a Git tag plus a GitHub Release carrying the linux/amd64 and
linux/arm64 binaries and their SHA-256 checksums. The `release.yml` workflow
builds and publishes them — but only after the CI of the tagged commit is
green. Grab the current one from the
[releases page](https://github.com/ceffio-suite/ceffio/releases/latest) and
verify before running:

```bash
sha256sum -c --ignore-missing checksums.txt
```

## Development

Development happens on `develop`; features arrive by pull request, and `main`
only ever holds a releasable state. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the full GitFlow, the release process, and the engineering rules this
codebase follows.

```bash
make build            # build ./bin/ceffio
./bin/ceffio --help   # list of commands
make test             # tests
make vet              # static analysis
gofmt -l .            # must print nothing
```

## Status

The product is **deployed and working**: Nextcloud, ONLYOFFICE, Keycloak,
Stalwart (mail), Talk with its High Performance Backend (audio and video
calls validated between two participants), the administration console,
backup/restore, and the OpenBao vault.

Open points, stated plainly:

- **Mail sending depends on your provider.** Port 25 outbound is blocked by
  many ISPs; the suite supports a smart-host relay, but publishing MX, SPF,
  DKIM and DMARC correctly is an operator task (`ceffio dns` checks it).
- **The bootstrap script works against published releases.** Until the first
  tag is cut, installation means building from sources — the commands above.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Ceffio deploys components under
their own licenses (AGPL for Nextcloud and Keycloak, among others); the
integration layer is Apache-2.0 and is not a derivative work of them.
