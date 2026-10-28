# Architecture

Ceffio deploys a fixed set of layers on a Kubernetes cluster, in a fixed order, from a
single binary. This document describes what runs where, and why the pieces are separated
the way they are.

For the day-to-day view — what is installed, what is healthy — see the administration
console. This file is the map.

## The shape

```
                      ┌─────────────────────────────────────────┐
   browser ──https──▶ │  Traefik (ingress)                      │
                      │  TLS: HTTP-01 or DNS-01, via cert-manager│
                      └───────────────┬─────────────────────────┘
                                      │
        ┌─────────────┬───────────────┼───────────────┬─────────────┐
        ▼             ▼               ▼               ▼             ▼
   Nextcloud      Keycloak        ONLYOFFICE      Stalwart      OpenBao
   (files)        (identity)      (office)        (mail)        (vault)
        │             │               │               │             │
        └─────────────┴───────────────┴───────────────┴─────────────┘
                                      │
                              PostgreSQL (CNPG)
                                      │
                              Longhorn (volumes)
```

Every arrow crosses a namespace. Nothing shares a process, and nothing shares a database.

## Namespaces, and which module owns them

The registry is the source of truth: a module declares the namespaces it writes to, and
the console's rights are derived from those declarations.

| Namespace | Owner | What lives there |
|---|---|---|
| `longhorn-system` | `storage` | The volumes every stateful layer sits on |
| `ceffio-system` | `platform`, `ingress`, `console` | Traefik, cert-manager, the console, the optional proxied interfaces |
| `ceffio-data` | `data` | PostgreSQL clusters (CloudNativePG) |
| `ceffio-identity` | `identity` | Keycloak |
| `ceffio-files` | `files` | Nextcloud and its caches |
| `ceffio-office` | `office` | ONLYOFFICE DocumentServer |
| `ceffio-video` | `talk` | Talk signaling, Janus, coturn, recording (with its relay), and the optional capture |
| `ceffio-mail` | `mail` | Stalwart |
| `ceffio-vault` | `vault` | OpenBao |
| `ceffio-exapps` | `exapps-daemon` | HaRP, the daemon Nextcloud asks for external applications |
| `cert-manager` | `ingress` | cert-manager itself and the DNS solver's secret |
| `cnpg-system` | `data` | The CloudNativePG operator |

## The layers, and what each one actually does

| Layer | Package | Role |
|---|---|---|
| Cluster | `internal/cluster` | Installs k3s if there is no cluster, and drives a full redeploy |
| Storage | `internal/storage` | Longhorn — replicated volumes for every PVC |
| Platform | `internal/platform` | The Helm releases the platform needs (Traefik and the CRDs), applied as one umbrella chart |
| Ingress | `internal/ingress` | cert-manager, the ClusterIssuer, the per-application Ingress objects, the upstream proxy headers |
| Data | `internal/data` | CloudNativePG and the databases each layer needs |
| Identity | `internal/identity` | Keycloak: the `ceffio` realm, its clients, the administrator account, the sign-in theme |
| Files | `internal/files` | Nextcloud, wired to PostgreSQL, Valkey and the vault |
| Office | `internal/office` | ONLYOFFICE DocumentServer, connected to Nextcloud |
| Talk | `internal/talk` | Talk signaling, Janus, coturn, the High Performance Backend |
| Mail | `internal/mail` | Stalwart, its domains, DKIM, and the OIDC directory |
| Vault | `internal/vault` | OpenBao: the single source of every secret |
| Console | `internal/console` | The administration interface |

**K3s is not part of `platform`.** It is installed by `internal/cluster`, which also
handles the "existing cluster" case where k3s is already running.

## The core modules

The registry (`internal/modules`) describes every layer so the console can display it and
so a module can declare dependencies. `ceffio install` lays these down in order; none of
them can be removed on its own.

| ID | Title | Namespaces |
|---|---|---|
| `storage` | Storage (Longhorn) | `longhorn-system` |
| `platform` | Platform | `ceffio-system`, `cert-manager` |
| `data` | Data | `ceffio-data`, `cnpg-system` |
| `identity` | Identity (SSO) | `ceffio-identity` |
| `files` | Files (Nextcloud) | `ceffio-files` |
| `office` | Document editing (ONLYOFFICE) | `ceffio-office` |
| `talk` | Talk media server | `ceffio-video` |
| `mail` | Mail server (Stalwart) | `ceffio-mail` |
| `vault` | Secrets vault | `ceffio-vault` |
| `ingress` | Ingress & TLS | `ceffio-system`, `cert-manager`, and every application namespace |
| `console` | Administration console | `ceffio-system` |

## Optional modules

Installed by choice, either at install time (`--with <id>`) or afterwards
(`ceffio module install <id>`, or the console's Modules page).

| ID | What it adds | Requires | Default |
|---|---|---|---|
| `recording` | Records Talk calls, and carries the relay that forwards Talk's requests and wakes the capture | — | **yes** (`--without recording` to skip) |
| `capture` | One audio track per participant, transcribed on this server and written beside the recording — told when to start by the relay, never by the database | `recording` | no |
| `exapps-daemon` | HaRP, for Nextcloud external applications | — | no |
| `live-transcription` | Live speech-to-text in Talk calls, on this server | `exapps-daemon` | no |
| `longhorn-ui` | The storage interface at `longhorn.<domain>`, behind the single sign-on | `storage`, `identity`, `ingress` | no |

Declared dependencies are expanded automatically: asking for `live-transcription` installs
`exapps-daemon` first, and `ceffio module remove exapps-daemon` is refused while an
installed module requires it.

## Why Talk instead of Element + Jitsi

Ceffio used to ship Matrix/Synapse with an Element client. It now ships Nextcloud Talk.
The reasons are about who owns which part of the problem:

- **One identity provider instead of two directories.** Synapse keeps its own user
  database, federated and independent of Keycloak. Talk signs users in through Keycloak,
  like every other layer: one account, one place to remove it.
- **One set of files, not two.** Talk writes into Nextcloud's own storage, so a shared
  file and its conversation are the same object. Element + Jitsi meant two storage
  systems and a bridge between them.
- **Fewer moving parts to keep alive.** The Matrix stack is Synapse, a TURN server, a
  Jitsi deployment and a bridge. The Talk stack is signaling, Janus, and coturn — and the
  first two are one product, versioned together.
- **Federation was never used here.** It is the main argument for Matrix, and this
  platform is deliberately single-tenant.

The cost is real and worth stating: Talk is tied to Nextcloud, so it cannot be deployed
without the files layer, and a Talk upgrade follows a Nextcloud upgrade.

## Talk's High Performance Backend

The HPB moves signaling out of each browser into a server process, which is what makes
group calls usable past a handful of participants.

- **`spreed.<domain>`** is the signaling endpoint, served by Traefik over TLS like any
  other host. Browsers connect there.
- **`talk.<domain>`** is coturn's public name — TURN and STUN. It is **not** behind
  Traefik: browsers reach it directly on the media ports, and the certificate is served by
  coturn itself. That is why this host appears in the DNS table but not in the ingress
  list.

Confusing the two is the most common mistake when debugging a call that connects but
carries no audio.

See [media-and-firewall.md](media-and-firewall.md) for the ports and the firewall traps.

## Where the data lives

| Data | Where | Backed up by |
|---|---|---|
| Files, conversations | Nextcloud PVC (Longhorn) | `ceffio backup` |
| Mail | Stalwart PVC | `ceffio backup` |
| Databases | PostgreSQL PVCs (Longhorn) | `ceffio backup` |
| Secrets | OpenBao PVC | `ceffio backup` |
| Configuration | Kubernetes objects | `ceffio backup` |

A single node means a single copy: Longhorn replicates within the node's disks, which
protects against a disk failure and **not** against losing the machine. The monitoring
page says so rather than implying redundancy that does not exist.

## See also

- [secrets.md](secrets.md) — the vault, the injector, and the exceptions
- [tls.md](tls.md) — how certificates are obtained and renewed
- [adding-a-module.md](adding-a-module.md) — extending the registry
- [console-image.md](console-image.md) — how the console is built and shipped