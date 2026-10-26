<p align="center">
  <img src="assets/ceffio-banner-1280.png" alt="Ceffio — logo" width="100%">
</p>

<p align="center">
  <a href="https://github.com/ceffio-suite/ceffio/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ceffio-suite/ceffio/ci.yml?branch=main&label=CI&logo=github" alt="CI status (main)"></a>
  <a href="https://github.com/ceffio-suite/ceffio/releases/latest"><img src="https://img.shields.io/github/v/release/ceffio-suite/ceffio?logo=github" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--or--later-blue" alt="AGPL-3.0-or-later license"></a>
  <a href="https://github.com/ceffio-suite/ceffio/blob/main/go.mod"><img src="https://img.shields.io/badge/Go-1.27-00ADD8?logo=go" alt="Go 1.27"></a>
  <a href="https://github.com/ceffio-suite/ceffio/graphs/contributors"><img src="https://img.shields.io/github/contributors/ceffio-suite/ceffio" alt="Contributors"></a>
  <a href="https://goreportcard.com/report/github.com/ceffio-suite/ceffio"><img src="https://goreportcard.com/badge/github.com/ceffio-suite/ceffio" alt="Go Report Card"></a>
</p>

Your **sovereign collaborative suite**: open source, self-hosted.

Ceffio replaces Microsoft 365 / Teams for a company, an administration, or an organisation —
SSO identity, files, collaborative documents, mail and videoconferencing — deployed on
Kubernetes **with a single command**, with no subscription.

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

Ceffio **is not a fork** of those applications. It is a **unified integration layer** —
installation, configuration, SSO, provisioning, lifecycle, security, monitoring,
backup/restore, upgrades, air-gap — built around proven open source projects:

| Domain | Component |
|---|---|
| Identity/SSO | Keycloak |
| Files | Nextcloud |
| Chat | Nextcloud Talk |
| Video | Nextcloud Talk + Janus (HPB) |
| Recording | Nextcloud Talk recording backend |
| Transcription | Live transcription (ExApp via HaRP) |
| Office | ONLYOFFICE |
| Mail | Stalwart |
| Data | PostgreSQL (CloudNativePG) + Valkey |
| Secrets | OpenBao |
| Ingress/TLS | Traefik + cert-manager |
| Console | Ceffio administration console |

The product promise is that all of this is **self-supporting in one command**: SSO works
across every app from the start, credentials are generated and sealed in the vault — never
asked for in a prompt, never left in a file.

**The public address is discovered, not asked for.** A small reporter (module
`public-ip`) queries several STUN servers — the same NAT path as the media — and, when
the STUN path is filtered, HTTP echo services. It publishes the address the sources agree
on in a ConfigMap that Janus, coturn, the console and `ceffio status` read; when the
address changes it republishes and rolls the pods that consume it. No user data crosses
those lookups, and the source list is a setting: the suite does not depend on a single
vendor for it. See [media-and-firewall.md](docs/media-and-firewall.md).

### Why Talk instead of Element + Jitsi

An earlier version of Ceffio assembled **Matrix (Synapse + Element)** for chat and
**Jitsi** for video. That stack was **removed**, for three reasons:

1. **Two authentication systems to synchronise.** Matrix and Jitsi each had their own; they
   had to be wired to Keycloak through dedicated bridges. Every bridge is a failure source,
   and one misconfigured authentication loop is enough to make video unusable.
2. **A double operational surface** for the administrator: two stacks, two lifecycles, two
   backup sets.
3. **Talk is native to Nextcloud**: its authentication is Nextcloud's, itself wired to
   Keycloak. No bridge is left to maintain, and chat and video live with the files.

## Architecture

A Go CLI installs K3s on a Linux host, then deploys and configures each building block in
its own namespace, directly through the Kubernetes API (client-go). There is no Operator:
the CLI is the only control point, and every deployment is idempotent.

<p align="center">
  <img src="docs/architecture.svg" alt="Ceffio architecture: Traefik serves the web applications by subdomain, Keycloak provides SSO, WebRTC media goes straight to Janus and coturn, and the whole stack stands on cert-manager, CloudNativePG and Longhorn." width="100%">
</p>

Three things to read on this diagram:

- **All web traffic enters through Traefik**, which serves each application under its own
  subdomain with certificates managed by cert-manager — issued over HTTP-01 or DNS-01, as
  the installation chooses.
- **Keycloak is the only source of identity.** Nextcloud, the console, OpenBao and Stalwart
  delegate authentication to it (OIDC).
- **Media bypasses Traefik.** Janus and coturn run in `hostNetwork` and receive audio and
  video directly on the host ports.

The full map — the namespaces, the layers, the modules, and why each is separated — is in
[**docs/architecture.md**](docs/architecture.md).

## The layers

Each layer is a Go package that deploys and configures one part of the stack. This
decomposition is what makes upgrading possible: every layer knows what it runs, so before
and after can be compared.

**K3s is installed by `internal/cluster`, not by `internal/platform`**, which applies the
Helm releases the platform needs.

| Layer | Package | Contents |
|---|---|---|
| Cluster | `internal/cluster` | K3s, and a full redeploy |
| Platform | `internal/platform` | Traefik and the CRDs, as one umbrella chart |
| Storage | `internal/storage` | Longhorn: every persistent volume |
| Data | `internal/data` | CloudNativePG, PostgreSQL, Valkey |
| Identity | `internal/identity` | Keycloak, realm, OIDC clients, the sign-in theme |
| Files | `internal/files` | Nextcloud |
| Office | `internal/office` | ONLYOFFICE + Nextcloud connector |
| Mail | `internal/mail` | Stalwart |
| Talk + HPB | `internal/talk` | Janus (SFU), signaling, coturn, NATS |
| Secrets | `internal/vault` | OpenBao + injector |
| Console | `internal/console` | Administration console |
| Ingress | `internal/ingress` | Routes and certificates |

### Talk's High Performance Backend

Talk works alone up to roughly 4–6 participants, in direct browser-to-browser connections.
Beyond that you need a **SFU**: a server that receives each stream once and redistributes it.

    Talk (Nextcloud app)   interface, chat, room management
    signaling              who is present, who joins what
    Janus                  media transport (the SFU)
    NATS                   coordination between signaling instances
    coturn                 TURN/STUN relay

Two design points that required correction under real conditions:

- **`hostNetwork` on Janus and coturn.** A Kubernetes `NodePort` Service can expose only
  **one** port, never a range — while WebRTC media needs a whole range end to end. Without
  `hostNetwork`, everything reports "Running" and nothing flows.
- **The public address must be announced.** Behind NAT, a Janus that announces its private
  addresses in the ICE candidates produces a black screen. The public address is
  **discovered automatically** via STUN at startup, and the signaling server announces a
  public name (`talk.<domain>`), which survives an address change where a hard-coded value
  would silently stop working.

## Modules

Every feature of the suite — the core layers and the optional add-ons — is a **module**: a
Go package implementing a single interface (`Info`, `Install`, `State`, `Uninstall`) and
registering itself in a global registry. The registry is the catalog every frontend reads:
`ceffio install --with/--without`, `ceffio module list|install|remove|status`, the console's
Modules page, the status and doctor layer lists, and the console's RBAC grant are all
generated from it — no feature list is hardcoded anywhere. Adding a feature means adding a
module; see [`docs/adding-a-module.md`](docs/adding-a-module.md).

**Core modules** are the product: `storage`, `platform`, `data`, `identity`, `files`,
`office`, `talk`, `mail`, `vault`, `ingress`, `console`. `ceffio install` deploys them in
its own sequence, and they are removed only with the cluster (`ceffio uninstall`) —
`ceffio module remove` refuses them.

**Optional modules** are chosen by the operator, at install time (`--with`/`--without`) or
afterwards (`ceffio module install <id>`, or the console's Modules page):

| ID | Role | Resources | Requires | Installed by default |
|---|---|---|---|---|
| `recording` | Records Talk calls: a hidden participant joins the room, renders it and uploads the result to Nextcloud | — (workload limited to 2 GiB RAM, no model download) | — | **yes** (`--without recording` to skip) |
| `exapps-daemon` | HaRP runs the containers Nextcloud asks for, speaking the Kubernetes API directly — prerequisite of every external application | — | — | no |
| `live-transcription` | Transcribes speech live during a Talk call, on this server, with open source speech models; nothing is sent to a third party | ~9 GB disk, ~16 GB RAM | `exapps-daemon` (installed automatically with it) | no |
| `capture` | Captures one audio track per participant during a Talk recording, transcribes each track on the CPU and writes the named transcript next to the recording | ~1,5 GB image, 4 GB RAM during transcription | `recording`, `exapps-daemon` | no |
| `longhorn-ui` | The storage interface at `longhorn.<domain>`, **behind the single sign-on** | negligible (one proxy pod) | `storage`, `identity`, `ingress` | no |

> **`longhorn-ui` can delete volumes, and therefore data.** It installs nothing without
> being asked, and the interface it exposes sits behind Keycloak. The storage interface has
> no authentication of its own, which is exactly why it is never exposed without the proxy
> in front of it.

Declared dependencies are expanded by the registry: asking for `live-transcription` installs
`exapps-daemon` first, and `ceffio module remove exapps-daemon` is refused while an
installed module requires it.

`live-transcription` places the speech models of the languages you choose — the module
setting `languages`, French by default — and verifies them on disk. A language left out is
downloaded by the app the first time it is used, which needs internet and makes that call
wait; the settings page places a language the moment it is saved.

**Every optional module can be installed from the CLI or from the console** — neither path
is privileged. `recording`, although optional, ships **with the installer** by default.
The README used to suggest otherwise; it is not the case.

## Installation

The deployment is **idempotent**: running it again breaks nothing, it updates what needs
updating. That is what makes a reinstall after an incident safe.

Prerequisites:

- A Linux host with root access (Ceffio installs K3s itself)
- Go 1.27+ only when building from sources
- Media ports reachable from the Internet **and** forwarded: see "Media and firewall"

`--existing-cluster` uses a cluster that is already running instead of installing K3s, and
`--runtime` chooses between `k3s` (default) and `rke2`.

## The CLI

| Command | Role |
|---|---|
| `ceffio install` | deploy the full stack — optional modules via `--with`/`--without` (catalog generated from the registry) |
| `ceffio status` | state of the deployed services |
| `ceffio doctor` | diagnostics (prerequisites, coherence, health) |
| `ceffio identity` | deploy Keycloak alone, and reapply the suite's OIDC clients |
| `ceffio files` / `office` / `mail` / `talk` / `vault` / `console` | redeploy one layer, alone |
| `ceffio mail sso` | check the mail's single sign-on (`--repair` reapplies it) |
| `ceffio module list` | every module of the registry with its state |
| `ceffio module install <id>` | install an optional module and its dependencies |
| `ceffio module remove <id>` | remove an optional module (`--yes` to skip confirmation) |
| `ceffio module status <id>` | detailed state of a module (status, detail, blocked) |
| `ceffio module config <id>` | read or write a module's settings (`--test`, secrets from stdin) |
| `ceffio backup` | backup (databases, secrets, volumes) |
| `ceffio restore` | restore from a backup |
| `ceffio upgrade --plan` | show what would change, before changing it |
| `ceffio users` | provision accounts (Keycloak + applications) |
| `ceffio theme` | reapply the Ceffio theme to Nextcloud |
| `ceffio dns` | check DNS configuration (A, AAAA, MX, SPF, DKIM, DMARC, PTR) |
| `ceffio publicip` | the published public address, and a per-source check (`check`) |
| `ceffio expose` | publish the suite behind the firewall |
| `ceffio uninstall` | uninstall and destroy the cluster |

### Settings

A module **declares** its settings — groups, fields, types, conditions — and the console
draws the form from that declaration. The same values are reachable from the command line:

```bash
ceffio module config <id>                  # the groups and their current values
ceffio module config <id> <group>          # one group
ceffio module config <id> <group> k=v …    # validate, store and apply
ceffio module config <id> <group> --test   # check without storing
```

A field hidden by a condition is **neither validated nor required**: choosing DNS-01 shows
the chosen provider's credentials and hides every other provider's, instead of drawing all
43 at once.

## Secrets: the vault is the only source

All application credentials (database passwords, admin accounts, OIDC client secrets, JWT
signing keys) live in **OpenBao**, deployed by `ceffio install` itself. Pods read their
secrets **at startup** through the OpenBao agent injector. Rotation happens in one place,
and the administration console reads and rotates through the same vault. Human logins go
through OIDC (Keycloak); services authenticate to the vault through Kubernetes auth — two
doors, never a shared token in a file.

**OpenBao is the only _source_ of secrets. It is not the only _place_ they appear.** Four
Kubernetes Secrets are written **from the vault**, because the software that reads them
cannot be reached by the injector:

| Secret | Why |
|---|---|
| `cert-manager/ceffio-acme-dns` | cert-manager resolves the ClusterIssuer's `secretRef` itself and cannot reach OpenBao |
| `ceffio-system/longhorn-oauth2-proxy-vault` | oauth2-proxy reads its secrets as environment variables |
| `ceffio-video/ghcr-pull` | a `dockerconfigjson`, read by the kubelet from the API |
| `ceffio-mail/*` | Stalwart's administration needs a credential when no pod is available to inject into |

Each is a copy with a short life, rewritten from OpenBao on the next `ceffio install` —
never a second source. The console **cannot read a secret's value**, by design: reading the
platform's Secrets from a web page is the shortest path to leaking all of them. Details in
[**docs/secrets.md**](docs/secrets.md).

## The administration console

A web interface for daily operations: service states, modules and their settings,
certificates with their expiry and renewal dates, users, the machine's consumption and
volumes. It reads the cluster's real state — it does not guess it. See
[`internal/console/README.md`](internal/console/README.md) and
[**docs/console-image.md**](docs/console-image.md).

## The sign-in page

The page every user meets first is Ceffio's, not Keycloak's. It is a theme that **extends
`keycloak.v2` and overrides no template**: a Keycloak upgrade keeps every page, every flow
and every fix, and only the look changes.

It ships inside the binary and is mounted read-only into the Keycloak pod, so an offline
installation gets it with nothing on disk.

Changing it is a setting — Settings → module `identity` → group `login_page`:

```bash
ceffio module config identity login_page theme=ceffio      # the Ceffio page (default)
ceffio module config identity login_page theme=keycloak.v2 # Keycloak's own page
```

Going back to Keycloak's page is the fastest way to tell a theming problem from a sign-in
problem. Changing which theme is used applies immediately; shipping a *new* theme restarts
the pod, because production Keycloak caches themes. Details in
[**docs/sign-in-page.md**](docs/sign-in-page.md).

## Console image

The console runs as a container image, built and published **by this repository** (the
`release.yml` workflow): every release tag `vX.Y.Z` publishes
`ghcr.io/ceffio-suite/ceffio:X.Y.Z` for `linux/amd64` and `linux/arm64`. `latest` follows
stable versions only — never an `-rc` candidate. The image embeds the **exact binaries of
the release** (byte for byte, verified against `checksums.txt`), never a separate
recompilation.

The image is named `ceffio`, not `ceffio-console`, and that is deliberate: a GHCR package
belongs to the repository that first published it, and a workflow in another repository
cannot push to it — the attempt is refused with `denied: permission_denied: write_package`
even with `packages: write` granted. The former repository
[`ceffio-suite/ceffio-console`](https://github.com/ceffio-suite/ceffio-console) is archived.

The image is `FROM scratch`: no shell, no package manager — the static binary plus the
certificate authorities. It is normally deployed **inside the cluster** by `ceffio install`,
which pulls it from GHCR. To run it manually:

```bash
docker run --rm -p 8088:8088 \
  -v ~/.kube/config:/kubeconfig:ro -e KUBECONFIG=/kubeconfig \
  ghcr.io/ceffio-suite/ceffio:X.Y.Z \
  console --domain example.com --addr :8088
```

### Permissions required in the cluster

Stated plainly, because an earlier document claimed the console only reads — that was
false. The console's `ServiceAccount` (`ceffio-admin`, created by `ceffio install`) holds,
per the RBAC deployed by [`internal/console/deploy.go`](internal/console/deploy.go):

- **cluster-wide reads**: pods, namespaces, deployments, ingresses, cert-manager
  certificates, nodes, metrics, storage classes and Longhorn's resources — what the
  dashboard, the certificates page and the monitoring page show;
- **writes inside the `ceffio-*` platform namespaces only** (never `kube-system`, never
  `cert-manager`, never `longhorn-system`): this is what installing an optional module from
  the console requires;
- **`pods/exec` limited to two namespaces**: `ceffio-files` (to run `occ` for the settings
  the OCS API does not expose) and `ceffio-identity` (to read the realm through kcadm);
- **no right over cluster roles and no `delete` on namespaces**: RBAC is granted by the
  installer, never by the console itself.

In short: the console **does write to the cluster** — within the platform namespaces, with
the perimeter above — while full (re)deployment remains the CLI's business.

## Media and firewall

This is the part most often gotten wrong, because it depends on the network topology rather
than on the code. Four families of ports must be reachable **from the Internet**:

| Ports | Protocol | Role |
|---|---|---|
| `49152-49200` | UDP | coturn relay ports — the range the relayed media actually uses |
| `3479` | UDP + TCP | TURN relay — essential on restrictive networks |
| `5349` | TCP | TURN secured (fallback when UDP is blocked) |
| `20000-20100` | UDP | Janus media (the SFU's own video transport) |

`talk.<domain>` is coturn's public name, and it is **not** behind Traefik: browsers reach
these ports directly, and coturn serves its own certificate. `spreed.<domain>` is the
signaling endpoint, and that one goes through Traefik like any other web host. Confusing the
two is the most common mistake when debugging a call that connects but carries no audio.

All of these are verifiable on a live deployment. The relay range is the one that is easy
to forget, and forgetting it produces a deceptive failure: **the allocation succeeds** (it
goes over `3479`), the server believes the relay is up, and **no media ever passes**. A
browser that cannot reach the range falls back to direct candidates, and on a restrictive
network there are none — so the call fails with "a TURN server is probably required" while
the TURN server is, in fact, perfectly healthy.

Three verified pitfalls:

- **On a firewall that handles ranges, leave the internal port empty.** pf
  (OpenBSD/OPNsense) reads `rdr-to IP port N` as "map everything onto N": filling that field
  with a single port silently collapses the whole range onto it, while still reporting
  "saved".
- **Forward from the right device.** If the VM sits behind a router which in turn sits
  behind the ISP box, rules placed on the router cannot work: they belong on the box. Always
  test from the Internet, never from the local network — an internal test proves nothing.
- **A range must be forwarded 1:1.** Each port of `49152-49200` must reach the **same** port
  on the host. coturn announces the relay port it allocated and the peer connects back to
  exactly that number; a translating NAT breaks the return path even though the allocation
  looked fine.

The check that settles all of this, run against the **public** address:

```bash
turnutils_uclient -u "<username>" -w "<credential>" -y \
    -e <public-ip> -p 3479 talk.<domain>
```

A healthy server prints a **public** relay address with a port inside the range, and loses
no packet:

```
INFO IPv4. Received relay addr: 82.64.251.96:49198
INFO Total lost packets 0 (0.000000%)
```

A **private** relay address means `--external-ip` did not take effect: the browser then
receives a candidate it cannot reach, which is the same failure by another route.

The full list, including the STUN lookup and the five firewall traps, is in
[**docs/media-and-firewall.md**](docs/media-and-firewall.md).

## TLS certificates: HTTP-01 or DNS-01

Ceffio obtains its certificates from Let's Encrypt through cert-manager, with **two** ways
of proving the domain is yours. The challenge is a **setting**, not a build-time choice.

| | HTTP-01 (default) | DNS-01 |
|---|---|---|
| Proof | a token served on port 80 of each hostname | a TXT record in your DNS zone |
| Credential | none | a DNS provider API token, held in OpenBao |
| Port 80 required | yes, for `.well-known/acme-challenge` | no |
| **Wildcard `*.domain`** | **impossible** | yes |
| Certificates needed | one per hostname | **one for the whole domain** |

### Why the default is HTTP-01

Nothing to configure, no credential to store or rotate. An installation that sets nothing
behaves exactly as before this setting existed.

Its limit is structural: **the ACME protocol gives the authority no way of validating a
wildcard over HTTP**, because a wildcard names hosts that do not exist yet. Nine hostnames
therefore mean nine certificates, each renewed against Let's Encrypt's weekly quota — and a
hostname with no service listening on port 80 can never be validated at all.

### How to enable DNS-01

The setting lives in **Settings → module `ingress` → group `tls`**, or:

```bash
ceffio module config ingress tls challenge=dns01 dns_provider=cloudflare dns_zone=example.com
ceffio module config ingress tls cred_cloudflare_api_token=<token>
```

**The provider is a dropdown**, built from the table in `internal/acme`. Choosing one shows
that provider's credential fields and hides every other provider's. A provider set while
the challenge is still `http01` is refused rather than ignored: a configuration that does
not do what it says is worse than one that fails.

### The providers, and why the list is open

**Nineteen providers have a credential table**, each carrying a one-sentence help saying
where to create the credential and with which rights: `acme-dns`, `Azure DNS`, `Cloudflare`,
`ClouDNS`, `deSEC`, `DigitalOcean`, `Gandi`, `GoDaddy`, `Google Cloud DNS`, `Hetzner`,
`Infomaniak`, `IONOS`, `Namecheap`, `OVH`, `Porkbun`, `PowerDNS`, `RFC 2136`, `Route 53`,
`Scaleway`.

cert-manager also ships eight in-tree solvers, and everything else goes through a webhook
solver built on [libdns](https://github.com/libdns/libdns). **The provider name travels as
a value in the ClusterIssuer**, so adding a host is a configuration change, never a code
change and never a new release.

Three paths cover every situation, including "no DNS provider account":

| Your situation | Solver | Notes |
|---|---|---|
| Cloudflare, Route 53, Azure, Google… | in-tree | nothing extra deployed |
| Scaleway, OVH, Gandi, Hetzner, … | libdns webhook | one component, provider by name |
| Your own DNS (BIND, Knot, PowerDNS, Technitium) | `rfc2136` | standard dynamic updates, TSIG key |
| No rights on the main zone | `acmedns` | answers only for `_acme-challenge`, delegated by CNAME |

### Renewal: the number that matters

Let's Encrypt certificates last 90 days, and cert-manager renews at about two thirds of
that — measured on a live certificate: 89 days of validity, renewal scheduled 30 days
before the end. The console shows both **Expires** and **Renews**, because "88 days left"
says nothing about whether the automation still works. A certificate that will expire and
never renew looks exactly like a healthy one until the day it stops.

Details, including why the console answers "is the credential in place?" from the
certificates rather than from the Secret: [**docs/tls.md**](docs/tls.md).

## Releases

Every release is a Git tag plus a GitHub Release carrying the linux/amd64 and linux/arm64
binaries and their SHA-256 checksums. The `release.yml` workflow builds and publishes them
— but only after the CI of the tagged commit is green. Grab the current one from the
[releases page](https://github.com/ceffio-suite/ceffio/releases/latest) and verify before
running:

```bash
sha256sum -c --ignore-missing checksums.txt
```

## Development

Development happens on `develop`; features arrive by pull request, and `main` only ever
holds a releasable state. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full GitFlow, the
release process, and the engineering rules this codebase follows.

```bash
make build            # build ./bin/ceffio
./bin/ceffio --help   # list of commands
make test             # tests
make vet              # static analysis
gofmt -l .            # must print nothing
```

## Status

The product is **deployed and working**: Nextcloud, ONLYOFFICE, Keycloak, Stalwart (mail),
Talk with its High Performance Backend, the administration console, backup/restore, and the
OpenBao vault.

Open points, stated plainly:

- **Mail sending depends on your provider.** Port 25 outbound is blocked by many ISPs; the
  suite supports a smart-host relay, but publishing MX, SPF, DKIM and DMARC correctly is an
  operator task (`ceffio dns` checks it).
- **One node is not a cluster.** Longhorn replicates across disks; losing the machine loses
  the data. The monitoring page says so rather than implying redundancy.
- **The public address lookup is the only external dependency** (several STUN servers,
  HTTP fallback, all configurable — see above).
- **`--profile` changes nothing.** It is accepted and displayed; the files in `profiles/`
  are sizing guidance the installer does not parse.
- **No HA profile yet.** `enterprise-ha.yaml` describes the target shape; the installer does
  not build it.
- **Some administration is delegated, not rebuilt.** Nextcloud's application catalogue,
  Longhorn's volumes and Keycloak's sessions are administered in their own interfaces, which
  the console links to.
- **Email templates and the account console are not themed** — only the sign-in page is.

## Documentation

| Document | What it answers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | What runs where, and why the layers are separated |
| [docs/secrets.md](docs/secrets.md) | The vault, the injector, and the Secrets that exist anyway |
| [docs/tls.md](docs/tls.md) | HTTP-01 or DNS-01, the providers, the renewal |
| [docs/media-and-firewall.md](docs/media-and-firewall.md) | Talk's ports and the firewall traps |
| [docs/sign-in-page.md](docs/sign-in-page.md) | The login theme, and how to leave it |
| [docs/console-image.md](docs/console-image.md) | How the console is built and what it may do |
| [docs/keycloak-production.md](docs/keycloak-production.md) | Keycloak in production mode |
| [docs/cout-hebergement.md](docs/cout-hebergement.md) | What the machine costs |
| [docs/adding-a-module.md](docs/adding-a-module.md) | Adding a layer or a module |
| [docs/README.md](docs/README.md) | The index of everything |
| [docs/history/](docs/history/) | Working notes, kept for context — they do not describe the code |

## License

Ceffio is distributed under the **GNU Affero General Public License v3.0 or later**
(`AGPL-3.0-or-later`). See [LICENSE](LICENSE).

Copyright © MANDEM.

Ceffio deploys third-party software that keeps its own license (Apache-2.0, AGPL-3.0,
GPL-3.0, MPL-2.0, BSD…). See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

"Ceffio" and its logo are trademarks of MANDEM; the code license grants no right over these
trademarks.