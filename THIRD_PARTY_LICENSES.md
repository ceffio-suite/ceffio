# Third-party licenses

Ceffio is licensed under **AGPL-3.0-or-later** (see [LICENSE](LICENSE)),
Copyright © MANDEM. Ceffio is not a fork of the software it deploys: it
orchestrates upstream projects running in **separate containers**. Each keeps
its own license and its own obligations.

Every license below was verified against the upstream repository's own
LICENSE file (not a badge or a tag), on 2026-10-14.

## Deployed components

| Component | Deployed image | License | Source |
|---|---|---|---|
| K3s | (installed on the host) | Apache-2.0 | [k3s-io/k3s](https://github.com/k3s-io/k3s) |
| Keycloak | `quay.io/keycloak/keycloak:26.7.3` | Apache-2.0 | [keycloak/keycloak](https://github.com/keycloak/keycloak) |
| Nextcloud | `docker.io/library/nextcloud:34.0.3` | AGPL-3.0 | [nextcloud/server](https://github.com/nextcloud/server) |
| Nextcloud Talk (app) | (inside Nextcloud) | AGPL-3.0 | [nextcloud/spreed](https://github.com/nextcloud/spreed) |
| Talk signaling | `docker.io/strukturag/nextcloud-spreed-signaling:2.1.1` | AGPL-3.0 | [strukturag/nextcloud-spreed-signaling](https://github.com/strukturag/nextcloud-spreed-signaling) |
| Janus | `ghcr.io/ceffio-suite/janus-gateway:1.4.0-1` | GPL-3.0 (upstream Janus) | [meetecho/janus-gateway](https://github.com/meetecho/janus-gateway) + [`images/janus-gateway/`](images/janus-gateway/) |
| — usrsctp (in the Janus image) | — | BSD-3-Clause | [sctplab/usrsctp](https://github.com/sctplab/usrsctp) |
| — libsrtp (in the Janus image) | — | BSD-3-Clause | [cisco/libsrtp](https://github.com/cisco/libsrtp) |
| coturn | `docker.io/coturn/coturn:4.18` | BSD-3-Clause | [coturn/coturn](https://github.com/coturn/coturn) |
| NATS | `docker.io/library/nats:2.15` | Apache-2.0 | [nats-io/nats-server](https://github.com/nats-io/nats-server) |
| ONLYOFFICE Docs | `docker.io/onlyoffice/documentserver:9.4.0.1` | AGPL-3.0 + 5 additional terms (LICENSE, §7) | [ONLYOFFICE/DocumentServer](https://github.com/ONLYOFFICE/DocumentServer) |
| OpenBao | `docker.io/openbao/openbao:2.7.1` | MPL-2.0 | [openbao/openbao](https://github.com/openbao/openbao) |
| vault-k8s agent injector | `docker.io/hashicorp/vault-k8s:1.7.6` (init-container agent) | MPL-2.0 | [hashicorp/vault-k8s](https://github.com/hashicorp/vault-k8s) |
| Stalwart Mail | `docker.io/stalwartlabs/stalwart:v0.16.26` | AGPL-3.0-only (community edition) + Stalwart Enterprise License (not used) | [stalwartlabs/stalwart](https://github.com/stalwartlabs/stalwart) |
| Valkey | `docker.io/valkey/valkey:8.1.10` | BSD-3-Clause | [valkey-io/valkey](https://github.com/valkey-io/valkey) |
| PostgreSQL | (via the CloudNativePG cluster) | PostgreSQL License | [postgresql.org](https://www.postgresql.org/about/licence/) |
| CloudNativePG | chart `cloudnative-pg:0.29.0` | Apache-2.0 | [cloudnative-pg/cloudnative-pg](https://github.com/cloudnative-pg/cloudnative-pg) |
| Traefik | (provided by K3s) | MIT | [traefik/traefik](https://github.com/traefik/traefik) |
| cert-manager | `cert-manager:v1.21.1` | Apache-2.0 | [cert-manager/cert-manager](https://github.com/cert-manager/cert-manager) |

## Notes on specific components

### ONLYOFFICE Docs — additional terms

ONLYOFFICE DocumentServer ships under AGPL-3.0 with **five additional terms**
(section 7 of its LICENSE, verified in the upstream file — not a separate
document): retain notices and attribution, mark modified versions with their
date and state they derive from ONLYOFFICE, expose ONLYOFFICE attribution
through a visible UI notice **in versions with a modified interface**, no
trademark rights, and CC BY-SA 4.0 for non-code content (icons, docs).

**Ceffio deploys the upstream image unmodified and does not mask the
branding**, so none of these terms is triggered. If you modify the image,
terms 1, 2 and 3 apply: keep attribution, state the version is modified, and
keep that notice visible in the interface. ONLYOFFICE's name and logo remain
covered by its trademark policy in all cases.

### Stalwart Mail — community edition only

Stalwart is dual-licensed: the community edition is AGPL-3.0-only, and
Enterprise features live under a separate commercial license
(`LicenseRef-SEL`). **Ceffio enables no Enterprise feature** — verified: the
mail layer (`internal/mail/`) activates no license key and no
Enterprise-only capability. If you enable Enterprise features yourself, you
need a commercial agreement with Stalwart Labs.

### Janus — GPL-3.0 and corresponding source

The `janus-gateway` image compiles upstream Janus (GPL-3.0) **unmodified**
from the official tarball, with pinned usrsctp and libsrtp (both BSD-3).
Ceffio's own additions are configuration files and the container entrypoint,
not patches to the Janus source tree. The corresponding source — the exact
build context frozen at the deployed tag — is published in
[`images/janus-gateway/`](images/janus-gateway/) and maintained in the public
repository [ceffio-suite/janus-gateway](https://github.com/ceffio-suite/janus-gateway).

### OpenBao injector render — MPL-2.0

`internal/vault/injecteur/rendu.yaml` is rendered from the Helm chart
[openbao/openbao-helm](https://github.com/openbao/openbao-helm) `0.30.3`
(MPL-2.0). Its file header carries the provenance notice, and modifications
to that file remain under MPL-2.0 (file-level copyleft — the rest of Ceffio
is unaffected).

### Valkey replaced Redis

Redis is distributed under RSALv2/SSPLv1 since version 7.4 — licenses that
are not open source. Ceffio deploys **Valkey** (BSD-3-Clause), the Linux
Foundation fork maintained by Redis's original authors, protocol-compatible.

## Go dependencies

Generated with `go-licenses report ./...` on 2026-10-14. All 56 modules are
under permissive licenses, compatible with AGPL-3.0:

| License | Modules |
|---|---|
| Apache-2.0 | 33 (client-go, cobra, go-logr, go-openapi/*, k8s.io/*, sigs.k8s.io/*, gnostic-models, moby/spdystream, modern-go/*, go.yaml.in/yaml/v2, …) |
| BSD-3-Clause | 16 (golang.org/x/*, google.golang.org/protobuf, google/uuid, spf13/pflag, munnerz/goautoneg, json-patch, inf.v0, …) |
| MIT | 5 (emicklei/go-restful, fxamacker/cbor, json-iterator, x448/float16, go.yaml.in/yaml/v3) |
| BSD-2-Clause | 1 (gorilla/websocket) |
| ISC | 1 (davecgh/go-spew) |

The full machine-readable report is reproducible with:

```bash
go install github.com/google/go-licenses@latest
go-licenses report ./...
```

## Air-gap distribution

Any offline bundle that embeds these images must include this file, the
license texts of each component, and a link to the exact source (tag) of
every GPL, AGPL and MPL component — Janus `v1.3.0` upstream (image tag
`1.4.0-1`), Nextcloud `34.0.3`, Keycloak `26.7.3`, signaling `2.1.1`,
ONLYOFFICE `9.4.0.1`, OpenBao `2.7.1`, Stalwart `v0.16.26`, Valkey `8.1.10`.

## Trademarks

"Ceffio" and the Ceffio logo are trademarks of MANDEM. Third-party names and
logos (Nextcloud, Keycloak, ONLYOFFICE, Redis, Janus…) belong to their
respective owners; they are cited here for identification purposes only.

---

*This inventory is maintained for transparency. It is not legal advice. If you
redistribute Ceffio or a bundle containing these components commercially,
have the obligations above reviewed by counsel — in particular the GPL-3.0
corresponding-source duty for Janus and the AGPL network clause for
Nextcloud, Stalwart and ONLYOFFICE.*
