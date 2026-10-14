# janus-gateway — corresponding source for the published image

This directory holds the **frozen build context** of the Janus WebRTC gateway
image that Ceffio deploys:

    ghcr.io/ceffio-suite/janus-gateway:1.4.0-1

Janus is **GPL-3.0**. Distributing a binary image of it carries the obligation
to publish the corresponding source — this directory and the repository below
are how Ceffio discharges it.

## Where the real, maintained source lives

The image is built by a **separate public repository**, which is the
authoritative source and its build pipeline:

    https://github.com/ceffio-suite/janus-gateway

The files here are a **snapshot frozen at tag `v1.4.0-1`** of that repository,
copied byte-for-byte (the Dockerfile here has the same SHA-256 as
`git show v1.4.0-1:Dockerfile` there). They are placed in the product tree so
that anyone auditing Ceffio's deployed components finds the corresponding
source next to the code that references it, without having to know the image
lives in another repo.

**The snapshot does not drift on its own**, but it is not the place to edit.
To update the image, change the `janus-gateway` repository, tag it, and then
refresh this snapshot to the new tag (and bump `internal/version/version.go`).

## What is actually here

| File | Origin |
|---|---|
| `Dockerfile` | Builds Janus `1.3.0` from the official upstream tarball (`github.com/meetecho/janus-gateway`), plus pinned `usrsctp` (by commit) and `libsrtp 2.6.0` |
| `docker-entrypoint.sh` | Ceffio's own: public-IP injection and **STUN IPv4 resolution** at container start |
| `janus.jcfg`, `janus.transport.*.jcfg`, `janus.plugin.videoroom.jcfg` | Upstream Janus config, adapted: media range narrowed to `20000-20100`, NAT handling |

**There are no patches against the Janus source tree.** The build compiles
upstream Janus unmodified. Everything Ceffio-specific is either configuration
(`*.jcfg`) or the container entrypoint — no `.diff`, no `sed` on the upstream
code. So there is no `patches/` directory: there is nothing to patch.

### Why the entrypoint resolves STUN to IPv4

Janus accepts a hostname for its STUN server but resolves it with
`getaddrinfo`, which returns IPv6 first on a dual-stack host. Janus then
queries STUN over IPv6 and announces a public IPv6 address — browsers with
only IPv4 receive no reachable candidate and the media fails (measured). The
entrypoint pins the IPv4 before writing the config. This is runtime behavior
in Ceffio's own script, not a change to Janus.

## Licensing

- **Janus** (compiled into the image): GPL-3.0 — © the Janus authors,
  https://github.com/meetecho/janus-gateway
- **usrsctp**: BSD-3-Clause — https://github.com/sctplab/usrsctp
- **libsrtp**: BSD-3-Clause — https://github.com/cisco/libsrtp
- **Ceffio's entrypoint and configuration adaptations**: © MANDEM. Inside
  this repository they follow its license (AGPL-3.0-or-later). NOTE: the
  upstream `janus-gateway` repository currently carries an Apache-2.0 LICENSE
  file, dated from before the suite's AGPL decision — the maintainer must
  align it (this snapshot does not change it).

The image is an aggregate: Ceffio's scripts are separate files from the
GPL Janus binary, and Janus is compiled unmodified from upstream. See
[`THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md) for the full
component inventory.
