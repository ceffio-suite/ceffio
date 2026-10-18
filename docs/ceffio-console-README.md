# ceffio-console — archived

**This repository no longer builds or publishes anything.** The publication of
the Ceffio administration console image has been moved into the
[`ceffio-suite/ceffio`](https://github.com/ceffio-suite/ceffio) repository
itself, and this repository is archived.

## Why

The console is not a standalone service: the image embeds the `ceffio`
binary, which carries the administration logic and the web page. Publishing
it from a separate repository meant cloning `ceffio` (`--depth 1`) at build
time and recompiling it — with Go 1.24 while `go.mod` required 1.27.1. The
published image therefore matched **no verifiable release**: nothing proved
that the binary inside the image was the one attached to the GitHub Release
and covered by `checksums.txt`.

Since the move, the `release.yml` workflow of
[`ceffio-suite/ceffio`](https://github.com/ceffio-suite/ceffio) publishes the
image **from the exact release binaries** (byte for byte, verified against
the release checksums), in multi-architecture (`linux/amd64`, `linux/arm64`),
on every tag.

## Where things live now

| What | Where |
|---|---|
| Image | `ghcr.io/ceffio-suite/ceffio` (tags `X.Y.Z`, `latest` for stable versions only) |
| Dockerfile | [`build/console/Dockerfile`](https://github.com/ceffio-suite/ceffio/blob/main/build/console/Dockerfile) in `ceffio` |
| Publishing workflow | [`release.yml`](https://github.com/ceffio-suite/ceffio/blob/main/.github/workflows/release.yml), job `console-image` |
| Console source code | [`internal/console`](https://github.com/ceffio-suite/ceffio/tree/main/internal/console) in `ceffio` |
| Documentation | [README of `ceffio`](https://github.com/ceffio-suite/ceffio#console-image), section "Console image" |

### About the image name

The image is published as `ceffio`, not `ceffio-console`. A GHCR package
belongs to the repository that first published it: the `ceffio-console`
package was created here, and a workflow running in `ceffio-suite/ceffio`
cannot push to it — the push is refused with
`denied: permission_denied: write_package`, even with `packages: write`
granted, because the check is against the package's owner and not against the
workflow's own repository.

The `ghcr.io/ceffio-suite/ceffio-console` package therefore still exists and
remains pullable, with the tags it already had. It receives **nothing new**:
every release of `ceffio` publishes to `ghcr.io/ceffio-suite/ceffio`.

## Correction to the previous README

This repository's former README stated that the console "does not write to
the cluster". **That was false.** The console's ServiceAccount (`ceffio-admin`)
holds write access inside the `ceffio-*` platform namespaces and `pods/exec`
limited to `ceffio-files` (running `occ` in the Nextcloud pod); it is what
allows it to install HaRP and the live-transcription ExApp. The exact
perimeter is documented in the `ceffio` repository (README, section "Console
image", and the RBAC deployed by `internal/console/deploy.go`).

Issues and pull requests are no longer accepted here: open them on
[`ceffio-suite/ceffio`](https://github.com/ceffio-suite/ceffio).
