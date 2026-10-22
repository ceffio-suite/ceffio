# The console image

The administration console is not deployed as a manifest from the operator's machine: it
is a **container image**, built and published by CI, and pulled by the cluster.

## Why an image

The console serves a web page and an API from one binary. Building it on the operator's
machine would need a Go toolchain there, on a machine whose job is to run Kubernetes; and
a locally built image would differ between two operators running the same Ceffio version.
An image built once, from a tagged commit, makes "what is running" answerable.

## What the image contains

- the `ceffio` binary itself, which serves both the page and the API;
- the page, embedded in the binary (`web/index.html`) — so the page and the API that
  serves it can never be from different versions;
- no configuration: everything comes from the cluster and from OpenBao.

`ceffio console --deploy` deploys that image. It does not build anything.

## Publication

The image is built and pushed by the release workflow, tagged with the version. The
`Makefile` and `.github/workflows/` carry both steps; a local build is for development
only and is never what a release ships.

The image tag in the Deployment is the Ceffio version, so the console's own footer —
`ceffio.org · v0.8.2 (abc1234)` — always matches the binary that is running.

## Rights in the cluster

The console reads a lot and writes almost nothing. Its rights come from two places:

1. **Per-namespace Roles, derived from what the modules declare.** Each module lists the
   namespaces it owns and the permissions it grants; the console's rights are the union of
   those declarations. A module added tomorrow gets a Role without anyone editing the
   console.
2. **One hand-written ClusterRole**, for the things that are cluster-scoped: listing pods
   and namespaces, reading nodes, metrics, storage classes, and Longhorn's own resources.
   **It is read-only, always**, and a test freezes the list.

Two exceptions, both deliberate:

- **Writing the platform's namespaces** at installation (create, update, patch — never
  delete);
- **`pods/exec`** in `ceffio-files` (Nextcloud's `occ`) and in `ceffio-identity` (kcadm),
  which is how the console reads the realm's settings. `create` on `pods/exec` is what
  running a command requires, and there is no narrower verb.

The console **cannot read Secrets** in `cert-manager`, and that is a rule rather than an
oversight: reading the platform's Secrets from a web page is the shortest path to leaking
all of them. The TLS page works around it by reading the certificates instead — see
[tls.md](tls.md).

## What it deliberately does not do

- **No `/api/apps` routes.** Nextcloud's application catalogue is administered in
  Nextcloud. A page rebuilt here would follow neither its categories nor its compatibility
  rules.
- **No write route on `/api/certificates`.** The DNS credential is written through the
  ingress module's settings, and one path to the vault entry is enough.
- **No reimplementation of an administration interface it can link to.** See the
  Administration page: it takes you to Nextcloud, Stalwart, OpenBao, Longhorn and
  Keycloak rather than rebuilding them.

## See also

- [console README](../internal/console/README.md) — the tabs, the API, the authentication
- [architecture.md](architecture.md) — where the console sits
- [secrets.md](secrets.md) — why it never reads a secret