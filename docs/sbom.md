# The software bill of materials

An SBOM answers a question an operator cannot answer from a changelog: **what
exactly runs on this machine, and which bytes is it?** Ceffio publishes three
kinds of documents, all CycloneDX JSON, and one command that writes the third.

## The three documents

| Document | Where | What it describes |
|---|---|---|
| `ceffio-linux-<arch>.cdx.json` | attached to each [release](https://github.com/ceffio-suite/ceffio/releases), next to the binary and covered by `checksums.txt` | the CLI binary: every Go module linked into it, with its version |
| the image's own SBOM | attached to the image in GHCR, read with `docker buildx imagetools inspect` | the binary, as shipped in the container |
| the installation's SBOM | written by `ceffio sbom` | the binary **and** every component of the version registry, with its digest and licence |

The first two are produced by [Syft](https://github.com/anchore/syft) in the CI
and in the release workflow. The third is a command, because it depends on the
installation: it lists what this deployment *can* run, and with `--cluster`,
what it *does* run.

## The installation's SBOM

```bash
ceffio sbom --output sbom.json          # the registry, as a document
ceffio sbom --cluster --output sbom.json # …and compare with what runs
ceffio sbom --cluster > /dev/null       # the exit code says whether there is a difference
```

Each component carries its name, its version, its image **with the digest it was
pinned to**, its role, its SPDX licence, and the module that deploys it. The
binary itself is in `metadata.component`, with its commit and build date.

The document carries **two kinds of components**, and says which is which with
the property `ceffio:pinned`:

- `true` — an image Ceffio ships and pins, by digest: the version registry;
- `false` — an image that runs on the machine but whose version belongs to the
  chart or the operator that deploys it (Longhorn, cert-manager, CloudNativePG,
  the AppAPI proxy, the console itself). Ceffio describes it and reports what
  runs; it does not claim to have chosen the version.

Without `--cluster`, the document describes what Ceffio can deploy. With
`--cluster`, the registry is compared with the images actually running in the
`ceffio-*` namespaces, `longhorn-system`, `cert-manager` and `cnpg-system`, and
the command reports:

- an image that runs and that the registry does not describe;
- a component that runs with another tag or another digest than the one the
  registry pins;
- a component the registry expects (a core module) that runs nowhere;
- **two references of the same image running at once** — a rolling update shows
  it for a moment, an installation that stays in it does not: this is how a
  component deployed once and never refreshed is found.

An optional module that is not installed is **not** a difference: the document
says `ceffio:optional=true` and `ceffio:installed` reflects what was observed.

**What `--cluster` does not do**: it does not resolve the multi-architecture
index digests at comparison time. A pod that asks for a tag is compared by tag —
the digest in its status is the manifest of its own platform, and comparing it
with an index digest would report every image as drifted.

## Read an image's SBOM

```bash
docker buildx imagetools inspect ghcr.io/ceffio-suite/ceffio:0.10.3 --format '{{ json .SBOM }}'
```

The same command gives `{{ json .Provenance }}`. Both are attestations attached
at publication, not files in a release.

## Run the scan yourself

The CI runs Grype on every SBOM; nothing stops an operator from doing the same:

```bash
# the binary
grype sbom:ceffio-linux-amd64.cdx.json --only-fixed --fail-on critical

# an installation's document
ceffio sbom -o sbom.json && grype sbom:sbom.json --only-fixed --fail-on critical

# an image
grype ghcr.io/ceffio-suite/ceffio:0.10.3 --only-fixed --fail-on critical
```

The project's own rule is the one the CI applies: a **critical vulnerability with
a fix** fails; everything else is reported. A finding deliberately accepted is
written in `.grype.yaml`, one entry per vulnerability, with its reason, its
decider and a review date.

## What the document does not cover

**The internal dependencies of third-party images.** The SBOM of a Nextcloud,
Longhorn or cert-manager image belongs to its publisher; Ceffio identifies the
image by digest and says which upstream project it is, but it does not inventory
the packages inside it. Inventing that inventory would be a guess presented as a
proof.

**The cluster itself** (the CNI, the kubelet, the metrics server) and the
operating system of the node. `ceffio sbom --cluster` follows an explicit list of
namespaces for that reason.
