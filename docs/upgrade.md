# Upgrading an installation

```bash
ceffio upgrade --plan          # what would change, without changing it
ceffio upgrade                 # backup, then replay the deployment
```

An upgrade is a **replay**, not a separate code path: every layer re-applies its
manifests at the version pinned by the registry, and each is idempotent. There
is therefore no "upgrade logic" that could drift from the installation logic.

The binary is part of what is upgraded: the console, the Talk relay and the
public-IP reporter all run the same image, and the plan compares it like any
other component.

## What the command needs in its environment

The replay reads the same settings the installation was given, and refuses to
invent them:

| Variable | Why |
|---|---|
| `BAO_ADDR`, `BAO_TOKEN` | the vault: the layers read their secrets there |
| `CEFFIO_ACME_EMAIL` | Let's Encrypt registration and expiry warnings — an address the operator chose, never a default |
| `CEFFIO_ACME_CHALLENGE`, `CEFFIO_DNS_PROVIDER`, `CEFFIO_DNS_ZONE` | the challenge the installation chose (HTTP-01, or DNS-01 with its provider) |

Without them the upgrade stops at the layer that needs them, **after** taking
the backup, and says which one is missing. That is deliberate: an upgrade that
silently rewrote the ClusterIssuers back to HTTP-01 would lose a DNS-01 wildcard
at the next renewal.

## When a component needs its data migrated

One refusal is not negotiable by the plan alone: a component whose **major
version** changes format on disk. Stalwart 1.0 cannot open a store created
before it, and starting it on one puts the pod in `CrashLoopBackOff` while
every other layer reports success.

`ceffio upgrade` therefore raises a blocker for a `0.x → 1.x` bump of
`stalwart`, before the backup and before anything is modified, pointing at the
conversion runbook. `--allow-major-migration` lifts that blocker — and only
that one: an unhealthy cluster, a failing backup or an inconsistent registry
still stops the upgrade.

```bash
ceffio upgrade --plan                            # shows the blocker
ceffio upgrade --domain example.org --allow-major-migration
```

The conversion itself is offline, on a stopped server:
[stalwart-1.0.md](stalwart-1.0.md).

## Optional modules are replayed too

An upgrade is a **convergence**, not only a version bump. The core layers are
replayed, and so are the optional modules that are installed: their image is not
a component of the version registry, so the plan cannot see it — but it follows
the binary, and only a replay makes it.

The replay only *replays*: a module whose state is not `installed` is left
alone, so an upgrade never installs something the operator did not ask for. A
module that fails stops the upgrade and is named.

## Checking that nothing lags

```bash
ceffio sbom --cluster
```

It reports a `divergence` when two references of the same image run at once —
the signature of a component that was deployed once and never refreshed. On a
converged installation it prints `The cluster matches the registry.` and exits
0.
