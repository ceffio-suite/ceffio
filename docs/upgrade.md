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

## What it does not do

**It does not replay the optional modules.** The layers it replays are the core
ones (platform, data, identity, files, office, SSO, ingress, console). A module
installed later — `recording`, `capture`, `live-transcription`, `exapps-daemon`
— keeps the image it was installed with. That is a real gap, not a design
choice: the relay of a `recording` installation can stay several releases
behind, and `ceffio module install <id>` answers "already installed" instead of
replaying.

To see whether an installation is in that state:

```bash
ceffio sbom --cluster
```

It reports `divergence` when two references of the same image run at once.
