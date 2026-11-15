# Secrets

**OpenBao is the only SOURCE of secrets. It is not the only PLACE they appear.**

That distinction matters, and the README used to blur it: it claimed no application
credential existed as a Kubernetes Secret anymore. That is false, and a reader who
believed it would go looking for a leaked credential that is in fact a deliberate copy.

## The rule

Every secret is **generated** or **entered** in one place — OpenBao — and reaches the
process that needs it through one of two paths:

1. **The injector writes a file** inside the pod (`/secrets/env`), which the container's
   startup command sources. This is the normal case: Keycloak, Nextcloud, Stalwart,
   PostgreSQL.
   A program that reads a **path given on its command line** gets one file per value
   instead: oauth2-proxy accepts `--client-secret-file` and `--cookie-secret-file`, so the
   injector renders `/secrets/client-secret` and `/secrets/cookie-secret`. Each file holds
   the value and nothing else — not even a final newline, which the proxy does not trim.
2. **A Kubernetes Secret is written from the vault**, for software that can only read its
   credentials from Kubernetes or from a generated file. These are the exceptions, listed
   below.

Nothing is ever **entered** directly into a Kubernetes Secret. The values always come from
OpenBao; what changes is how they reach the process.

## The exceptions, and why each one exists

| Secret | Who writes it | Why not the injector |
|---|---|---|
| `cert-manager/ceffio-acme-dns` | `internal/ingress/dnswebhook.go` | cert-manager resolves the ClusterIssuer's `secretRef` itself. It has no way to reach OpenBao, and it is not our process to teach. |
| `ceffio-video/ghcr-pull` | `internal/talk/talk.go` | It is a `kubernetes.io/dockerconfigjson`, consumed by the kubelet to pull images. The kubelet reads it from the API, never from a mounted file. |

The mail server used to be a third entry here: Stalwart's administration credential was a
Secret written from the vault. It is gone since 0.11.0 — the workload reads
`kv/ceffio/stalwart/admin` through the injector, and `internal/mail` now prints
`Kubernetes Secret "stalwart-admin" still present — dead copy, to be removed` when an
older installation leaves one behind. A value in two places drifts, and the workload now
reads only the injected one.

`ceffio-system/longhorn-oauth2-proxy-vault` used to be on this list. It is gone: the module
now declares its vault access (`Info.Vault`) and oauth2-proxy reads its two credentials
from injected files. Keeping a Secret was a second copy of a credential, kept in sync by
nothing — a rotation in OpenBao left the pod authenticating with the old value, and no
error said so. An installation that upgrades deletes the leftover Secret on its next
install.

Each is a copy with a short life, not a second source: regenerating the value happens in
OpenBao, and the copy is rewritten from it on the next `ceffio install`.

## What the console refuses to do

The console **never reads a secret's value**. Its RBAC reference forbids it, and the
refusal is deliberate: reading the platform's Secrets from a web page is the shortest path
to leaking all of them.

This has a consequence that cost real time to discover: the TLS page **cannot** read the
DNS credential, the Secret that holds it, nor the ClusterIssuer. It answers the question
"is renewal configured?" from the **certificates themselves** — a Certificate that is
Ready proves the solver could sign. See [tls.md](tls.md).

## The vault's own bootstrap

OpenBao is initialised once, and its root token is revoked as soon as a scoped token
exists. The recovery keys are the only way back in if that scoped token is lost — they are
shown once at initialisation, and belong somewhere other than the machine.

`ceffio backup` includes the vault's key-value tree — every entry under `kv/ceffio`,
values included, dumped through `bao kv list` and `bao kv get` — plus the two Secrets the
vault needs to run: `openbao-token` and `openbao-unseal-key`. Both are Secrets already
present on the machine, like the database passwords; archiving them means a restore puts
the vault back as it was, including the token the other modules authenticates with.

It does **not** include the recovery keys, and that line is deliberate: they are the only
way back in if the vault itself is lost, they do not live on the machine, and a backup
that carries both the data and the keys that open it is not a backup, it is a copy of the
risk. Losing the vault therefore remains a manual rebuild — `operator init` with the
recovery keys, then re-writing the entries with `bao kv put` from the archive's
`vault/kv-ceffio.json` — and a restore into a **new** cluster records a failure for the
vault step instead of pretending to have restored it: the archived `openbao-token` was
issued by the vault that no longer exists, and the new vault will not accept it.

## Working with the vault

```bash
ceffio vault                 # deploy and ready the vault; idempotent
```

`ceffio vault` **deploys** the vault — it has no sub-commands. It creates the namespace,
the unseal key, the configuration, the StatefulSet, initialises OpenBao if it is not
already initialised, enables the KV engine, creates the administration policy and a
derived token, revokes the root token, and finishes with an end-to-end check that the
vault **refuses** a path outside the policy.

Running it again destroys nothing and regenerates no key. Re-initialising an initialised
vault would make every existing secret unreadable — which is why it does not.

An operator reads or writes an entry with the `bao` CLI inside the vault pod, through the
web interface at `bao.<domain>` — which signs in through the same Keycloak account, like
everything else — or with `ceffio module config` for the settings the modules expose.

## Rotation

The administration account's password is rotated from the console: it is generated once,
applied to Keycloak and to Nextcloud, and **shown only once**. No system can read it back
afterwards; only an irreversible fingerprint is kept.

The mail server is covered **through that directory** rather than written to, and that is
deliberate: `adminceffio@ceffio.local` has no local Stalwart password. It belongs to a
domain attached to the OIDC directory, and Stalwart 1.0 refuses to give it one
(`x:AccountPassword/set` answers `forbidden`, "Your account does not support password
changes" — measured on 1.0.3 with an account in the same domain). The rotation checks with
`/api/discover/<account>` that mail delegates to the platform's Keycloak realm, and reports
the step as SSO. The endpoint it used before 0.10.21, `PATCH /api/principal/{name}`, was
removed in Stalwart 0.16 and could only answer 404.

Every other secret is generated at installation and **reused** on every subsequent run.
Regenerating one silently would break the pair that depends on it — a database password
the database no longer accepts, or an OIDC client secret Keycloak no longer knows — with a
failure that names nothing.

## See also

- [architecture.md](architecture.md) — which layer owns which namespace
- [tls.md](tls.md) — the DNS credential, and why the console reads it indirectly
- [keycloak-production.md](keycloak-production.md) — the identity layer's own secrets