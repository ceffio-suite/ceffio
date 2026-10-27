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
| `ceffio-mail/*` | `internal/mail/mail.go` | Stalwart's own administration calls need a credential at a moment when no pod is available to inject into. |

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

`ceffio backup` includes the vault's data. It does **not** include the recovery keys: a
backup that carries both the data and the keys that open it is not a backup, it is a
copy of the risk.

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

Every other secret is generated at installation and **reused** on every subsequent run.
Regenerating one silently would break the pair that depends on it — a database password
the database no longer accepts, or an OIDC client secret Keycloak no longer knows — with a
failure that names nothing.

## See also

- [architecture.md](architecture.md) — which layer owns which namespace
- [tls.md](tls.md) — the DNS credential, and why the console reads it indirectly
- [keycloak-production.md](keycloak-production.md) — the identity layer's own secrets