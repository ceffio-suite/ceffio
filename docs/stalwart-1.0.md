# Stalwart 1.0 — migrating a live mail store

Stalwart 1.0 **cannot open a store created by a pre-1.0 server**. It says so and
stops:

```
Server startup error (server.startup-error): details = The data store was
created by a Stalwart version prior to 1.0 and cannot be opened by this
version.
```

Measured on `v1.0.3` with the production volume copied byte for byte: the pod
loops in `CrashLoopBackOff`. There is no in-place upgrade (upstream:
<https://stalw.art/docs/install/upgrade/>, <https://stalw.art/docs/migration/upgrade-0-16/>) —
the store is converted **offline**, by `stalwart-migrate`, into a **new empty**
volume, and the server is then pointed at the converted volume.

The registry pins Stalwart `v1.0.3`, so this conversion is a prerequisite of
the release that carries it — not an option.

## What the code does, and what it refuses to do

- `internal/version` pins `v1.0.3`; a fresh installation starts on an empty
  store, which needs no migration at all.
- `internal/mail/sso.go` writes the OIDC directory **in the format of the
  server in front of it**: `acceptedAudiences` from 1.0 on, `requireAudience` +
  `requireScopes` before. 1.0 refuses the old names (`invalidPatch`,
  `Invalid property: requireAudience`), and writing them would abort
  `ceffio upgrade` after the new pod is already serving. The format is read
  from the directory object already stored — no endpoint exposes the version
  (`/api/server`, `/api/version`: 404).
- `ceffio upgrade` **refuses to cross that major version** unless told the
  migration was done: a `0.x → 1.x` bump of `stalwart` is a blocker
  ("crosses a major version whose data store is incompatible"), and
  `--allow-major-migration` is the only thing that lifts it. The refusal
  happens at preflight, before the backup and before anything is modified.

## Before you start

- the installation is healthy (`ceffio status`, `ceffio doctor`);
- you have room for one extra copy of the mail volume (the store of this
  installation is ~3 MB; a 2 Gi volume is enough for a large mailbox);
- **`ceffio backup` does not cover the mail volume.** It archives the
  config maps, the three SQL dumps and the Nextcloud/ONLYOFFICE volumes —
  verified by listing a real archive (`configmaps/`, `db/`, `volumes/`): no
  `stalwart`. The mail store has to be saved explicitly, as below.
- no `ceffio upgrade` has been run with the new binary yet (it would move mail
  to 1.0.3 before the conversion and the pod would crash-loop).

Set the working variables:

```sh
NS=ceffio-mail
K=/etc/rancher/k3s/k3s.yaml          # the server's kubeconfig
STAMP=$(date +%Y%m%d-%H%M%S)
```

## The runbook

Every command below was replayed on a copy of the production store before
being written here; the numbers in "What the rehearsal measured" are that
replay.

### 1. Stop mail

```sh
sudo -n kubectl --kubeconfig $K -n $NS scale deploy/stalwart --replicas=0
sudo -n kubectl --kubeconfig $K -n $NS wait --for=delete pod \
  -l app.kubernetes.io/name=stalwart --timeout=300s
```

A file-level copy of a running RocksDB is not a backup: the store is closed
before anything is touched.

### 2. Save the pre-1.0 store, and verify the archive

```sh
sudo -n kubectl --kubeconfig $K -n $NS apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata: {name: stalwart-save, namespace: ceffio-mail}
spec:
  restartPolicy: Never
  securityContext: {runAsUser: 2000, runAsGroup: 2000, fsGroup: 2000}
  containers:
  - name: save
    image: docker.io/library/alpine:3.22
    command: ["sleep", "3600"]
    volumeMounts: [{name: src, mountPath: /src, readOnly: true}]
  volumes:
  - name: src
    persistentVolumeClaim: {claimName: stalwart-data, readOnly: true}
YAML
sudo -n kubectl --kubeconfig $K -n $NS wait --for=condition=Ready pod/stalwart-save --timeout=180s

sudo -n kubectl --kubeconfig $K -n $NS exec stalwart-save -- \
  tar czf - -C /src . > /home/ubuntu/stalwart-0.16-$STAMP.tar.gz
tar tzf /home/ubuntu/stalwart-0.16-$STAMP.tar.gz | wc -l     # not 0
```

This archive is the rollback: it is the only copy of the 0.16 store once the
volume is converted.

### 3. Copy, convert into a new volume, keep the state

Three volumes: the **source copy** (`/src`, read-only), the **converted
store** (`/dst`), and the **state directory** (`/state`) — the state holds
`answers.toml` and the progress of each run, so it must survive a pod
restart.

```sh
# the answers recorded during the rehearsal, against a copy of this very store
# (identical settings, so `prepare --non-interactive` has nothing left to ask)
sudo -n kubectl --kubeconfig $K -n $NS create configmap stalwart-migrate-answers \
  --from-file=answers.toml=docs/stalwart-1.0/answers.toml

sudo -n kubectl --kubeconfig $K -n $NS apply -f docs/stalwart-1.0/manifests.yaml
sudo -n kubectl --kubeconfig $K -n $NS wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/stalwart-copy --timeout=300s
sudo -n kubectl --kubeconfig $K -n $NS logs stalwart-copy     # "N.NM /src"
```

`manifests.yaml` creates three volumes and three pods:

- `stalwart-src`, filled by `stalwart-copy` from `stalwart-data` (read-only);
- `stalwart-v1`, the **empty** target — 1.0 refuses to convert onto a store
  that already exists;
- `stalwart-state`, the state directory (`answers.toml`, run progress);
- `stalwart-migrate`, with the tool
  `docker.io/stalwartlabs/stalwart-migrate:1.0.7@sha256:368725b2…`.

The tool finds the store through the **config map**, so source and target are
the same `config.json` with different path maps (`/src`, `/dst`).

### 4. Prepare, run, finalise, verify

```sh
E="sudo -n kubectl --kubeconfig $K -n $NS exec stalwart-migrate -- stalwart-migrate"
SRC="--source /etc/stalwart/config.json --path-map /var/lib/stalwart=/src"
DST="--target /etc/stalwart/config.json --target-path-map /var/lib/stalwart=/dst --state /state"

$E prepare $SRC --state /state --non-interactive   # exits 1 if a question remains
$E run     $SRC $DST
$E run     $SRC $DST --final --yes                 # no writes to /src any more
$E verify  $SRC $DST --full                        # every account, every change row
$E report  --state /state --severity warning
```

`prepare --non-interactive` is what makes this runnable without a terminal:
it re-reads `answers.toml` and refuses to continue while a question is
unanswered.

`verify --full` is not optional. It is the only step that says the converted
store contains what the old one contained; the 1.0 server will start on a
half-copied store without complaining.

### 5. Exchange the volumes

The volume root **is** the store: there is no directory to rename inside it.

`stalwart-swap` (in the same `manifests.yaml`) empties `stalwart-data` and
copies `stalwart-v1` over it, as the volume owner:

```sh
sudo -n kubectl --kubeconfig $K -n $NS wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/stalwart-swap --timeout=300s
sudo -n kubectl --kubeconfig $K -n $NS logs stalwart-swap
```

It must print the store listing, not an error: that output is the only
confirmation that the conversion landed where the server will look.

The archive from step 2 is now the rollback.

### 6. Install the release that pins 1.0.3

Install the **binary only** — the conversion is done, the deployment is still
scaled to zero:

```sh
sudo -n install -m 0755 ceffio /usr/local/bin/ceffio
sudo -n env KUBECONFIG=$K BAO_ADDR=http://127.0.0.1:32334 BAO_TOKEN=… \
  CEFFIO_ACME_EMAIL=admin@ceffio.org CEFFIO_ACME_CHALLENGE=dns01 \
  CEFFIO_DNS_PROVIDER=cloudflare CEFFIO_DNS_ZONE=ceffio.org \
  /usr/local/bin/ceffio upgrade --domain ceffio.org --allow-major-migration
```

`--allow-major-migration` is the attestation the preflight asks for: it lifts
the `0.x → 1.x` blocker and **nothing else**. Without it the preflight
refuses before taking the backup.

### 7. Prove it

```sh
sudo -n kubectl --kubeconfig $K -n $NS get pods                       # 1/1 Running
sudo -n kubectl --kubeconfig $K -n $NS exec deploy/stalwart -- \
  /usr/local/bin/stalwart --version                                   # 1.0.3
sudo -n kubectl --kubeconfig $K -n $NS exec deploy/stalwart -- \
  curl -fsS http://localhost:8080/healthz/live                         # 200
ceffio sbom --cluster   # no drift
ceffio status           # every layer Ready
```

Then the mail itself, which is what the owner sees:

- the admin account and the domains are listed by the management API
  (`x:Account/get`, `x:Domain/get` with `-u "$STALWART_RECOVERY_ADMIN"`);
- `/api/discover/<account>@<domain>` still points at the Keycloak issuer — the
  module's final check;
- a message delivered to the admin address over SMTP is visible over IMAP
  (`Mailbox/get` on the account), and a message sent from the WebUI arrives.

### 8. Clean up

```sh
sudo -n kubectl --kubeconfig $K -n $NS delete pod \
  stalwart-save stalwart-copy stalwart-swap stalwart-migrate
sudo -n kubectl --kubeconfig $K -n $NS delete pvc stalwart-src
sudo -n kubectl --kubeconfig $K -n $NS delete configmap stalwart-migrate-answers
# keep stalwart-v1 and stalwart-state for a few days: they are the evidence,
# and the source of a second attempt if the first one has to be redone.
```

## Rollback

The 0.16 store is gone; the archive is the store.

```sh
sudo -n kubectl --kubeconfig $K -n $NS scale deploy/stalwart --replicas=0
# recreate the save pod of step 2, then:
sudo -n kubectl --kubeconfig $K -n $NS exec -i stalwart-save -- \
  tar xzf - -C /src < /home/ubuntu/stalwart-0.16-$STAMP.tar.gz
sudo -n kubectl --kubeconfig $K -n $NS set image deploy/stalwart \
  stalwart=docker.io/stalwartlabs/stalwart:v0.16.27@sha256:c429b311…
sudo -n kubectl --kubeconfig $K -n $NS scale deploy/stalwart --replicas=1
```

0.16 still opens its own store: this is exactly the state of the
installation before the window. Rebooting 1.0 later means redoing the
conversion from the restored store.

## What changes for the users

- **Sessions are not migrated**: everyone signs in again (OAuth tokens and
  app passwords live in the old store's own format). IMAP/CalDAV/CardDAV
  clients re-authenticate and re-sync once.
- **The search index is rebuilt** on the first 1.0 start: search is empty or
  partial for a few minutes on a large mailbox.
- **Ports change**: the 1.0 defaults observed on this installation are
  25, 443, 465, 993, 995, 4190 and 8080 — submission on 587 and IMAP on 143
  are **not** listening. A client configured for 587/143 keeps failing
  until it is moved to 465/993 (or the listeners are re-added).
- OIDC audiences are enforced against `acceptedAudiences` = the WebUI client
  identifier, as before.

## What the rehearsal measured

Run against a byte-for-byte copy of the production store, on a scratch volume:

| Step | Result |
|---|---|
| `prepare` | 2741 objects reviewed, 12 dropped, 60 warnings, **0 errors** |
| `run` | completed, incl. a second pass (incremental) |
| `run --final` | completed |
| `verify` | **1 account, 0 mismatches** |
| boot of `v1.0.3` on the converted store | `1/1 Running`, `--version` → `1.0.3`, `/healthz/live` 200, `/api/account` 200 |
| inventory on 1.0.3 | account `b` (`adminceffio`, Admin, same `createdAt`), domains `ceffio.org` (id `b`) and `ceffio.local` (id `c`) attached to the OIDC directory, four roles, `Application` `jkewme17aaab` (`oauthClientId stalwart-webui`), `x:AllowedIp` `10.42.0.0/16` |
| SSO check | `/api/discover/adminceffio@ceffio.local` returns the Keycloak issuer |
| writes replayed | `x:Authentication/set`, `x:SystemSettings/set`, `x:Domain/set`, `x:Account/set`, `x:Application/set` → `updated`; `x:Directory/set` with `requireAudience` → **refused** (`invalidPatch`), with `acceptedAudiences` → `updated` |
| mail round-trip | message accepted over SMTP (`220 mail.ceffio.org Stalwart ESMTP`) and visible over JMAP (`Mailbox/get`), filed in Junk (no SPF/DKIM on the injected message) |

The rehearsal is why the payload decision in `sso.go` is not a guess, and why
the blocker in `ceffio upgrade` exists.