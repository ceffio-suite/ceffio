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
  It fires whenever the plan can read a version to compare: for a running
  component, and — since 0.10.20 — for one whose deployment is scaled to zero,
  because the image is then read from the workload (step 6). Releases before
  0.10.20 read the pods only and let a stopped component pass unchallenged.

## Before you start

- the installation is healthy (`ceffio status`, `ceffio doctor`);
- you have room for one extra copy of the mail volume (the store of this
  installation is ~3 MB; a 2 Gi volume is enough for a large mailbox);
- **on the version that runs the 0.16 store, `ceffio backup` does not cover the
  mail volume.** That backup archives the config maps, the three SQL dumps and
  the Nextcloud/ONLYOFFICE volumes — verified by listing a real archive
  (`configmaps/`, `db/`, `volumes/`): no `stalwart`. Mail joined the backup in
  0.11.0 ([mail.md](mail.md)), which is the release this conversion prepares, so
  the store has to be saved explicitly here, as below.
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
  -l app=stalwart --timeout=300s
```

The selector is `app=stalwart`: the pods of the deployment carry
`app: stalwart`, not `app.kubernetes.io/name`. The wrong selector matches
nothing and the `wait` returns immediately — it looks like the store is
closed when the pod is still writing to it.

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
volume is converted. Restoring it was replayed end to end — untar into the
volume, then compare every file against the archive: 36 files, identical
SHA-256 for all of them.

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

`manifests.yaml` creates three volumes and two pods:

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

> `swap.yaml` is a **separate file** for a reason: it empties the live volume
> as soon as it is applied. Applied with the rest, before the conversion, it
> destroys the 0.16 store. Apply it here, and nowhere else.

`swap.yaml` empties `stalwart-data` and copies `stalwart-v1` over it, as the
volume owner, then compares the two trees:

```sh
sudo -n kubectl --kubeconfig $K -n $NS apply -f docs/stalwart-1.0/swap.yaml
sudo -n kubectl --kubeconfig $K -n $NS wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/stalwart-swap --timeout=600s
sudo -n kubectl --kubeconfig $K -n $NS logs stalwart-swap
```

The log must contain `SWAP_IDENTICAL` — that is `diff -r` over the whole
store, and the only confirmation that what the server will open is what
`verify` approved. Without it, stop: the archive from step 2 is the way back.

The archive from step 2 is now the rollback.

### 6. Install the release that pins 1.0.3, and start mail again

Install the **binary only** first:

```sh
sudo -n install -m 0755 ceffio /usr/local/bin/ceffio
```

**Mail runs nowhere at this point, and the plan must say so.** The image the
plan compares comes from the workload's spec first (`internal/upgrade/plan.go`,
`imagesDesWorkloads`), the pods second. A deployment scaled to zero is
therefore reported `stalwart v0.16.27 → v1.0.3 (stopped: 0 replicas)`, and
because it now has a version to compare, the `0.x → 1.x` blocker **fires**:
`--plan` refuses until `--allow-major-migration` is passed — that flag is your
confirmation that step 3's migration is done. The full upgrade then restarts
mail: `mail.Deploy` applies the deployment with `replicas: 1` and waits for its
rollout, so the layer comes back on 1.0.3, over the store step 3 converted.

**Measured in this window (binary 0.10.19, before that reading existed).** The
plan printed `stalwart — not deployed`, said nothing about the pending bump,
and the deployment stayed at 0 replicas: the plan read the pods only, so the
component had no version at all and the `0.x → 1.x` blocker could not fire. The
full upgrade never reached the mail layer either — it was refused at preflight
(`CEFFIO_ACME_EMAIL is required`), and mail stayed down until the manual path
(b) below. The reading is what changed; the replay itself always applied
`replicas: 1`.

Two manual ways to bring it back, in this order.

**a. `ceffio mail`** reinstalls the mail layer from the registry — it is the
supported path, and the one that also re-applies the SSO directory:

```sh
sudo -n env KUBECONFIG=$K BAO_ADDR=http://127.0.0.1:32334 BAO_TOKEN=… \
  /usr/local/bin/ceffio mail --domain <domain>
```

It needs the **outbound relay** credentials (vault `ceffio/smtp/relais` keys
`relais`, `username`, `password`, or the Secret `ceffio-files/nextcloud-smtp`).
When neither exists it stops before touching anything, with
`ceffio: outbound relay user not found: exit status 1` — the relay then only
lives in the old store, and the command has nothing to write.

**b. Without the relay entry**, take the image from the SBOM — it is the
registry reference, digest included — and put it on the deployment:

```sh
sudo -n /usr/local/bin/ceffio sbom -o /tmp/sbom.json
IMG=$(python3 - <<'PY'
import json
d = json.load(open("/tmp/sbom.json"))
for c in d["components"]:
    if c["name"] == "stalwart":
        print(next(p["value"] for p in c["properties"]
                   if p["name"] == "ceffio:image"))
PY
)
sudo -n kubectl --kubeconfig $K -n $NS set image deploy/stalwart stalwart="$IMG"
sudo -n kubectl --kubeconfig $K -n $NS scale deploy/stalwart --replicas=1
sudo -n kubectl --kubeconfig $K -n $NS rollout status deploy/stalwart --timeout=300s
```

Then run the full upgrade, relay or not: now that the pod runs, `upgrade`
sees the component, reasserts the registry image and replays the other
layers (backup, ACME, DNS, SSO):

```sh
sudo -n env KUBECONFIG=$K BAO_ADDR=http://127.0.0.1:32334 BAO_TOKEN=… \
  CEFFIO_ACME_EMAIL=admin@ceffio.org CEFFIO_ACME_CHALLENGE=dns01 \
  CEFFIO_DNS_PROVIDER=cloudflare CEFFIO_DNS_ZONE=ceffio.org \
  /usr/local/bin/ceffio upgrade --domain <domain>
```

`BAO_TOKEN` is not optional: with `BAO_ADDR` alone the run stops at
`vault unreadable for keycloak/db: vault refused (HTTP 403)`; the token is
`kubectl -n ceffio-vault get secret openbao-token -o jsonpath='{.data.token}' | base64 -d`.

> Before reading `ceffio upgrade --plan`, delete every throwaway pod anyway:
> the plan now prefers the workload's declared image, but a component deployed
> by an operator (cnpg, cert-manager) has no workload of ours to read and
> still falls back to the pods. Measured on this installation: a single test
> pod running 1.0.3 made the plan report `stalwart v1.0.3` while the deployment
> still pinned 0.16.27 — the drift the plan exists to catch. Fixed for
> workloads in 0.10.20: #167.

### 7. Prove it

```sh
NS=ceffio-mail
sudo -n kubectl --kubeconfig $K -n $NS get pods                       # 1/1 Running
sudo -n kubectl --kubeconfig $K -n $NS exec deploy/stalwart -- \
  /usr/local/bin/stalwart --version                                   # 1.0.3
sudo -n kubectl --kubeconfig $K -n $NS exec deploy/stalwart -- \
  curl -fsS http://localhost:8080/healthz/live                        # 200
sudo -n kubectl --kubeconfig $K -n $NS exec deploy/stalwart -- \
  curl -fsS -u "$STALWART_RECOVERY_ADMIN" http://localhost:8080/api/account  # 200
sudo -n env KUBECONFIG=$K /usr/local/bin/ceffio sbom --cluster       # exit 0, "The cluster matches the registry."
sudo -n env KUBECONFIG=$K /usr/local/bin/ceffio doctor               # no problem detected
sudo -n env KUBECONFIG=$K /usr/local/bin/ceffio status               # 45/45 ready
sudo -n env KUBECONFIG=$K /usr/local/bin/ceffio mail sso             # sign-in goes through the IdP
```

`ceffio upgrade --plan` must then print `=` for every component and
`✓ No version drift: nothing to upgrade.` — that is the proof the deployment
carries the registry digest, not just a tag.

Then the mail itself, which is what the owner sees. Over the management API
(same basic auth as above):

- `x:Domain/get` lists both domains, each bound to the OIDC directory
  (`directoryId`), with the DKIM settings (`Dkim1Ed25519Sha256`,
  `Dkim1RsaSha256`, same selector template);
- `x:Account/get` lists the admin account with its `emailAddress` and its
  `createdAt` unchanged by the migration.

Delivery, end to end, without needing the account password:

```sh
# inject a message on the inbound listener, STARTTLS on 25
sudo -n kubectl --kubeconfig $K -n $NS exec deploy/stalwart -- sh -c '
  printf "From: sender@example.net\nTo: adminceffio@ceffio.local\nSubject: round-trip\n\nbody\n" > /tmp/in.eml
  curl -sk --url smtp://localhost:25 --ssl-reqd --mail-from sender@example.net \
    --mail-rcpt adminceffio@ceffio.local -T /tmp/in.eml'          # 250 2.0.0 Message queued with id …
# read it back
sudo -n kubectl --kubeconfig $K -n $NS exec deploy/stalwart -- sh -c '
  set -a; . /secrets/env; set +a
  curl -s -u "$STALWART_RECOVERY_ADMIN" -H "Content-Type: application/json" \
    -d "{\"using\":[\"urn:ietf:params:jmap:core\",\"urn:ietf:params:jmap:mail\"],\"methodCalls\":[[\"Email/query\",{\"accountId\":\"<account id>\"},\"q\"]]}" \
    http://localhost:8080/jmap'                                  # the message id is listed
```

IMAP is reachable on 993 (`LIST`, `SELECT INBOX` with the recovery admin).

> Submission on 465 is **not** verified by the runbook, and this installation
> cannot verify it: the account has no known password (the vault secret
> authenticates the server-level `admin`, whose login answers `454 4.7.0
> Temporary authentication failure`, and the same login submitting as
> `adminceffio@ceffio.local` answers `501 5.5.4 You are not allowed to send
> from this address`). Rehearse submission with the owner's own credentials
> before announcing the window: a 0.16 install answering the same 501 proves
> this is a property of the account, not of the migration.

### 8. Clean up

```sh
sudo -n kubectl --kubeconfig $K -n $NS delete pod \
  stalwart-save stalwart-copy stalwart-swap stalwart-migrate
sudo -n kubectl --kubeconfig $K -n $NS delete configmap stalwart-migrate-answers
sudo -n kubectl --kubeconfig $K -n $NS delete pvc \
  stalwart-src stalwart-v1 stalwart-state
```

`stalwart-v1` and `stalwart-state` are evidence, not a backup: delete them
once `--plan` reports no drift and `sbom --cluster` matches. The archive from
step 2 is the only copy worth keeping, and it is the rollback.

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
- **The console's password rotation no longer reports a mail failure.** The
  mail administrator (`adminceffio@ceffio.local`) has no local password: its
  domain is attached to the OIDC directory, and `x:AccountPassword/set`
  answers `forbidden` ("Your account does not support password changes") for
  such an account. Since 0.10.21 the step verifies with
  `/api/discover/<account>` that mail delegates to Keycloak and reports SSO;
  before, it PATCHed `/api/principal/{name}`, an endpoint removed in Stalwart
  0.16 that answered 404.
- OIDC audiences are enforced against `acceptedAudiences` = the WebUI client
  identifier, as before.

## What the production window measured

The same procedure, run on the live installation on 2026-11-09 (Stalwart
`v0.16.27` → `v1.0.3`, registry `v0.10.19`):

| Step | Result |
|---|---|
| store archived (step 2) | 36 files, 2.7 MB; copy on the server, `SERVER_COPY_OK` |
| copy pod | 36 files / 2.7 MB into `stalwart-src` |
| `prepare --non-interactive` | 2741 objects, 12 dropped, 60 warnings, **0 errors** |
| `run` then `run --final --yes` | `run 1: ok` (2741 objects written), then final pass |
| `verify --full` | `1 accounts checked, 0 mismatches` |
| `report --severity warning` | 102 rows |
| `swap.yaml` | `SWAP_IDENTICAL`; `/live` = 25 entries, 1.3 MB, all `2000:2000` |
| boot of `v1.0.3` | pod `1/1 Running`, `--version` → `1.0.3`, `/healthz/live` 200, `/api/account` 200 |
| listeners | 25, 443, 465, 993, 995, 4190, 8080 (no 587, no 143) |
| inventory | domains `ceffio.org` (`b`) and `ceffio.local` (`c`), both on the OIDC directory, DKIM Ed25519+RSA kept; account `adminceffio` (`b`, Admin) with its `createdAt` |
| SSO | `ceffio mail sso` → `✓ the sign-in goes through the identity provider`, issuer `https://keycloak.ceffio.org/realms/ceffio` |
| delivery | `250 2.0.0 Message queued with id 4b64bca50000002`, visible over JMAP (`Email/get`: subject, sender, `receivedAt`) and IMAP |
| drift | `ceffio upgrade --plan` → `✓ No version drift: nothing to upgrade.` |
| SBOM | `sbom --cluster` exit 0, 34 components, `The cluster matches the registry.` |
| health | `doctor` → no problem detected; `status` → 45/45 ready |

Two things went wrong, and the runbook now prevents them: the swap pod was
applied with the rest of the manifests, before the conversion (it emptied the
live volume — restored from the step 2 archive, byte-for-byte identical), and
`ceffio upgrade` cannot restart a component whose deployment is at zero
replicas (step 6).

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
| mail round-trip | injected on the inbound listener (`smtp://localhost:25`, STARTTLS) → `250 2.0.0 Message queued with id …`, then read back over JMAP (`Email/query` + `Email/get`) and over IMAP (993). Submission (465) needs the account's own password: the recovery admin's login answers `454`, and it owns no address (`501`) |

The rehearsal is why the payload decision in `sso.go` is not a guess, and why
the blocker in `ceffio upgrade` exists.