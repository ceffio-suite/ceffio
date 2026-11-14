# Implementation plan — mail as an optional module, internal users, platform mail (0.11.0)

Status: accepted by the maintainer (2026-11-14) and **delivered in 0.11.0**:
PR 0 (POC, results and design amendments in §9) and PRs 1–10 are merged, and
the release follows §7. This document stays the design record — the decisions,
the measured facts of §9 and the PR chain; the operator's guide is
[mail.md](mail.md). Every product decision is recorded in §2; the places where
the implementation had to stop and ask are listed in §0.5 (gate 3, the host
exposure fix, was deferred by the maintainer to a later release).

This plan was written after a read-only inspection of the demo server (v0.10.22)
and of the Stalwart 1.0 documentation. The demo is only evidence of what the
current procedure produces: **every change below goes through `ceffio install`,
`ceffio upgrade`, the console or the registry — never a manual change on a
server.** Anyone must be able to reproduce the result with the same procedure.

---

## 0. How to use this document (for the implementing agent)

### 0.1 Read first

1. `CONTRIBUTING.md` — GitFlow, "Before submitting", and the nine rules. Rules
   3 (secrets only in OpenBao, never printed), 4 (no real IP/domain/account in
   the repo), 5 (a check must be proven able to fail), 6 (read after write),
   8 (idempotency) and 9 (a feature is a module; extend the contract, never a
   feature-specific route/page/section) are the ones this plan leans on most.
2. `docs/adding-a-module.md` — the module contract, with `recording` as the
   worked example of a module that moved from the core to `Optional`.
3. `docs/stalwart-1.0.md` — what changed in Stalwart 1.0 and what Ceffio
   already learned the hard way.
4. This plan, entirely, before the first commit.

### 0.2 Working mode

- One PR per step of §6, **in the order given**. Each PR starts from an
  up-to-date `develop`, does one thing, and is mergeable on its own.
- Branch names: `feat/<slug>`, `fix/<slug>`, `chore/<slug>`, `docs/<slug>`
  (the names in §6). PR title in Conventional Commits; it becomes the commit
  message and feeds the release notes.
- Before every push:
  ```bash
  gofmt -l cmd internal test tools   # must print nothing (not `.`: a local .gomodcache breaks it)
  make build vet test                # test includes the -race -tags demo pass
  ```
- **Merge policy (decided):** the agent merges its own PR as soon as the CI is
  green, with `gh pr merge --merge --delete-branch`, then starts the next step
  from the updated `develop`. If branch protection refuses the merge (a review
  is required), the agent STOPS and asks the maintainer — it never uses
  `--admin` or any other bypass.
- Code and comments in English; identifiers and test names follow the
  surrounding code (many are French). Console strings follow the page
  (English). Comments explain WHY and keep their evidence (rule 7).
- Nothing in the repository may name the demo server, its IP or its domain:
  use `example.com`, `mail.example.com`, `<public-ip>`, `<demo-host>`.

### 0.3 Access to the demo server (decided)

The maintainer gives the host out of band (`ssh ubuntu@<demo-host>`, `sudo`
available, `sudo kubectl` for the cluster). The agent MAY:

- inspect anything read-only (never print a secret value: lengths or
  fingerprints only);
- create test objects whose names start with `ceffio-test-` (Stalwart
  accounts, Keycloak/Nextcloud users, app passwords) and **delete them when the
  step is done**;
- at the end (§8), take a backup and upgrade the demo to the release candidate,
  then to the release.

Anything else that writes to the demo (DNS, reverse DNS, firewall, deleting
non-test data) is the maintainer's call.

A helper that runs a JMAP request inside the Stalwart pod, the same way
`internal/mail/sso.go` does (the secret is sourced inside the pod, never on the
command line):

```bash
# jmap.sh '<json request>'  (read-only use unless the step says otherwise)
printf '%s' "$1" | ssh ubuntu@<demo-host> \
  'sudo kubectl -n ceffio-mail exec -i deploy/stalwart -c stalwart -- sh -c "set -a; . /secrets/env 2>/dev/null; set +a; curl -s --max-time 20 -u \"\$STALWART_RECOVERY_ADMIN\" -H Content-Type:application/json -X POST http://localhost:8080/jmap --data @-"'
```

The admin JMAP account id is `d333333` (`compteGestion` in `internal/mail/sso.go`).

### 0.4 Toolchain note

`go.mod` requires go 1.27.2; with an older local Go, `GOTOOLCHAIN=auto`
downloads it. A failed download is a network problem: retry, never lower the
`go` line.

### 0.5 Stop and ask the maintainer when

1. a merge is refused by branch protection (§0.2);
2. a POC result in PR 0 contradicts this plan (the plan is amended in the POC
   PR before anything is built on it);
3. **before merging PR 6** if the host-exposure fix (separate task: OpenBao
   NodePort, K3s API and kubelet reachable from the Internet, no host firewall)
   is not yet in `develop` — PR 6 opens port 25 to the Internet;
4. §8: the live verification needs the maintainer to publish DNS records,
   set the reverse DNS at the hosting provider, and provide one external
   mailbox for send/receive tests;
5. a fresh-install test needs a clean machine (§8.3) — ask for one; if there is
   none, say in the release PR that this scenario was not run;
6. anything would delete or overwrite data that is not a `ceffio-test-` object.

---

## 1. Goal

From the administration console:

1. enable mail (the `mail` module), and have Ceffio **check every prerequisite
   of the domain** and **set the server up** (TLS, SMTP, IMAP, submission,
   DKIM, sending, exposure) by itself;
2. create two kinds of users:
   - **external user**: an address outside the platform (e.g. a personal
     address), no mailbox — what every user is today;
   - **internal user**: a mailbox `username@<domain>` with a **1 GiB default
     quota** (adjustable), signed in through Keycloak, visible in **Nextcloud
     Mail** with nothing to configure, and usable from **Thunderbird and
     phones** with app passwords the user creates;
3. suspend, resume and delete a mailbox, and suspend, resume and delete a user;
4. make the platform's own mail (Nextcloud notifications, Keycloak password
   resets) go out through a provisioned **`noreply@<domain>`** account when
   Stalwart is installed, and through the external SMTP settings when it is not.

## 2. Decisions (taken — do not re-ask)

| # | Question | Decision |
|---|---|---|
| D1 | Core or optional | `mail` becomes `Kind: Optional`, `Default: true` (the `recording` path). `--without mail` skips it. |
| D2 | Address of an internal user | `username@<domain>` — the Keycloak username, the platform root domain (already the Stalwart domain today; `mail.<domain>` is only the host) |
| D3 | Kinds of users | Two distinct kinds, fixed at creation. An external user never gets a mailbox; an internal user is a different user (different username, separate Nextcloud space). No conversion between kinds. |
| D4 | Existing users at upgrade | They stay external. Nothing is created automatically. |
| D5 | Delete | Two actions: **delete the mailbox** (the internal user keeps Nextcloud and files; the mailbox can be recreated) and **delete the user** (Keycloak, Nextcloud with files, mailbox). No grace period; typed confirmation (the username). |
| D6 | Suspended mailbox | Sign-in refused everywhere, mail **still received**. |
| D7 | External clients in 0.11.0 | Yes: 465 (submission, implicit TLS) and 993 (IMAPS) published with 25. |
| D8 | App passwords for Thunderbird/phone | Self-service: the user creates them in Stalwart's web interface at `https://mail.<domain>`, signed in through SSO. |
| D9 | Sending | **Direct by default**; the relay is optional. Direct sending requires a correct reverse DNS and outbound port 25 (checks `ptr`, `port25-out`). |
| D10 | Platform mail | With Stalwart: Nextcloud **and** Keycloak send as `noreply@<domain>` through Stalwart. Without Stalwart: both use the external SMTP settings (the `files` module's `outgoing_mail` group). |
| D11 | DNS records | 0.11.0 displays them (from Stalwart's own zone) and checks them. Automatic publication with the ACME DNS-01 credential is 0.11.1. |
| D12 | Inbound reachability | Guided test: an automatic connection to `<public-ip>:25` from the server, then the console asks the operator to send a mail from an external address to `postmaster@<domain>` and shows the SPF/DKIM/DMARC results read from that message. |
| D13 | DNSBL | Checked, **warning only**. |
| D14 | Host firewall / exposure fix | Separate task, not in this plan — but a hard dependency of PR 6 (§0.5). |
| D15 | Demo server | The agent may run POCs and the final verification there (§0.3). |
| D16 | PR merges | The agent merges when the CI is green (§0.2). |
| D17 | Release | The agent does all of it: release branch, rc tag, merge to `main`, tag, back-merge (§7). |

## 3. Where things stand (v0.10.22)

### 3.1 Code anchors

| Area | Where | Today |
|---|---|---|
| Stalwart deployment | `internal/mail/mail.go` | `Deploy(ctx, domain, relaisHote, relaisPort, relaisUser, relaisPass)`; manifest with PVC `stalwart-data` **20Gi hard-coded**, Service ClusterIP 25/587/143/993/8080, Ingress `mail` on `mail.<domain>` with cert `mail-tls`; everything through `kubectl` (`k8s.Command`) |
| Relay | `internal/mail/mail.go` (`configurerRelais`) | only tests the credential and prints "to be finalized through the admin interface": **never written into Stalwart** |
| SSO and JMAP | `internal/mail/sso.go` | `ConfigurerSSO`; JMAP helpers `appelJMAP`, `majJMAP`, `majJMAPObjet`, `creerObjet`, `chercherID`, `lireChamps`, `lireIDs`; all via `kubectl exec` + curl in the pod |
| Mail module | `internal/modules/mail/module.go` | `Kind: Core`; `Install` refuses ("the registry does not carry the relay settings"); `State` = deployment ready; `Uninstall` refuses |
| Mail settings | `internal/modules/mail/reglages.go` | group relay: `hote`, `port`, `utilisateur`, `mot_de_passe`, `exiger_tls`; secret in vault `kv/ceffio/mail/relay`, values in ConfigMap `ceffio-system/ceffio-settings` key `mail.relay`; `Test` = `verifierRelais` |
| Install sequence | `cmd/ceffio/install.go` (~line 470–500) | unconditional `mail.Deploy` + `mail.ConfigurerSSO`; `--smtp-relais*` flags; optional modules via `installerModulesOptionnels` (`--with/--without`, help generated from the registry) |
| Redeploy (upgrade) | `internal/cluster/redeploy.go` (~line 99–115) | replays mail as a core layer |
| Optional replay | `internal/module/replay.go` `RejouerInstalles` | replays optional modules whose state is exactly `Installed` |
| Console module ops | `internal/console/module_ops.go` `runOperation` | builds `module.Env{Domain, Kube, Out}` — **no `Settings`, `Secrets`, `ModuleID`** (compare `internal/console/modules.go:96`) |
| Console image | `build/console/Dockerfile` | `FROM scratch`: **no kubectl, no shell** — a module installed from the console must use client-go only |
| Users (console) | `internal/console/users.go` | list/create (Keycloak, then Nextcloud `occ user:add`), `deactivate`/`reactivate`/`password` on Keycloak only; **no delete**; protected account `adminceffio` |
| Users (page) | `internal/console/web/index.html` `renderUsers` (~line 738) | form username/email/password; actions deactivate/reactivate/password |
| Users (CLI) | `cmd/ceffio/users.go` | stub ("not implemented") |
| Module CLI | `cmd/ceffio/module.go` | `list`, `install`, `remove`, `status` |
| Console routes | `internal/console/console.go` ~line 150–220 | closed list enforced by `internal/console/regles_generiques_test.go` (`TestRoutesConsoleAppartiennentALAListeFermee`, `TestLaPageNAppelleAucunModuleEnDur`, …) |
| RBAC | module `Permissions` → console Roles | frozen by `rbac_nonregression_test.go` (golden manifest) |
| Nextcloud SMTP | `internal/modules/files/reglages_smtp.go` | group `outgoing_mail` (`hote`, `port`, `securite`, `utilisateur`, `mot_de_passe`, `expediteur`), secret vault `smtp/relais`, written into Nextcloud with `occ` |
| Keycloak SMTP | — | **not configured at all**: Keycloak sends no mail today |
| DNS command | `cmd/ceffio/dns.go` | `ceffio dns status` only resolves A records of registry hosts; its help claims MX/SPF/DKIM/DMARC/PTR checks that do not exist |
| Backup | `internal/backup/backup.go` | `Volumes` = nextcloud-data, onlyoffice-data — **mail not backed up** |
| Public IP | `internal/publicip` (`Lire`) | the server's public address, already maintained by the `publicip` module |
| ACME DNS-01 | `internal/acme` (`providers.go`, `identifiants.go`) | provider credential table (Cloudflare, Route 53, RFC 2136, OVH, …) — reused in 0.11.1 |
| Private-domain profile | `internal/ingress/ingress.go` `isDemo` | `.local` domain: no public DNS, hostAliases, Ceffio CA |
| OPNsense exposure | `internal/expos/opnsense.go`, `cmd/ceffio/expose.go` | declares HTTP domains on os-caddy; no L4 port forwards |
| Kubernetes helpers | `internal/k8sapi` | `Appliquer`, `Executer`, `ExecuterAvecEntree`, `PodDuDeploiement`, `DeploiementPret`, `AttendrePret`, `ListerPVC`, `LireService`, `LireSecret`, … |

### 3.2 What the procedure produces (observed on the demo)

| Area | Observed |
|---|---|
| Stalwart | v1.0.3, single RocksDB store on PVC `stalwart-data` (20 Gi, 84 MB used), strategy `Recreate` |
| StorageClass | `longhorn`, `allowVolumeExpansion: true`, `reclaimPolicy: Delete` (deleting the PVC deletes the mail) |
| Stalwart domains | the root domain (addresses) and `ceffio.local` (internal SSO domain of `adminceffio`), both attached to the OIDC directory |
| OIDC directory | `claimUsername: preferred_username`, `usernameDomain: ceffio.local` |
| DKIM | keys generated (Ed25519 + RSA), automatic rotation |
| Zone | `x:Domain.dnsZoneFile` contains MX, SPF (`v=spf1 mx -all` + HELO SPF for the mail host), DKIM ×2, DMARC `p=reject`, SRV (caldavs, carddavs, imaps, jmap, pop3s, submissions), MTA-STS, TLS-RPT, autoconfig/autodiscover |
| Public DNS | none of those records published; a wildcard `A` makes every name resolve to the server |
| Reverse DNS | the hosting provider's default name, not `mail.<domain>` |
| Outbound 25 | open on this host (many hosts and ISPs block it) |
| Listeners | `smtp` 25, `submissions` 465, `imaps` 993, `pop3s` 995, `sieve` 4190, `https` 443, `http` 8080 — no 587, no 143 |
| Service | 25, 587, 143, 993, 8080 → 587 and 143 lead nowhere; 465 missing |
| Exposure | no mail port reachable from the Internet; K3s ServiceLB active (Traefik uses it on 80/443) |
| TLS | no `x:Certificate`, `SystemSettings.defaultCertificateId: null`; cert-manager `mail-tls` in `ceffio-mail` is valid for `mail.<domain>` |
| Routes | `x:MtaRoute`: `mx` and `local` only (direct delivery) |
| Accounts | only `adminceffio@ceffio.local` |
| Nextcloud | Mail 5.13.1 and user_oidc 8.13.0 enabled |
| Host firewall | none (handled by the separate task, §0.5) |

### 3.3 What the Stalwart 1.0 documentation settles

- **Quota**: `x:Account.quotas` is `Map<StorageQuota, UnsignedInt>`; disk quota
  = `quotas.maxDiskQuota` in bytes (1 GiB = 1073741824). `usedDiskQuota` is
  read-only usage. Over quota: IMAP `APPEND` → `NO [OVERQUOTA]`, JMAP
  `overQuota`; inbound SMTP is **deferred** (`451 4.3.0`) and retried.
- **Suspension**: no enable flag on accounts. `permissions:
  {"@type":"Merge","enabledPermissions":{},"disabledPermissions":{"authenticate":true}}`
  suspends every sign-in; reception continues (`emailReceive` is separate).
  Clearing the entry restores access.
- **Credentials** (`x:Account.credentials`, User only): `Password`,
  `AppPassword`, `ApiKey`, `Passkey`. App passwords: `x:AppPassword/set` with
  the user's request-level `accountId` (admin needs `impersonate` +
  `sysAppPasswordCreate`, which the admin role holds); the secret (`app_…`) is
  returned **once**; accepted by IMAP, POP3, SMTP submission, ManageSieve and
  HTTP Basic; refused at interactive sign-in (1.0.2). At most **5** app
  passwords per account (`overQuota`), and an account of an OIDC directory
  refuses `credentials` altogether ("Cannot set credentials for accounts in an
  external directory") — its only credentials are app passwords, API keys and
  passkeys (9.A).
- **Aliases**: `x:Account.aliases` is, in 1.0.3, a **map keyed by index** of
  `EmailAlias {name, domainId, description}`, patched with a pointer
  (`"aliases/0"`) or a full index map; `@type` is sent on write only, the
  read-back also has `enable` (9.B). There is no `x:Alias/*` method family
  (`unknownMethod`).
- **Certificate**: `x:Certificate {certificate, privateKey}`, each from `Text`,
  `EnvironmentVariable` (`variableName`) or `File` (`filePath`); SANs and
  validity are server-set. A `File` certificate is read at load time only: a
  changed file is picked up by the `x:Action` `ReloadTlsCertificates`, not by
  itself (9.C).
- **Nextcloud Mail** cannot pass the OIDC token over IMAP (a passwordless OIDC
  account fails with "No password provided") → Nextcloud Mail uses an app
  password created by Ceffio.

References: `https://stalw.art/docs/auth/authorization/quotas/`,
`/docs/auth/authentication/app-password/`, `/docs/ref/object/account/`,
`/docs/auth/authorization/permissions/`, `/docs/ref/object/certificate/`,
`/docs/ref/object/mta-route/`, `/docs/ref/object/mta-outbound-strategy/`,
`/docs/ref/object/network-listener/`, `/docs/management/maintenance/backup/`,
`/docs/auth/backend/oidc/`.

### 3.4 Glossary

- **Internal user**: Keycloak user with attribute `ceffio_kind=internal`, email
  `username@<domain>`, a Stalwart account, a Nextcloud Mail account.
- **External user**: any other user (attribute absent or `external`), email
  outside `<domain>`, no Stalwart account.
- **Mailbox**: the Stalwart account of an internal user.
- **Platform sender**: the SMTP identity Nextcloud and Keycloak send with.

## 4. Target design

### 4.1 The `mail` module

- `Kind: Optional`, `Default: true`, `Requires: ["identity", "ingress", "files"]`.
- Implements `module.Module`, `module.Configurable`, `module.Testable`
  (existing), and the two new interfaces `module.Checker` (§4.3) and
  `module.Accounts` (§4.6).
- **`Install` never refuses because of an external prerequisite** (DNS,
  reverse DNS, port): an operator must be able to install first and fix DNS
  after. External prerequisites gate **mailbox creation** instead, and show in
  `State`.
- `State`:
  - `Absent` when the Deployment `stalwart` does not exist;
  - `Installing` / `Unknown` as today (`socle.EtatDuDeploiement`);
  - `Degraded` when the Deployment is ready but a `Blocking` check fails —
    `Detail` names the failing checks;
  - `Installed` otherwise.
- `Uninstall`: removes the public Service, the Ingress hosts it added, the
  Deployment, ServiceAccount and ConfigMap; **keeps the PVC and the vault
  entries** (the mailboxes); switches the platform sender back to the
  external SMTP settings (§4.5); says all of this in `env.Out`. Nextcloud Mail
  accounts of internal users are left in place (they work again after a
  reinstall).
- Permissions (module `Permissions`): the standard set in `ceffio-mail`, plus
  `pods` get/list and `pods/exec` create in `ceffio-files` (occ) and
  `ceffio-identity` (Keycloak). Update the RBAC golden file in the same PR and
  say why in the PR.

### 4.2 Settings of the `mail` module

Existing group `relay` unchanged (keys and storage kept: existing installs
must not lose their values). New group `server` (values in ConfigMap key
`mail.server`, no secret):

| Key | Type | Default | Rule |
|---|---|---|---|
| `envoi` | Choice `direct` / `relais` | `direct` | `relais` requires the relay group to be filled and its `Test` to pass |
| `volume_gio` | Number | `20` | applied as `max(current PVC size, value)`; a lower value is refused with an explanation (Kubernetes cannot shrink a PVC); refused when the StorageClass forbids expansion |
| `quota_defaut_gio` | Number | `1` | 1 ≤ value ≤ `volume_gio` |
| `clients_externes` | Bool | `true` | publishes 465 and 993 (D7); `false` publishes 25 only |

`Apply` of either group re-applies the corresponding server configuration
(relay route, PVC size, exposure) and reads it back (rule 6).

### 4.3 New contract: `module.Checker`

In `internal/module` (new file `checks.go`):

```go
// CheckLevel says what a failed check means.
type CheckLevel string

const (
	CheckOK            CheckLevel = "ok"
	CheckWarning       CheckLevel = "warning"        // works, but degraded (spam, missing record…)
	CheckBlocking      CheckLevel = "blocking"       // the feature cannot work correctly
	CheckNotApplicable CheckLevel = "not_applicable" // e.g. private domain, relay mode
)

// Check is one verified prerequisite. Fix is shown verbatim (a DNS record to
// publish, a command, a sentence); the console offers to copy it.
type Check struct {
	ID     string     `json:"id"`
	Label  string     `json:"label"`
	Level  CheckLevel `json:"level"`
	Detail string     `json:"detail"`        // what was measured
	Fix    string     `json:"fix,omitempty"` // what the operator does
}

// Checker is implemented by a module whose operation depends on things
// outside the cluster. The console shows the list on the module card
// (GET /api/modules/{id}/checks); `ceffio module check <id>` prints it and
// exits 1 when a check is Blocking.
type Checker interface {
	Checks(ctx context.Context, env Env) []Check
}

// Bloquants returns the Blocking checks (helper used by State and by Accounts).
func Bloquants(checks []Check) []Check
```

### 4.4 Mail checks

DNS lookups go through **public resolvers** (default `1.1.1.1:53` and
`9.9.9.9:53`, overridable by an environment variable for air-gapped tests),
never the cluster's CoreDNS (a wildcard or split-horizon zone would answer for
records that do not exist). The DNSBL check is the exception (see below). On a
private domain (`isDemo`), every DNS/Internet check returns `not_applicable`
with "private domain: internal delivery only".

| ID | What is measured | Level when it fails |
|---|---|---|
| `mx` | MX of `<domain>` | absent → `warning` (Fix: `<domain>. MX 10 mail.<domain>.`); → another host → **`blocking`** ("another mail service receives this domain: move the MX or uninstall the mail module") |
| `a-mail` | A/AAAA of `mail.<domain>` = the public IP (`publicip.Lire`) | `blocking`; an AAAA pointing elsewhere → `warning` |
| `ptr` | PTR of the public IP = `mail.<domain>`, and `mail.<domain>` resolves back to it | `blocking` when `envoi=direct`, `warning` when `relais` (Fix: "set the reverse DNS at your hosting provider") |
| `port25-out` | TCP connect to port 25 of the first MX of a large provider (resolved at run time), **from the Stalwart pod** (its egress is what matters) | `blocking` when `envoi=direct`, `not_applicable` when `relais` |
| `relay` | the relay settings `Test` (existing `verifierRelais`) | `blocking` when `envoi=relais`, `not_applicable` otherwise |
| `tls` | STARTTLS on 25 and implicit TLS on 465/993 present a certificate valid for `mail.<domain>` (dial the Service, SNI `mail.<domain>`) | `blocking` |
| `records` | SPF, DKIM (every active selector), DMARC, MTA-STS, TLS-RPT, autoconfig/autodiscover, SRV: compared with `dnsZoneFile` of `<domain>` (internal domain excluded; SRV filtered to the published ports — no `pop3s`; `imaps`/`submissions` only with `clients_externes`) | `warning`, one check per record family, Fix = the exact records to publish. In relay mode the SPF Fix says to add the relay provider's `include:` |
| `inbound-25` | TCP connect + SMTP banner on `<public-ip>:25` from the server | `warning` (proves the port is open on the host side only) |
| `inbound-test` | last message received at `postmaster@<domain>` from an external domain, in `INBOX` **or** `Junk Mail` (a first contact is classified as spam, 9.B), ignoring DSNs from `MAILER-DAEMON` (9.F): its `Authentication-Results` (SPF, DKIM, DMARC) | `warning` until done; Fix explains the guided test (D12) |
| `dnsbl` | the public IP against `zen.spamhaus.org`, `bl.spamcop.net`, `b.barracudacentral.org` through the **system resolver** (Spamhaus refuses public resolvers and answers `127.255.255.x`, which means "could not query" → `not_applicable`) | `warning` |
| `volume` | sum of `maxDiskQuota` of all mailboxes vs PVC capacity; free space on the volume | `warning` above 100 % committed or below 10 % free |

The `tls` check dials with SNI `mail.<domain>` and will be `blocking` until
PR 6 installs the certificate: Stalwart serves its built-in
`CN=rcgen self signed cert` (SAN `DNS:localhost`) before that (9.A, 9.E).

Every check gets a unit test proving it can fail (rule 5), with a fake
resolver / fake dialer / fake JMAP — no network in unit tests.

### 4.5 Platform sender (`noreply`)

New package `internal/platformmail`:

```go
type Sender struct {
	Host, User, Password, From, FromName string
	Port     int
	Security string // "ssl" (implicit TLS) or "starttls"
}

// Resolve: the mail module installed and the noreply credential present →
// Sender{Host: "mail.<domain>", Port: 465, Security: "ssl",
//        User/From: "noreply@<domain>", Password: from vault};
// otherwise the files module's outgoing_mail settings when filled;
// otherwise nil (no platform mail).
func Resolve(ctx context.Context, env module.Env) (*Sender, error)

func ApplyNextcloud(ctx context.Context, s *Sender) error // occ config:system:set mail_* (nil → mail_smtpmode unset)
func ApplyKeycloak(ctx context.Context, s *Sender) error  // realm "ceffio" smtpServer (nil → removed)
```

- The `noreply@<domain>` Stalwart account is created by the mail module's
  `Install`: permissions `Merge` with `emailReceive` disabled (mail sent to it
  bounces), one app password named `platform-sender`, secret in vault
  `kv/ceffio/mail/noreply` (`user`, `password`). Idempotent: if the vault entry
  exists and a submission login with it succeeds, nothing changes; otherwise a
  new app password replaces the old one (destroy the old one).
- Callers: mail `Install` (after noreply), mail `Uninstall` (back to external),
  `files` `outgoing_mail` `Apply` (stores the values; applies them only when the
  mail module is absent, and says so in its result), and the optional replay at
  upgrade (through mail `Install`).
- The writer of Nextcloud's `mail_*` system config moves from
  `internal/modules/files/reglages_smtp.go` into `ApplyNextcloud`, so there is
  one writer.
- Keycloak: realm `smtpServer` = `{host, port, ssl:"true", starttls:"false",
  auth:"true", user, password, from, fromDisplayName:"<platform name>"}`, through
  the same Keycloak admin access the console and `internal/identity` already
  use. Read back after writing.
- Host name inside the cluster: Nextcloud and Keycloak connect to
  `mail.<domain>:465` so the certificate matches. POC E (9.E) showed that the
  name resolves and that pods reach a published `LoadBalancer` port through the
  public IP (hairpin works), but that 465 is not published today; and that
  when it is not published the ClusterIP path serves a certificate that does
  not match. Decision: `platformmail` probes `mail.<domain>:465` **from the pod
  that will use it** (the mail module has `pods/exec` in `ceffio-files` and
  `ceffio-identity`) and, when the port is unreachable (e.g.
  `clients_externes=false` publishes 25 only), installs an in-cluster alias
  instead of silently misconfiguring: a `hostAliases` entry
  `mail.<domain>` → Stalwart Service ClusterIP on those two Deployments,
  annotated so it is idempotent and refreshed when the IP changes. Same name,
  same certificate, no public exposure.

### 4.6 New contract: `module.Accounts`

In `internal/module` (new file `accounts.go`):

```go
// User is the platform user as the Users page knows it (Keycloak).
type User struct {
	ID, Username, Email string
	Attributes          map[string]string
}

// AccountField is a creation input a module adds to the Users form.
type AccountField struct {
	Field              // the settings Field (Key, Label, Help, Type, Default, Options, Required)
	ReplacesEmail bool // when this Bool field is true, the form hides and ignores the email input
}

// AccountResult is what a module asks the Users page to write back.
type AccountResult struct {
	Email      string            // non-empty: becomes the user's email in Keycloak and Nextcloud
	Attributes map[string]string // written as Keycloak user attributes
}

// AccountAction is an action the console offers on one user's account.
type AccountAction struct {
	ID      string  `json:"id"`
	Label   string  `json:"label"`
	Confirm string  `json:"confirm,omitempty"` // non-empty: the user must type this (the username)
	Fields  []Field `json:"fields,omitempty"`  // inputs of the action (e.g. new quota)
}

// AccountInfo is one user's account in one module, for the Users page.
type AccountInfo struct {
	Present   bool            `json:"present"`
	Suspended bool            `json:"suspended"`
	Summary   string          `json:"summary"` // e.g. "312 MiB / 1 GiB"
	Actions   []AccountAction `json:"actions"`
}

type Accounts interface {
	AccountFields(ctx context.Context, env Env) []AccountField
	// ValidateAccount runs BEFORE anything is created (Keycloak included).
	ValidateAccount(ctx context.Context, env Env, u User, v Values) error
	EnsureAccount(ctx context.Context, env Env, u User, v Values) (AccountResult, error)
	// AccountInfos is batched: one call for the whole list.
	AccountInfos(ctx context.Context, env Env, users []User) (map[string]AccountInfo, error)
	AccountAction(ctx context.Context, env Env, u User, action string, v Values) error
	// Whole-user lifecycle, called by the Users page:
	SuspendAccount(ctx context.Context, env Env, u User) error
	ResumeAccount(ctx context.Context, env Env, u User) error
	DeleteAccount(ctx context.Context, env Env, u User) error
}
```

Console flow (generic — no module name in the page or the handlers):

- `GET /api/users` → `{users: [...], fields: {<module>: [AccountField…]}, accounts: {<module>: {<userID>: AccountInfo}}}` for installed modules implementing `Accounts`.
- `POST /api/users` body gains `modules: {<module>: {<key>: <value>}}`.
  Order: `ValidateAccount` of every module → Keycloak user → Nextcloud user →
  `EnsureAccount` of every module → write back `AccountResult` (Keycloak
  email/emailVerified/attributes, Nextcloud `occ user:setting <uid> settings email`).
  If an `EnsureAccount` fails after Keycloak creation, the error is returned
  with what exists, and a retry (same request) converges (idempotent).
- `POST /api/users/{id}/deactivate|reactivate`: Keycloak `enabled`, Nextcloud
  `occ user:disable|enable` (missing today), then `SuspendAccount|ResumeAccount`
  of every module.
- `POST /api/users/{id}/delete` with `{"confirm": "<username>"}`: every
  module's `DeleteAccount`, then Nextcloud `occ user:delete`, then Keycloak
  `DELETE`. Modules first, so a failure leaves a user that can be deleted
  again. The protected account `adminceffio` is refused as today.
- `POST /api/users/{id}/accounts/{module}/{action}` → `AccountAction`.
- All of this stays under the existing `/api/users` and `/api/users/` routes:
  the closed route list does not change.
- `ceffio users` (today a stub) gets `list`, `add <username> [--email …]
  [--set <module>.<key>=<value>…]`, `deactivate`, `reactivate`, `delete
  --confirm <username>`, `account <username> <module> <action> [--set …]` —
  generated from the same contract.

### 4.7 Mail implementation of `Accounts`

- `AccountFields`: `boite` (Bool, label "Internal user with a mailbox",
  `ReplacesEmail: true`, default `true` when the mail module is installed),
  `quota_gio` (Number, default = `quota_defaut_gio`).
- `ValidateAccount`:
  - `boite=true`: username matches `[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]` or is a
    single character (the stricter form of the usual Unix name rule)
    without `..`; not reserved (`postmaster`, `abuse`, `noreply`, `no-reply`,
    `hostmaster`, `webmaster`, `admin`, `administrator`, `root`,
    `mailer-daemon`, `dmarc`, `security`, `adminceffio`); the address is not an
    existing Stalwart account or alias; **no `Blocking` check fails** (the
    error lists them); `1 ≤ quota_gio ≤ volume_gio`.
  - `boite=false`: email required and **not** on `<domain>` ("an address on
    the platform domain belongs to an internal user").
- `EnsureAccount` (`boite=true`), idempotent:
  1. Stalwart account named `<username>@ceffio.local` (the OIDC directory's
     `usernameDomain`, so a first SSO login lands on the same account, 9.B),
     `description` = Ceffio-managed marker, then the alias
     `<username>@<domain>` (`aliases/0`, 9.B) and `quotas.maxDiskQuota =
     quota_gio × 2^30` (9.G);
  2. app password `nextcloud-mail` → vault `kv/ceffio/mail/comptes/<username>`
     (destroy the previous one carrying the same `description` marker first:
     cap of 5, 9.A);
  3. Nextcloud Mail account for the user: `occ mail:account:create-imap` with
     IMAP `mail.<domain>:993 ssl` and SMTP `mail.<domain>:465 ssl`, login =
     `<username>@ceffio.local`, password = the app password (9.J: the
     provisioning path needs a master password or the user's Nextcloud
     password, neither of which exists here); the password is briefly visible
     in the pod's process list — documented in the code;
  4. returns `AccountResult{Email: "<username>@<domain>", Attributes:
     {"ceffio_kind": "internal"}}`.
- `AccountInfos`: one JMAP `x:Account/get` for all; Present/Suspended/usage;
  actions:
  - present: `suspend` or `resume`, `quota` (field `quota_gio`), `delete-mailbox` (Confirm = username);
  - internal and absent: `recreate-mailbox`;
  - external users: no action (D3).
- `SuspendAccount`/`suspend`: `permissions` Merge + `disabledPermissions.authenticate` (D6).
- `ResumeAccount`/`resume`: remove that entry.
- `delete-mailbox` / `DeleteAccount`: destroy the Stalwart account (semantics
  per POC H: immediate, the id is never reused), its app passwords, the vault
  entry, the Nextcloud Mail account (`occ mail:account:export <uid>` to find
  its id, then `occ mail:account:delete <id>`). The user keeps
  `ceffio_kind=internal` and its email (the address stays reserved for it).
- Self-service app passwords (D8): internal users sign in at
  `https://mail.<domain>` through Keycloak (`stalwart-webui` client) and
  create app passwords in Stalwart's account manager. POC B (9.B) settled the
  mapping: the OIDC directory keeps `usernameDomain = ceffio.local`, every
  account keeps its `<username>@ceffio.local` address plus the
  `<username>@<domain>` alias, and `adminceffio` is untouched. A third-party
  OIDC client cannot manage app passwords (9.B), so Ceffio never drives
  user-level JMAP with an OIDC token: it uses the cluster-local admin
  credential, and the WebUI is the user's own door. The Users page summary
  shows the address to open.

### 4.8 Server setup done by `Install` (every step idempotent, read back)

1. Workload: as today, PVC size `max(current, volume_gio)`; mount the
   `mail-tls` Secret read-only at `/etc/stalwart/tls`.
2. TLS: ensure an `x:Certificate` from `File` `/etc/stalwart/tls/tls.crt` and
   `tls.key`; `SystemSettings.defaultCertificateId` = its id. Renewal: when the
   Secret's `resourceVersion` changed (or on every `Apply`, the action is
   idempotent), create the `x:Action` `ReloadTlsCertificates` — no rollout
   (9.C).
3. SSO: `ConfigurerSSO` as today, plus the mapping decided by POC B.
4. Sending: `envoi=direct` → only the `mx` and `local` routes (remove a relay
   route left by an earlier `relais`); `envoi=relais` → relay route + outbound
   strategy from the relay settings (shapes from
   `/docs/ref/object/mta-route/` and `/docs/ref/object/mta-outbound-strategy/`, POC I).
5. Exposure: Service `stalwart` (ClusterIP) ports 25, 465, 993, 8080; new
   Service `stalwart-public`, `type: LoadBalancer`,
   `externalTrafficPolicy: Local`, ports 25 (+465, 993 when
   `clients_externes`). POC D (9.D) confirmed that `Local` preserves the real
   client address for genuine clients and that `Cluster` does not; the
   `hostNetwork` fallback is **not** used. Note the limit measured: traffic
   originating from the node itself is masqueraded whatever the policy, so a
   host-side probe proves reachability, never the client address.
6. Ingress: the `mail` Ingress also serves `autoconfig.<domain>`,
   `autodiscover.<domain>` and `mta-sts.<domain>` (Stalwart answers those
   paths); add these names to the `mail-tls` Certificate.
7. Aliases: `postmaster@<domain>` and `abuse@<domain>` as aliases of the admin
   account (the operator reads them in Stalwart's web interface, signed in as
   `adminceffio`).
8. `noreply@<domain>` (§4.5), then `platformmail.ApplyNextcloud` +
   `ApplyKeycloak`.
9. OPNsense topology: `ceffio expose` also creates port forwards for 25 (+465,
   993) to the node. If the OPNsense API version cannot create them, `expose`
   prints the exact rule to create by hand and the `inbound-25` check reports
   it.

### 4.9 Backup

`ceffio backup` covers the mail volume with a **consistent** copy. Stalwart has
no online dump (`/docs/management/maintenance/backup/`): one RocksDB directory
plus a local blob store, copied with the server stopped, or through an atomic
filesystem snapshot of the whole directory — POC K (9.K). So: scale the
Deployment to 0, wait for the pod to be gone, archive `/var/lib/stalwart`
through a helper pod mounting the same PVC, scale back to 1 (on error too). A
live RocksDB directory is never tarred while Stalwart runs; inbound mail during
the window is deferred by senders (4xx), not lost.

Vault entries are **not** covered today (9.K): `internal/backup` dumps
PostgreSQL, the Nextcloud/OnlyOffice volumes and Kubernetes Secrets/ConfigMaps,
nothing from OpenBao. PR 2 adds the `kv/ceffio` tree (so
`kv/ceffio/stalwart/admin`, the relay settings and `kv/ceffio/mail/noreply` are
covered) and `openbao-token`, `openbao-unseal-key` to the Secret list; the
restore writes the kv entries back with `bao kv put` after the Secrets are
restored. A full vault rebuild (`operator init` with the archived recovery
keys) stays a documented manual step. Restore is proven (PR 2).

### 4.10 Upgrade from 0.10.x

- `RejouerInstalles` replays optional modules whose state is `Installed` **or
  `Degraded`** (a mail module degraded by a missing DNS record must keep being
  upgraded). Check every other optional module is fine with that.
- A 0.10.x cluster has the Deployment `stalwart` → the new `State` reports
  `Installed`/`Degraded` → it is replayed. The existing relay values (vault
  `kv/ceffio/mail/relay`, CM `mail.relay`) are kept; `server` settings take
  their defaults — except `envoi`, which is `relais` when a relay is already
  configured (do not switch a working installation to direct sending).
- Existing users stay external (D4).

---

## 5. Out of scope for 0.11.0

- Automatic DNS publication with the ACME DNS-01 credential (0.11.1).
- Conversion between external and internal users (excluded by D3).
- Aliases per user, shared mailboxes, mailing lists, catch-all.
- Making DNSBL or the inbound test blocking.
- Moving the `stalwart-webui` Keycloak client into the mail module.

---

## 6. Pull requests, in order

Every PR: tests first where possible; `gofmt` + `make build vet test` green;
merge when CI is green (§0.2); delete the branch.

### PR 0 — POC on the demo (`docs/plan-mail-poc`)

No product code. Run each item on the demo with `ceffio-test-` objects, delete
them, and record the **results** (never secrets) in §9 "POC results" of this
file; amend §4 where a result changes the design. Merge this docs PR before
PR 1 (PR 1 needs item I, PR 2 item K).

- **A.** App password for an account in a domain attached to the OIDC
  directory: create `ceffio-test-poc@<domain>`, `x:AppPassword/set`, then IMAP
  login on 993 and SMTP AUTH on 465 (`openssl s_client` / `curl imaps://`)
  from inside the cluster.
- **B.** SSO mapping: how does an OIDC login of `ceffio-test-poc` reach
  `ceffio-test-poc@<domain>` while `adminceffio` keeps reaching
  `adminceffio@ceffio.local`? Candidates: claim `email` instead of
  `preferred_username`; `usernameDomain` = `<domain>` with the admin moved;
  accounts in `ceffio.local` with a `<domain>` alias. Prove the chosen one: a
  Keycloak test user signs in to the WebUI and can create an app password.
- **C.** Does Stalwart reload a `File` certificate when the file changes
  (update a test Secret mounted in a test pod, or observe after a re-apply)?
- **D.** With a test LoadBalancer Service (`externalTrafficPolicy: Local`) on
  a free test port, does Stalwart (or a test pod) see the client's real
  address? Remove the test Service afterwards.
- **E.** From the Nextcloud and Keycloak pods: does `mail.<domain>:465`
  connect with a valid certificate (hairpin)? Note what happens behind NAT.
  (Result: not published, and nothing listens; see 9.E for the decision taken.)
- **F.** `permissions` Merge with `authenticate` disabled: IMAP, SMTP AUTH and
  WebUI refused, inbound mail still delivered. `emailReceive` disabled:
  inbound accepted at `RCPT`/`DATA` then bounced with a DSN, not refused (9.F).
- **G.** `quotas.maxDiskQuota` set and changed through `x:Account/set`;
  `usedDiskQuota` read back.
- **H.** `x:Account` destroy: is the data removed immediately, kept in
  deleted items, recoverable?
- **I.** Exact JSON of a relay `x:MtaRoute` and of the outbound strategy that
  sends all non-local mail through it (create on a test route name, read, delete).
- **J.** `occ mail:account:create --help` and `mail:account:export/delete`
  signatures on the installed Nextcloud Mail.
- **K.** Stalwart's backup procedure: online consistent copy or not.

### PR 1 — `fix/mail-relay-ports-volume`

- `internal/mail`: `AppliquerEnvoi(ctx, mode, relais)` writes the route(s)
  per POC I; called by `Deploy` and by the module's `Apply`. Remove the
  "to be finalized through the admin interface" path of `configurerRelais`.
- Settings group `server` (§4.2) in `internal/modules/mail/reglages.go`.
- `--smtp-relais*` install flags write the module settings through `Apply`
  (mail is still core in this PR: `install.go` calls `Apply`, then `Deploy`).
- Service ports 25, 465, 993, 8080 (drop 587, 143).
- PVC size from `volume_gio`, `max(current, wanted)`; refuse when the
  StorageClass forbids expansion.
- Tests: route JSON for both modes (fake JMAP), PVC size never decreases
  (fake clientset), a lower `volume_gio` is refused, Service ports.
- Live (demo): settings unchanged → `Deploy` is a no-op apart from the
  Service ports; read back routes and ports.

### PR 2 — `feat/backup-mail`

- Mail volume in `internal/backup` with the stop-the-server method of POC K
  (scale 0, archive `/var/lib/stalwart` from a helper pod on the same PVC,
  scale back to 1 even on error).
- Vault coverage (9.K): dump the whole `kv/ceffio` tree with `bao kv list/get`
  into `vault/`, add `openbao-token` and `openbao-unseal-key` to the backed-up
  Secrets, restore the kv entries with `bao kv put` after the Secrets. The
  manual full-vault rebuild (`operator init` with the archived recovery keys)
  is documented, not scripted.
- Tests: the volume list contains mail; the vault tree is dumped and restored
  from a fake `bao` (fake `Executer`); the scale-down/up is restored even when
  the copy fails.
- Live (demo): `ceffio backup`, then restore the archive into a **temporary
  namespace** (`ceffio-test-restore`: PVC + Stalwart pod with the same
  secrets), list accounts through JMAP, delete the namespace.

### PR 3 — `chore/mail-client-go`

- `internal/mail` without `kubectl`: manifests through `k8sapi.Appliquer`,
  exec through `k8sapi.Executer`/`ExecuterAvecEntree`, rollout restart by
  patching the pod template annotation, waits through `AttendrePret`.
- New `internal/mail/jmap`: one client (`Get`, `Set`, `Query`, typed errors
  for `notCreated`/`notUpdated`/`notDestroyed`/`error`) behind a `Transport`
  interface — exec-into-pod in production, `httptest` in tests. `sso.go`
  helpers move onto it.
- No behaviour change: existing tests pass unchanged; add transport tests.
- Live (demo): copy a locally built `linux/amd64` binary to the demo (not over
  the installed one: e.g. `/tmp/ceffio-pr3`) and run `ceffio mail sso`
  without `--repair` (the read-only verification) — it must give the same
  result as the installed binary.

### PR 4 — `feat/mail-optional`

- `internal/modules/mail/module.go`: `Kind: Optional`, `Default: true`,
  `Requires: identity, ingress, files`; `Install` = settings → `mail.Deploy` →
  `ConfigurerSSO`; `State` and `Uninstall` per §4.1 (checks come in PR 6:
  until then `State` is deployment-based). Remove the obsolete `Warning`.
- `cmd/ceffio/install.go`: remove the unconditional mail block; mail installs
  in the optional phase; `--without mail` works; help text generated.
- `internal/cluster/redeploy.go`: remove the mail replay.
- `internal/module/replay.go`: replay `Degraded` too (§4.10) + test.
- `internal/console/module_ops.go`: `runOperation` passes `Settings`,
  `Secrets`, `ModuleID` + test.
- Console summary (`synthese.go`) and Stalwart rotation check (`admin.go`)
  only when the module is installed.
- Permissions per §4.1; RBAC golden updated.
- Upgrade default for `envoi` (§4.10).
- Tests: kind/default/requires; a 0.10.x-shaped fake cluster (Deployment
  `stalwart` present) is replayed by the upgrade path; fresh install with and
  without mail; console install path builds a complete `Env`.
- Live (demo): none yet (needs a release candidate; covered in §8).

### PR 5 — `feat/module-checks`

- `internal/module/checks.go` (§4.3) and doc in `docs/adding-a-module.md`.
- Route `GET /api/modules/{id}/checks` (404 when the module does not implement
  `Checker`); add it to the closed list in `regles_generiques_test.go` with
  its justification; the page renders checks on the module card generically
  (levels, Detail, Fix in a copyable block) — no module name in the page.
- `ceffio module check <id>`: prints the list, exit code 1 on `blocking`.
- New `internal/dnscheck`: resolver on public resolvers (MX, TXT, A, AAAA,
  CNAME, SRV, PTR, FCrDNS), injectable for tests.
- `ceffio dns status` uses `dnscheck`; its help stops claiming checks it does
  not run, and prints the mail checks when the mail module is installed.
- Tests: route, page genericity, CLI exit code, each `dnscheck` function on
  fixtures including a failing one.

### PR 6 — `feat/mail-setup` (do not merge before the exposure fix, §0.5)

- Mail `Checker` (§4.4) and `State` with checks (§4.1).
- `Install` steps 1, 2, 5, 6, 7, 9 of §4.8 (8 comes in PR 7).
- DNS records from `dnsZoneFile` in the `records` checks' Fix.
- Guided inbound test (`inbound-test`) and DNSBL (`dnsbl`).
- `ceffio expose`: port forwards (§4.8 step 9).
- Tests: every check fails on a bad fixture; private domain → all
  `not_applicable`; `stalwart-public` ports follow `clients_externes`;
  certificate object JSON; idempotency (second `Install` writes nothing).
- Live (demo): with a locally built binary copied to the demo (as in PR 3),
  `ceffio module check mail` lists the expected failures there (missing
  records, reverse DNS) — paste the output in the PR with the domain and the
  IP replaced by placeholders. Nothing is installed by this run.

### PR 7 — `feat/platform-mail`

- `internal/platformmail` (§4.5); noreply account in mail `Install` (step 8);
  `files` `outgoing_mail` writer moved into `ApplyNextcloud`; Keycloak
  `smtpServer`; mail `Uninstall` falls back.
- Tests: `Resolve` in the three situations; Nextcloud config written/cleared;
  Keycloak payload; noreply credential rotation when the login fails.

### PR 8 — `feat/module-accounts`

- `internal/module/accounts.go` (§4.6), doc in `docs/adding-a-module.md`.
- Console users handlers and page per §4.6 (generic; `TestLaPageNAppelleAucunModuleEnDur`
  must keep passing); user delete; deactivate/reactivate also on Nextcloud.
- `ceffio users` subcommands.
- Tests with a fake `Accounts` module: field rendering, `ReplacesEmail`,
  creation order and write-back, validation stops before Keycloak, delete
  order, typed confirmation, protected account refused.

### PR 9 — `feat/mail-accounts`

- Mail `Accounts` (§4.7), SSO mapping from POC B, Nextcloud Mail wiring,
  quota and over-commit (`volume` check), reserved names.
- Tests with fake JMAP + fake occ: create/ensure idempotent, validation rules
  (each one proven to refuse), suspend/resume payloads, delete-mailbox keeps
  the user, recreate, external user gets no actions.

### PR 10 — `docs/mail`

- New `docs/mail.md`: operator guide (prerequisites and every check, DNS
  records, reverse DNS at the host, direct vs relay, ports and firewall,
  OPNsense, backup/restore, upgrade from 0.10.x, uninstall keeps the data) and
  user guide (Nextcloud Mail, Thunderbird/phone with app passwords,
  autoconfig).
- Update `docs/adding-a-module.md` (Checker, Accounts), `docs/stalwart-1.0.md`,
  README feature list, the `ceffio mail` command help.
- Mark this plan "delivered" and link `docs/mail.md`.

---

## 7. Release 0.11.0 (the agent does it all — D17)

The tag is placed on the merge commit in `main` (that is how v0.10.x were cut;
the `release.yml` workflow publishes on `v*` tags, builds the binaries and the
console image, and refuses a commit whose CI is not green).

The CI (`ci.yml`) runs on pushes to `main`/`develop` and on PRs into them —
not on a bare push of `release/*`. So the release PR is opened FIRST, and the
release candidate is tagged on its head once that PR's CI is green.

```bash
git checkout develop && git pull
git checkout -b release/0.11.0 && git push -u origin release/0.11.0
gh pr create --base main --head release/0.11.0 --title "release: 0.11.0" --body "…"
# once the PR's CI is green, tag its head as a release candidate
# (prerelease, never "latest"):
git tag -a v0.11.0-rc.1 -m "Ceffio 0.11.0-rc.1" && git push origin v0.11.0-rc.1
```

1. Wait for the Release workflow of `v0.11.0-rc.1` (binaries + console
   image); run §8 with that build. A fix found there is committed on
   `release/0.11.0` (stabilisation only, no feature), the PR's CI re-runs,
   and the new head gets `-rc.N+1`.
2. Merge the PR `release/0.11.0` → `main` when CI is green and §8 passed.
3. Tag the merge commit and push:
   ```bash
   git checkout main && git pull
   git tag -a v0.11.0 -m "Ceffio 0.11.0" && git push origin v0.11.0
   ```
4. Wait for the Release workflow; check the release has both binaries,
   `checksums.txt` and the console image.
5. Back-merge: branch `chore/back-merge-0.11.0` from `main`, PR into
   `develop`, merge when CI is green.
6. Upgrade the demo to `v0.11.0` (backup first) and re-run §8.2 quickly.
7. Delete the merged branches (`release/0.11.0`, `chore/back-merge-0.11.0`).

## 8. Live verification

### 8.1 Before (demo)

`ceffio backup` on the demo; keep the archive path in the PR notes.

### 8.2 Upgrade of the demo to the release candidate

1. `ceffio upgrade` to `v0.11.0-rc.N`: the mail module is listed as an
   installed optional module; `adminceffio` still exists; DKIM keys unchanged
   (same selectors); the relay settings (if any) kept.
2. `ceffio module check mail`: expected on the demo before DNS work — `records`
   warnings, `ptr` blocking (direct mode). Mailbox creation is refused with
   that list (proves the gate).
3. **Stop and ask** the maintainer to publish the displayed records and set
   the reverse DNS (or to configure a relay), and for one external mailbox.
4. Checks green (warnings allowed only for `inbound-test` until step 6).
5. Create `ceffio-test-int` (internal, 1 GiB) and `ceffio-test-ext`
   (external, the maintainer's external address).
6. Guided inbound test: mail from the external mailbox to
   `postmaster@<domain>` → `inbound-test` shows SPF/DKIM/DMARC pass.
7. `ceffio-test-int`: inbox visible in Nextcloud Mail; send to the external
   mailbox and receive its reply; the received message passes SPF/DKIM/DMARC
   on the external side.
8. Keycloak "forgot password" for `ceffio-test-ext`: the mail arrives from
   `noreply@<domain>`; a Nextcloud share notification too.
9. App password created by `ceffio-test-int` in the WebUI (SSO), then IMAP
   993 and SMTP 465 from the agent's machine.
10. Suspend the mailbox: IMAP refused, mail still received; resume. Raise the
    quota to 2 GiB; usage shown.
11. Delete the mailbox (user kept, address reserved), recreate it; delete
    both test users (Keycloak, Nextcloud, Stalwart, vault entries gone —
    read back).
12. Uninstall/reinstall is NOT run on the demo (it would drop exposure while
    the maintainer's mail is live); it is covered by tests and by 8.3.

### 8.3 Fresh install (needs a clean machine — ask, §0.5)

Only the documented procedure: install → checks red → DNS/reverse DNS done →
checks green → internal user → mail in and out. Then `install --without mail`
on a second domain that already has an MX elsewhere: nothing installed,
nothing published. If no machine is available, the release PR says so.

## 9. POC results

Run on the demo on 2026-11-13/14 with `ceffio-test-*` objects only. Every object
created for a POC was deleted afterwards and the deletion was read back (empty
`x:Account/query`, `x:Certificate/get`, no `ceffio-test` route in
`x:MtaRoute/query`, Keycloak `clients?clientId=…` and `users?search=…` → `[]`,
`kubectl get all,svc,endpointslice,ds -A | grep ceffio-test-` → nothing). No
secret appears below: app-password secrets were returned once by JMAP and kept
out of this repository. Commands are condensed; the full transcripts are in the
PR body.

### 9.A App password for an account of an OIDC-attached domain — works

- `x:Account/set` create `ceffio-test-poc` in `<domain>`, quota 1 GiB →
  `{"created":{"ceffio-test-poc":{"id":"f"}}}`. Passing `credentials` in the
  same call is refused with `{"type":"forbidden","description":"Cannot set
  credentials for accounts in an external directory."}`: the OIDC directory owns
  authentication.
- `x:AppPassword/set` with request-level `accountId:"f"` →
  `{"created":{"p8":{"id":"p8","secret":"app_…"}}}`; the secret (40 characters)
  is returned **once**.
- IMAP 993 from inside the cluster (`openssl s_client` + `AUTHENTICATE PLAIN`):
  accepted with the app password, refused with a wrong one (curl exit 67).
  Submission 465 (`openssl s_client -connect 127.0.0.1:465` + `AUTH PLAIN`):
  `235 2.7.0 Authentication succeeded.`; wrong password `454 4.7.0`.
- `mail.<domain>:465` through the Service times out: the Service declares
  25, 587, 143, 993, 8080 and **no 465** (see 9.E). PR 1 confirms it.
- Stalwart serves its built-in `CN=rcgen self signed cert` (SAN `DNS:localhost`)
  on 993 until PR 6 installs the certificate; a verifying client fails
  (`curl` exit 60), so the POCs used `-k`.
- Cap: a sixth app password is refused with
  `{"notCreated":{…:{"type":"overQuota","description":"You have exceeded your
  quota of 5 app passwords."}}}`.

Consequences: (1) an account in an OIDC directory is managed through JMAP but
never has a password, so every Ceffio-owned credential is an app password:
Ceffio must destroy its own stale ones (stable `description` marker) and report
`overQuota` as a blocking check; (2) the `tls` check cannot pass before PR 6.

### 9.B SSO mapping — option (c), aliases on `ceffio.local` accounts

- The OIDC directory maps `claimUsername` (`preferred_username`) to
  `<username>@<usernameDomain>` = `<username>@ceffio.local`. A test Keycloak
  user `ceffio-test-sso` (`preferred_username=ceffio-test-sso`, email
  `ceffio-test-sso@<domain>`) signed in through the `stalwart-webui` client
  (PKCE S256, `/api/discover/<user>` → Keycloak AS, callback
  `https://mail.<domain>/account/oauth/callback`): Stalwart auto-provisioned the
  account `ceffio-test-sso@ceffio.local` (id `g`). The `email` claim is ignored
  for the account name.
- Stalwart's own `/login` only knows local accounts: `POST /api/auth
  {"type":"authCode",…}` → `{"type":"failure"}`. The WebUI must go through
  Keycloak.
- Signed in, the user creates an app password in the account manager
  (`x:AppPassword/set` with its own token) → `{"created":{"up1":{"id":"b",
  "secret":"app_…"}}}`; IMAP 993 and SMTP 465 accept it.
- A third-party Keycloak client (`ceffio-test-poc`, audience `stalwart-webui`)
  is refused by `x:AppPassword/*` (`forbidden`) even after granting the account
  `permissions Merge`. Only the token of the installed application (`azp` =
  its `oauthClientId`) has the account-manager rights. Consequence: Ceffio
  drives user-level JMAP with the cluster-local admin credential, never with an
  OIDC token; the WebUI is the user's self-service.
- `x:Alias/*` does not exist in 1.0.3 (`unknownMethod`). Aliases live inside the
  account: `x:Account/set` update
  `{"aliases":{"0":{"@type":"EmailAlias","name":"ceffio-test-alias",
  "domainId":"<domain id>"}}}` (or the pointer form `"aliases/0"` with
  `{"name","domainId"}`) → `{"updated":{"g":null}}`; the read-back gives
  `{name, domainId, description, enable:true}` **without** `@type`. A message
  sent to `ceffio-test-alias@<domain>` was delivered to the account's
  `Junk Mail` (IMAP `INBOX` stayed `0 EXISTS`): the alias works, and a first
  contact is classified as spam.

Decision: **option (c)**. Accounts keep `<username>@ceffio.local` (the OIDC
directory and `adminceffio` are untouched) and Ceffio attaches
`<username>@<domain>` as an alias in `EnsureAccount`. Option (b)
(`usernameDomain = <domain>`) would move `adminceffio` and every OIDC user at
once and is rejected. Caveat: an account auto-provisioned by a first SSO login
has no alias and no quota until Ceffio's `EnsureAccount` runs (on the next
`module install mail`, the next replay, or the next write on the Users page);
the Users page must show that state instead of pretending the mailbox is
complete.

### 9.C File certificate reload — action `ReloadTlsCertificates`

- Created `x:Certificate` with `{"certificate":{"@type":"File","filePath":
  "/tmp/ceffio-test-cert.pem"},"privateKey":{"@type":"File","filePath":
  "/tmp/ceffio-test-key.pem"}}` → `{"created":{"ceffio-test-cert":
  {"id":"jomosjtsacaa"}}}`. The server parses the PEM at `set` time: read-back
  gave `issuer=CN=ceffio-test-a.invalid`,
  `subjectAlternativeNames={"ceffio-test-a.invalid":true}`, `notValidAfter=
  2026-12-14T02:38:53Z`.
- Replaced both files with a second certificate (`CN=ceffio-test-b.invalid`,
  `notAfter 2027-01-13`) **without** restarting: the read-back still showed
  certificate A. A `File` certificate is read at load time only; no reload on
  file change.
- Created the action `x:Action/set {"create":{"…":{"@type":
  "ReloadTlsCertificates"}}}` → `{"created":{"ceffio-test-reload":
  {"id":"bvppspu"}}}`; the `x:Certificate/get` in the same request showed
  certificate B (`issuer=CN=ceffio-test-b.invalid`, `notValidAfter=
  2027-01-13T02:38:53Z`). The action re-reads the files, no restart, no
  connection interrupted.
- Destroyed the object, reloaded again: `x:Certificate/get` empty and the
  certificate served on 993 back to `CN=rcgen self signed cert` (demo state
  restored).

Consequence for PR 6: mount the `mail-tls` Secret at `/etc/stalwart/tls`,
declare `x:Certificate` from `File` `/etc/stalwart/tls/tls.crt` + `tls.key`, set
`SystemSettings.defaultCertificateId`, and send `ReloadTlsCertificates` after
every change of the Secret (compare its `resourceVersion`, the action is
idempotent). No rollout. The documentation confirms certificates are loaded at
start-up, at ACME renewal and on that action, and that the other nodes of a
cluster pick the change up at the next synchronisation (single node here).

### 9.D Client IP behind the LoadBalancer Service — `Local` is required, and the host-side test cannot prove it

A temporary `type: LoadBalancer` Service (`ceffio-test-lb-peer`,
`externalTrafficPolicy: Local`, port 28461) forwarded to a PHP listener in the
Nextcloud pod that logs `peer=…`:

| Test | Client | Policy | Peer seen by the pod |
|---|---|---|---|
| 1 | the demo host, to its own public IP | `Local` | `10.42.0.1` |
| 2 | the demo host, to its own public IP | `Cluster` | `10.42.0.1` |
| 3 | a Keycloak pod (`10.42.0.235`) | `Local` | `10.42.0.235` |
| 4 | the same Keycloak pod | `Cluster` | `10.42.0.1` |

- For a genuine client (the Keycloak pod) `Local` **preserves** the source
  address and `Cluster` rewrites it to the node bridge (`10.42.0.1`).
- The host → own public IP test cannot discriminate: kube-proxy marks
  node-local sources for masquerading even under `Local`
  (`-m addrtype --src-type LOCAL -j KUBE-MARK-MASQ` in `KUBE-EXT-*`), and
  klipper-lb adds its own `POSTROUTING -j MASQUERADE` for the hostPort hop.
  Both tests therefore show `10.42.0.1`.

Decision: keep `externalTrafficPolicy: Local` on `stalwart-public`; the
`hostNetwork` fallback of §4.8.5 is **not** needed. Consequence for checks: a
connection originating from the node (`inbound-25`, dialling `<public-ip>:25`)
proves reachability only, never the client address — no check may claim
otherwise. The cleanup was read back (`ceffio-test-lb-peer` deleted, listener
gone, port closed, `svclb-` pod gone).

### 9.E `mail.<domain>:465/993` from the application pods — not reachable today, hairpin works once the port is published

- Nothing publishes 465/993: the `stalwart` Service is `ClusterIP` with
  25/587/143/993/8080 and only Traefik has a LoadBalancer (80/443); the node
  itself has no listener on 25/465/587/993 (`ss -ltn`).
- From the Nextcloud pod and from the Keycloak pod, `mail.<domain>` resolves to
  the public IP and every connect to 465 and 993 is **refused** (errno 111);
  the same refusal happens **from the host**, so this is not a hairpin
  restriction, only un published ports.
- Hairpin networking itself works: from the Keycloak pod, port 28461 of POC D
  (a published `LoadBalancer` port) answered the test banner.
- The in-cluster path (`stalwart.ceffio-mail.svc.cluster.local:993`) completes a
  TLS 1.3 handshake but verification fails (`verify error:num=18:self-signed
  certificate`, SAN `DNS:localhost`), i.e. the name would not match either.

Decision for PR 7: keep `mail.<domain>:465` as the platform sender host.
`platformmail` probes it **from the pod that will use it** (the mail module has
`pods/exec` in `ceffio-files` and `ceffio-identity`, §4.1) and, when the port is
not published (e.g. `clients_externes=false` publishes 25 only), installs an
in-cluster alias instead of silently misconfiguring: a `hostAliases` entry
`mail.<domain> → <stalwart Service ClusterIP>` on the Nextcloud and Keycloak
Deployments, marked by an annotation so it is idempotent and refreshed when the
Service IP changes. Same host name, same certificate, no public exposure. The
real submission login without `-k` is verified in §8.

### 9.F `permissions`: suspend and `noreply`

- `permissions = {"@type":"Merge","disabledPermissions":{"authenticate":true}}`:
  IMAP and SMTP authentication are refused, mail already delivered stays, and
  **inbound delivery continues** (a message sent to the account during the
  suspension was accepted and stored).
- `permissions = {"@type":"Merge","disabledPermissions":{"emailReceive":true}}`:
  inbound SMTP still answers `250` at `RCPT TO` and accepts `DATA`, then the
  message is bounced with a DSN from `MAILER-DAEMON@<domain>` ("Failed to
  deliver message") to the sender; `usedDiskQuota` of the target stays 0.
- `permissions = {"@type":"Inherit"}` gives the account its access back.

Consequences: `SuspendAccount` = Merge + `authenticate` (D6) — reception
continues, which is what a departure or a temporary suspension should do;
`noreply` = Merge + `emailReceive` — mail to it bounces with a DSN, it is not
silently dropped (what §4.5 wants). The `inbound-test` check (§4.4) must
therefore match a message whose `From` is the external test address **and**
ignore DSNs from `MAILER-DAEMON`, and it must look in `Junk Mail` as well as
`INBOX`.

### 9.G Quota

`x:Account/set` update `{"quotas":{"maxDiskQuota":1073741824}}` then
`2147483648` → `{"updated":{"f":null}}`, read back with the new value; an
invalid value is refused with `invalidPatch "Invalid value for unsigned integer
property"`; `usedDiskQuota` is a read-only top-level field (observed 1097 and
5010 bytes on the test accounts). Telemetry of §4.4 `volume` can be computed
from one `x:Account/get` for all accounts plus the PVC capacity.

### 9.H Account destroy

`x:Account/set` destroy of `ceffio-test-poc` → `{"destroyed":["f"]}`; a
following `x:Account/get` returns `notFound` and the account list no longer
contains it. Re-creating the same name gives a **new id**, an empty mailbox
(`INBOX 0 EXISTS`), no app password and no quota. Nothing is recoverable.
(1.0.3 quirk, also seen on `x:MtaRoute` and on the account cleanup: `destroy`
sometimes answers `notDestroyed:{<id>:{"type":"notFound"}}` although the object
**is** gone; the read-back is the authority, not the destroy response.)

Consequence: `delete-mailbox` is irreversible → typed confirmation with the
username (§4.6), the module runs before Keycloak/Nextcloud deletion so a failure
leaves a user that can be deleted again, and the address stays reserved in
Keycloak.

### 9.I Relay route and outbound strategy

- Current demo state (`x:MtaRoute/query`): ids `jkewme12adqb` (`@type Local`,
  `local`) and `jkewme12adab` (`@type Mx`, `mx`, `maxMxHosts 2`,
  `maxMultihomed 2`). **No relay route exists** — today's code only tests the
  relay credentials, it never configures routing, which is exactly PR 1.
- Outbound strategy singleton (`x:MtaOutboundStrategy/get`,
  `accountId:"d333333"`, id `singleton`) reads:
  - `route`: `{"match":{"0":{"if":"is_local_domain(rcpt_domain)",
    "then":"'local'"}},"else":"'mx'"}`
  - `connection`: `{"match":{},"else":"'default'"}`
  - `schedule`: local delivery on `'local'`, DSN on `'dsn'`, reports on
    `'report'`, otherwise `'remote'`
  - `tls`: `{"match":{"0":{"if":"retry_num > 0 && last_error == 'tls'",
    "then":"'invalid-tls'"}},"else":"'default'"}`
  - `x:MtaTlsStrategy/get` → `[]` (no custom TLS strategy).
- Creating a `Relay` route works with the documented fields (`host`, `port`,
  `protocol` smtp/lmtp, `implicitTls`, `allowInvalidCerts`, `authUsername`,
  `authSecret` = `{"@type":"Value","secret":…}`, `description`). `name` is
  **required on create** even though it is read-only afterwards: omitting it
  gives `validationFailed … {"type":"Required","property":"name"}`. Read-back
  never returns the secret (`authSecret` comes back as `{"@type":"Value"}`).
- Patched the strategy `route` to the test relay and back to `'mx'` in the same
  request, reading back after each write; final state is the original one.
- **Not proven:** an actual relayed delivery (the demo has no relay provider).
  §8 verifies it live once the maintainer has one.

Consequence for PR 1: `envoi=relais` = create/update one `Relay` route named by
Ceffio (`relay`) from the relay settings, then patch the outbound strategy to
`{"match":{"0":{"if":"is_local_domain(rcpt_domain)","then":"'local'"}},
"else":"'relay'"}`; `envoi=direct` = no relay route and `else:"'mx'"`. The
current `else:"'mx'"` proves the failure mode the plan fixes: with a relay
configured but not routed, outbound mail still goes direct.

### 9.J Nextcloud Mail CLI

`occ list mail` on the demo exposes `mail:account:create-imap`,
`mail:account:create-jmap`, `mail:account:export`, `mail:account:delete`,
`mail:provisioning:create`, `mail:provisioning:apply`.

- `mail:provisioning:create` takes `--provisioning-domain`, `--email-template`,
  `--imap-host/--imap-port/--imap-ssl/--imap-user/--imap-password`,
  `--smtp-*`, `--sieve-*`, `--ldap-aliases-attribute`, `--(no-)master-password`,
  `--(no-)sieve`, `--(no-)ldap-aliases`. Applied to every user of the domain by
  `mail:provisioning:apply`. `--no-master-password` uses the user's Nextcloud
  login password (an OIDC user has none) and `--master-password` uses one
  password for every mailbox (only possible with a Stalwart "master user"
  impersonation, which the 1.0.3 documentation does not document and which was
  not proven). Templates support `%USERID%`, `%EMAIL%` and `%LDAP:attribute%`.
- `mail:account:create-imap` takes the account settings as options, password
  included; the password is therefore visible in the pod's process list while
  the command runs (same trust boundary as the mailbox itself: the Nextcloud
  pod).
- `mail:account:export <uid>` prints the account(s) of a Nextcloud user with
  their internal id; `mail:account:delete <id>` removes one.

Consequence for PR 7/9: per-user `mail:account:create-imap` with a dedicated
`nextcloud-mail` app password (vault `kv/ceffio/mail/comptes/<username>`), not
the provisioning path; deletion is `export` → `delete`; the password exposure is
documented in the code comment and limited to the pod.

### 9.K Backup consistency — and the vault is not backed up at all

- Documentation (`/docs/management/maintenance/backup/`): everything (accounts,
  mailboxes, blobs, full-text index) lives in one RocksDB directory plus a local
  blob store; the documented procedure is to stop the server and copy the
  directory, or to take an **atomic filesystem snapshot** of the whole directory
  (WAL included). Copying a running RocksDB file by file is unsafe; there is no
  online dump command. The demo confirms the layout: one directory
  `/var/lib/stalwart` on the `stalwart-data` PVC (20 GiB, Longhorn RWO), the pod
  runs as uid/gid 2000.
- A scale-to-zero window around the copy is therefore the only portable method
  for `ceffio backup`; inbound mail during the window is not lost: no listener
  answers, so the sending servers keep the message queued and retry. A
  Longhorn snapshot would work on this cluster but is not portable and is not
  what `ceffio backup` produces.
- **`ceffio backup` does not cover the vault at all today**: `internal/backup`
  dumps PostgreSQL (`mysuite`, `keycloak`, `nextcloud`), the Nextcloud and
  OnlyOffice volumes, and Kubernetes Secrets/ConfigMaps — no OpenBao entry, and
  neither `openbao-token` nor `openbao-unseal-key` is in the Secret list. So
  `kv/ceffio/stalwart/admin` (Stalwart's recovery admin), the relay settings,
  `kv/ceffio/mail/noreply` and every other module secret would be lost by a
  restore.

Consequence for PR 2: (1) add the mail volume to `backup.Volumes` with
`UID/GID 2000`, taken while the Deployment is scaled to 0 (helper pod mounting
the PVC, `tar` there, scale back to 1 even on error) and restored the same way;
(2) dump the whole `kv/ceffio` tree through `bao kv list/get` in `openbao-0`
into `vault/`, and add `openbao-token` and `openbao-unseal-key` to the backed-up
Secrets; (3) restore the kv entries after the Secrets and before the workloads
(the vault pod is already up in the restore flow, static seal); document that a
full vault rebuild (`operator init` with the archived recovery keys) stays
manual. The end-to-end restore test runs in a `ceffio-test-restore` namespace
(§8.3).

### 9.L What PR 0 changed in §4

Applied in this PR, on the strength of the results above:

- §3.3: aliases are a map keyed by index (not a list), `@type` is only sent on
  write; a `File` certificate needs the `ReloadTlsCertificates` action; an OIDC
  account accepts no `credentials`, only app passwords (cap 5).
- §4.4: `inbound-test` also looks in `Junk Mail` and ignores DSNs; the `tls`
  check is expected to fail until PR 6.
- §4.5: in-cluster connection decided (9.E): `mail.<domain>:465`, probed from
  the consuming pod, `hostAliases` fallback to the Service ClusterIP.
- §4.7: account naming is `<username>@ceffio.local` + alias `<username>@<domain>`
  (9.B); Nextcloud Mail is created per user with an app password (9.J).
- §4.8: certificate via `File` + `ReloadTlsCertificates` (9.C);
  `externalTrafficPolicy: Local` confirmed, no `hostNetwork` fallback (9.D).
- §4.9 and PR 2: stop-the-server copy (9.K) **and** the vault gap fixed.
