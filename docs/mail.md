# Mail

Mail is an **optional module**. When it is installed, the suite receives the mail of the
platform domain, gives each internal user a real mailbox, and sends the platform's own
messages — Nextcloud notifications, Keycloak password resets — from `noreply@<domain>`
instead of an external SMTP account.

The server is **[Stalwart](https://stalw.art/) 1.0**. Ceffio deploys it, configures it and
watches it; it does not reimplement it. Everything below is what `ceffio` actually does,
and every check named here can be run on a live installation:

```bash
ceffio module check mail
```

Placeholders are used throughout: `example.com` is the platform domain,
`mail.example.com` the mail host, `203.0.113.10` the public address of the cluster.

## What the module deploys

Everything lives in the namespace **`ceffio-mail`**, next to the applications but with its
own ServiceAccount.

| Object | Role |
|---|---|
| Deployment `stalwart` | The mail server, image `docker.io/stalwartlabs/stalwart:v1.0.3` pinned by digest, `strategy: Recreate` (one writer on the store) |
| PVC `stalwart-data` | The mailboxes, 20 GiB by default, `ReadWriteOnce` |
| Service `stalwart` | ClusterIP, ports 25, 465, 993, 8080 — what the cluster itself uses |
| Service `stalwart-public` | LoadBalancer, `externalTrafficPolicy: Local`, port 25 always, plus 465 and 993 when external clients are allowed |
| Ingress `mail` | `mail.<domain>`, `autoconfig.<domain>`, `autodiscover.<domain>`, `mta-sts.<domain>` → `stalwart:8080` |
| Certificate `mail-tls` | Created and extended by cert-manager from the four Ingress hosts, mounted read-only in the pod |
| ConfigMap `stalwart-config` | Where the store lives (`{"@type":"RocksDb","path":"/var/lib/stalwart"}`) — domains, accounts and TLS objects are stored inside the database, not in this file |
| Aliases | `postmaster@<domain>` and `abuse@<domain>` as aliases of the admin account |
| Account `noreply@<domain>` | The platform sender, with its app password in the vault |

The pod mounts the `mail-tls` Secret at `/etc/stalwart/tls` with `optional: true`: a
certificate that has not been issued yet does not prevent the server from starting, it
keeps its self-signed one and the `tls` check says so.

A normal `ceffio install` deploys it (the module is enabled by default);
`ceffio install --without mail` skips it, and `ceffio module install mail` adds it later.
The mail module requires `identity`, `ingress` and `files`.

**Removing it keeps the data.** `ceffio module remove mail` deletes the workload, the
Services, the Ingress, the ConfigMap and the ServiceAccount, and points Nextcloud and
Keycloak back at the external relay — or clears their SMTP settings when there is none.
It prints what it kept:

```
  ∙ kept: the volume stalwart-data and the vault entries — the mailboxes are intact
  ∙ kept: the Nextcloud Mail accounts of internal users — they work again after a reinstall
```

## The four names, never to be confused

| Name | What it is | Where it comes from |
|---|---|---|
| platform domain | `example.com` — SPF, DKIM, DMARC and the zone file live there | the `identity` module |
| mail host | `mail.example.com` — the name in MX, in certificates, in clients | `CEFFIO_MAIL_DOMAIN`, `mail.<domain>` by default |
| account domain | `ceffio.local` — the OIDC directory gives every account `<username>@ceffio.local` | fixed, and not the platform domain |
| namespace | `ceffio-mail` | fixed |

An internal user therefore has **two mail identities**: the account it signs in with
(`<username>@ceffio.local`) and the address the world writes to
(`<username>@<domain>`), which is an alias on that account. A client configured with the
address works; the *login* is the account name. See [For users](#for-users).

## Prerequisites

### An `A` record for the mail host

`mail.<domain>` must resolve to the public address of the cluster, and to nothing else. The
`a-mail` check compares the two, and it is **blocking** when they differ: mail for the domain
would go to another machine. Remove any duplicate `AAAA` record unless the platform really
answers on IPv6 — clients that prefer IPv6 try it first and fail.

### An `MX` record for the domain

`<domain>. MX 10 mail.<domain>.` The `mx` check reads the domain's MX through the public
resolvers. An empty answer is a warning (the domain accepts no mail at all, so the server
will never receive any); an MX pointing at **another provider** is blocking, because someone
else is receiving this domain's mail. A null MX (RFC 7505, `.`) is recognised and reported
as such.

### A reverse DNS at the hosting provider

Not at the DNS provider: the PTR of `203.0.113.10` belongs to whoever owns the address
range. It must be `mail.example.com`, and the forward lookup of that name must come back to
the same address — the `ptr` check does the forward-confirmed round trip.

In **direct** mode the PTR is a **blocking** prerequisite: Google and Microsoft refuse mail
from an address without one. In **relay** mode it is a warning: the address being judged is
the relay's, and a missing PTR costs reputation rather than delivery.

Ceffio never creates this record, and `ceffio expose` cannot: it prints the fix
(`ask your hosting provider to set the reverse DNS (PTR) of <ip> to <host>`) and stops
there.

### A certificate covering the four names

`mail-tls` is requested by cert-manager for `mail.<domain>`, `autoconfig.<domain>`,
`autodiscover.<domain>` and `mta-sts.<domain>`. The `tls` check dials the server's own
STARTTLS/465/993 listeners and judges the certificate against the mail host name; an
unusable certificate — self-signed, wrong name, expired, or expiring in less than 14 days —
is **blocking**, with the fix `serve the platform certificate on the mail host, then re-run
the mail deployment: ceffio mail --domain <domain>`.

Certificate issuance is an external prerequisite, never a refusal: the Ingress and the
Secret are applied, and the install warns that `Secret ceffio-mail/mail-tls` is not issued
yet, so Stalwart keeps its self-signed certificate and the `tls` check reports it. How the
certificate is obtained is [tls.md](tls.md)'s business.

### The vault

The module needs it to finish installing. Every credential it owns is an app password or a
relay password — returned once by the server and kept nowhere else — so it has to live in
OpenBao, never in a ConfigMap. Without one, the install stops at the platform sender with
`no vault configured: the platform sender credential lives in ceffio/mail/noreply, so the
mail module requires OpenBao (BAO_ADDR)`, and creating a mailbox is refused for the same
reason:

| Vault path | Content |
|---|---|
| `kv/ceffio/stalwart/admin` | The admin account of the mail server |
| `kv/ceffio/mail/relay` | The outbound relay's password |
| `kv/ceffio/mail/noreply` | The platform sender's app password |
| `kv/ceffio/mail/comptes/<username>` | One app password per internal user (Nextcloud Mail) |

Without a vault, configuring the relay fails with `mail: no vault configured: the relay
password must be stored in OpenBao, never in a ConfigMap, where anyone able to read the
namespace could read it`. See [secrets.md](secrets.md).

### The ports

| Port | Protocol | Purpose | Published when |
|---|---|---|---|
| 25 | SMTP | Mail from other servers | always |
| 465 | SMTPS, implicit TLS | Submission from phones, Thunderbird, Nextcloud Mail | `clients_externes=true` (default) |
| 993 | IMAPS | Reading mail from clients | `clients_externes=true` (default) |
| 8080 | HTTP | Administration interface and autoconfiguration | never — it is reached through the Ingress on 443 |
| 25 | SMTP out | Direct delivery to the recipient's MX | depends on the hosting provider |

**Outbound port 25 is usually filtered by hosting providers**, which is why a relay is the
practical default in the field even though the module ships in `direct` mode. The
`port25-out` check proves it from inside the mail pod, against the first MX record of
`gmail.com` on port 25.

## The installation order

The order matters, and each step is verifiable:

1. **DNS first**: `mail.<domain>` A record, `<domain>` MX record. Point them at the cluster
   before installing, or the certificate cannot be issued.
2. **Install the suite** (`ceffio install`), or the module alone
   (`ceffio module install mail`). The install prints the mail domain, the mailbox volume
   size, the ports published outside, the `postmaster@`/`abuse@` aliases, the TLS
   certificate it installed, the platform sender it kept or rotated, and the firewall step
   it deliberately leaves to you — `ceffio expose --ports 25,465,993` (or `25` alone when
   external clients are off) — because the console has no access to the firewall API. No
   password is printed: it is in the vault, and only the vault.
3. **Open the firewall**: `ceffio expose --ports 25,465,993` (next section).
4. **Publish the records** the `records-*` checks print (see [DNS records](#dns-records)).
5. **Ask the hosting provider for the PTR**, if it is not already set.
6. **Run the checks** and work down the list:
   ```bash
   ceffio module check mail
   ```

## Ports and the firewall

On the reference installation the firewall is OPNsense with os-caddy. `ceffio expose`
declares the public domains *and*, with `--ports`, the L4 forwards the mail module needs:

```bash
ceffio expose --config ceffio-expose.json --ports 25,465,993
```

The configuration file carries the firewall API address, the credentials file path, the
domain and the internal target:

```json
{
  "hoteAPI": "firewall-api.example.com",
  "fichierCle": "~/.config/opnsense/apikey.txt",
  "domaine": "ceffio.example.com",
  "ipInterne": "CLUSTER-INTERNAL-IP",
  "portInterne": "80"
}
```

**A printed rule is the contract, not a success message.** The firewall API can only say
that it saved the rule; it never proves that the internet reaches the port. When the API
cannot create a forward, the command does not fail — it prints the exact rules to create by
hand and continues:

```
The firewall API did not confirm every port forward:
  ! <reason>
Create these rules by hand (Firewall > NAT > Port Forward, then the
matching pass rule on the WAN interface):
    WAN TCP * -> 203.0.113.10:25
    pass in on WAN inet proto tcp from any to 203.0.113.10 port 25 keep state
```

The command then tells you how to verify, and it is not `ceffio expose`:

```bash
ceffio module check mail
```

The `inbound-25` check dials the public address on port 25 **from the machine running the
check** and accepts a `220` banner. It is deliberately a warning and not a blocking failure:
traffic originating from the node itself is masqueraded, whatever `externalTrafficPolicy`
says (measured, §9.D of the plan), so this check proves reachability only — it never proves
which client address the server sees.

Two more traps are documented in [media-and-firewall.md](media-and-firewall.md) for Talk's
ports and apply here as well: a port forward without its matching pass rule is a silent
drop, and a Service type applies to all its ports — which is why `stalwart-public` is a
separate Service carrying only 25 (and 465/993) while administration stays on the ClusterIP.

Deleting the `stalwart-public` Service frees the node's ports but **not** the firewall's
forwards: remove them by hand when you remove the module for good.

## DNS records

Nothing in Ceffio invents DNS records. Stalwart generates a zone file for each domain it
serves (`x:Domain/dnsZoneFile`), and the `records` check compares that file family by
family with what the public resolvers answer. Each failing family prints, as its fix, the
**literal line to publish** — copy it into your DNS provider.

The families are:

| Check | Records | Notes |
|---|---|---|
| `records-spf` | `v=spf1` TXT at the apex | In relay mode the zone file only describes direct delivery: the relay provider's `include:` has to be appended by hand, and the fix says so |
| `records-dkim` | One TXT per **active** selector, `<selector>._domainkey.<domain>` | A key generated but not active is not expected in DNS |
| `records-dmarc` | `_dmarc.<domain>` TXT | |
| `records-mta-sts` | `_mta-sts.<domain>` TXT and, when declared, the `mta-sts.<domain>` CNAME | Stalwart serves the policy file on `mta-sts.<domain>` |
| `records-tls-rpt` | `_smtp._tls.<domain>` TXT | |
| `records-autoconfig` | Whatever the zone declares at `autoconfig.<domain>` and `autodiscover.<domain>` | Served by the same Ingress |
| `records-srv` | The SRV records the zone declares: `_caldavs`, `_carddavs` and `_jmap` always, plus `_imaps` and `_submissions` when external clients are allowed | A record pointing at a port the public Service does not expose would send a client to a closed door, so the client-facing ones are only compared when those ports are published |

The `records` check itself is a summary: `N records are published as the mail server expects
them`, or `the public DNS does not match the zone file of <domain>: …`, whose fix tells the
operator to publish the records printed by the `records-*` checks below.

**`pop3s` is never compared**: the server has no POP3 listener and Ceffio does not pretend
one is published. If the zone file mentions a record Ceffio does not serve, it is simply not
part of the comparison — the check does not claim completeness.

When the server has generated no zone file for the domain, the summary is a warning (`the
mail server generated no zone file for <domain>: no record can be compared`) and the
operator has to open the domain in Stalwart's administration interface.

The comparison uses the **public resolvers** (`1.1.1.1`, `9.9.9.9` by default), never the
cluster's DNS, so it sees what the outside world sees. `CEFFIO_DNS_SERVERS` overrides them
with a comma-separated list. The blocklist check is the exception, see below.

## The checks

`ceffio module check mail` runs every prerequisite and prints them in order, one line each,
with the fix underneath when there is one:

```
  ✓ ok       MX record of the domain — mail for example.com goes to mail.example.com
  ✗ blocking Outgoing port 25 — the mail server cannot reach gmail-smtp-in.l.google.com on port 25: …
  ⚠ warning  End-to-end inbound test — no message from an outside domain has reached …
```

Symbols: `✓` ok, `⚠` warning, `✗` blocking, `·` not applicable. The command exits **1 when
at least one check is blocking**, 0 otherwise. The same list is in the console under the
module's **Checks** tab (`GET /api/modules/mail/checks`), and a blocking check turns the
module's state into `Degraded` with the reason `blocking checks: …`.

There are **eleven** top-level checks, and the `records` one expands into a summary plus
seven children — up to eighteen lines.

| Check | What it proves | Blocking? |
|---|---|---|
| `mx` | The domain's MX points at the mail host | Yes, when another provider receives the domain |
| `a-mail` | The mail host resolves to the platform's public address | Yes |
| `ptr` | The reverse DNS of the public address is the mail host, forward-confirmed | Yes in direct mode, warning in relay mode |
| `port25-out` | The server reaches a recipient's MX on port 25, probed from inside the pod | Yes in direct mode |
| `relay` | The relay answers a real SMTP session and accepts the credential | Yes in relay mode |
| `tls` | The certificate served on 25/465/993 covers the mail host and is valid | Yes |
| `records` + 7 children | Public DNS matches Stalwart's zone file | No, warnings |
| `inbound-25` | The public address answers on port 25 from the checking machine | No, warning |
| `inbound-test` | A real message from an outside mailbox arrived, with SPF/DKIM/DMARC results | No, warning |
| `dnsbl` | The public address is not on three blocklists | No, warning |
| `volume` | The volume holds the sum of the mailbox quotas, with 10 % free | No, warning |

A check is **not applicable** when it cannot mean anything: on a private `.local` domain
everything that needs public DNS is N/A (`mx`, `a-mail`, `ptr`, `port25-out`, `records`,
`inbound-25`, `inbound-test`, `dnsbl`); with no platform domain at all, all eleven are
`not_applicable` with `no platform domain is configured: the mail prerequisites cannot be
checked without one`.

### `mx`, `a-mail`, `ptr`

Read through the public resolvers. `mx` names the expected fix (`<domain>. MX 10
<mailhost>.`), `a-mail` compares the address of the host with the platform's and warns when
an IPv6 record exists that the platform does not serve, `ptr` does the forward-confirmed
round trip and says which side is wrong (missing PTR, PTR on another name, or an `A` record
that does not come back).

### `port25-out` and `relay`

The two halves of "can the server send at all", and only one of them is ever applicable.

In **direct** mode, `port25-out` resolves the first MX record of `gmail.com`, runs
`timeout 10 bash -c 'exec 3<>/dev/tcp/<mx>/25'` inside the mail pod and calls it blocking
when the connection does not come up:
`the mail server cannot reach <mx> on port 25: most hosting providers filter it, and
direct delivery then fails silently`. A probe that cannot run at all (a pod that refuses
exec) is a warning, not a verdict on the port.

In **relay** mode, `relay` validates the group and then opens a real SMTP session to the
relay: EHLO, STARTTLS when offered, AUTH PLAIN when a username is set. A refusal is
blocking with `the relay <host>:<port> refused: <reason>`; a missing setting is blocking with
the name of the field to fill. `port25-out` is N/A (`outgoing mail leaves through the relay:
the server does not connect to port 25 itself`), and so is `relay` in direct mode
(`outgoing mail is delivered directly: there is no relay to check`).

### `tls`

Dials the **cluster** Service on 25 (STARTTLS), 465 and 993, and judges the certificate
against the mail host name. It is blocking when the certificate cannot be used, and the
detail says which failure it is: a self-signed certificate, a name it does not cover, an
expired one, or one expiring in less than 14 days — `its renewal is failing`. The fix is the
one quoted in [Prerequisites](#a-certificate-covering-the-four-names).

### `records`

Described in [DNS records](#dns-records). Warnings only: a missing `_dmarc` record does not
stop mail from arriving, it costs deliverability.

### `inbound-25`

Dials `<public address>:25` from the machine running the check and waits for an SMTP banner.
It is the only check that says anything about the path the internet actually takes, and it is
still limited: see [Ports and the firewall](#ports-and-the-firewall). A failure reads `no
connection to <ip>: the port is filtered or nothing listens there (<reason>)`, with the fix
`open inbound port 25 (hosting firewall, router NAT) and re-run this check`.

### `inbound-test`

The only end-to-end check. It looks for `postmaster@<domain>` — created at install as an
alias of the admin account — reads its most recent message coming from another domain
(bounces and the platform's own domain excluded), and looks for the `Authentication-Results`
header: SPF, DKIM, DMARC pass.

Until someone sends a message to `postmaster@<domain>` from an outside mailbox, the check
stays a warning (`no message from an outside domain has reached postmaster@<domain> yet:
the inbound path has not been demonstrated`). That is not a defect: it is the check telling
you the last step of the proof is manual.

### `dnsbl`

Queries `zen.spamhaus.org`, `bl.spamcop.net` and `b.barracudacentral.org` for the public
address, **through the system resolver** — unlike the other DNS checks, `CEFFIO_DNS_SERVERS`
has no effect on it. `127.255.255.x` answers are treated as "query refused", not as a
listing: an anonymous resolver is not allowed to ask Spamhaus everything. When none of the
lists answers, the check is not applicable; a genuine listing is a warning.

### `volume`

Compares the PVC's capacity with the sum of the mailboxes' `maxDiskQuota`, and reads the free
space inside the pod with `df`. It warns when the quotas exceed the capacity — *delivery stops
when the volume fills, before the quotas do* — and when less than 10 % is free. A healthy
line reads `<used> of the <capacity> volume, <free> free (<n> %)`.

A mailbox quota can never exceed the volume size, and the volume can grow but **never
shrink**: `reglages.Valider` refuses `the default quota (N GiB) cannot exceed the volume size
(M GiB): a mailbox would not fit in the store`, and the server settings' Test refuses a
smaller volume with `the volume in place is already N GiB and Kubernetes cannot shrink it:
ask for N GiB or more`.

## Sending: direct or through a relay

Two settings in the group **`server`**, and a whole group for the relay.

| | `direct` | `relais` |
|---|---|---|
| How mail leaves | Ceffio connects to the recipient's MX on port 25 | Stalwart hands everything to the relay |
| Needs outbound port 25 | yes | no |
| Needs a correct PTR | blocking prerequisite | warning |
| Needs relay settings | no | host, port, username, password, STARTTLS |
| Practical when | the provider does not filter port 25 | **almost everywhere else** |

`direct` is the default because it needs nothing external, but a hosting provider that
filters port 25 makes it fail — silently, on delivery. `port25-out` exists precisely to make
that failure visible before it matters.

### The relay group

**Settings → module `mail` → group "Outbound relay (Stalwart)"**, or from a terminal:

```bash
ceffio module config mail relay hote=smtp.example.org port=587 utilisateur=ceffio exiger_tls=true
ceffio module config mail relay mot_de_passe=-          # reads the secret from standard input
ceffio module config mail relay --test                  # dials the relay, stores nothing
```

A secret is never passed as an argument — `key=-` reads it from the input, because an
argument is visible in `ps` and lands in the shell history. A secret left out keeps the
stored one, so the group can be re-saved without retyping the password.

| Field | Default | Meaning |
|---|---|---|
| `hote` | — (required) | The provider's SMTP relay, e.g. `smtp.example.org` |
| `port` | `587` | Submission port; 465 is accepted where the provider offers it |
| `utilisateur` | — (required) | The authenticated account on the relay |
| `mot_de_passe` | — | Stored **only** in `kv/ceffio/mail/relay`; never sent back to a page, leave empty to keep it |
| `exiger_tls` | `true` | Refuses a relay that does not upgrade to TLS. Turning it off sends the credential in clear text |

The **Test** button runs the sequence the send path needs: required fields, then a live
SMTP session (EHLO, STARTTLS when offered, AUTH PLAIN with the username and password). It
stores nothing. Switching to `relais` without a passing test is refused at apply time with
`the relay refuses the connection (<reason>); fill the relay group and run its Test first` —
the values are still stored, the apply is not.

Setting `relais` means setting **both** things: the send mode in `server` and the relay
group. Applying one re-applies the server, so the two never drift.

### The server group

**Settings → module `mail` → group "Mail server (Stalwart)"**:

| Field | Default | Meaning |
|---|---|---|
| `envoi` | `direct` | `Direct (recipient's MX)` or `Through the outbound relay` |
| `volume_gio` | `20` | Size of the volume holding every mailbox; it can grow, never shrink |
| `quota_defaut_gio` | `1` | Quota applied to each new mailbox; cannot exceed the volume size |
| `clients_externes` | `true` | Publish 465 and 993, so phones and Thunderbird can connect |

Applying the server settings re-applies the workload. **The workload is `Recreate`** — a
single writer on the RocksDB store — so re-applying means a short mail outage. Ceffio keeps
the volume size and the in-place changes as narrow as it can for that reason.

If the apply fails after the values are stored, the error says so and does not pretend
otherwise: `the values are stored, but applying them to the server failed: <cause> — from a
machine with kubectl, ceffio mail applies them`. The console has no Stalwart administrative
credential, so it can store a setting without being able to apply it; that error is the
honest answer, and `ceffio mail --domain <domain>` finishes the job.

## The platform's own mail

When the module is installed and its credential is in the vault, everything the platform
sends goes through `noreply@<domain>` on `mail.<domain>:465`, with a real submission login.
The install prints the credential it kept or rotated:

```
  ✓ platform sender credential unchanged: noreply@example.com
  ∙ platform sender credential refused: rotating the app password
  ✓ platform sender ready: noreply@example.com (submission login accepted)
```

The account is created with `emailReceive` disabled: mail sent **to** it bounces with a
delivery report from `MAILER-DAEMON@<domain>` instead of vanishing.

When the mail module is absent, Nextcloud and Keycloak fall back to the files module's
`outgoing_mail` group — an external SMTP relay the operator configures. When neither
exists, `platformmail.Resolve` returns nothing and the platform sends nothing, which is a
supported state, not an error.

`mail.<domain>` inside the cluster: the applications resolve it through public DNS, which
only works when the NAT hairpins and the port is published. When the probe from the pod says
the path is closed, the module installs an annotated `hostAliases` entry
(`mail.<domain>` → the `stalwart` ClusterIP) on the Nextcloud and Keycloak Deployments: same
host name, same certificate, no public exposure, and the deployment restarts to pick it up.

## Backup and restore

`ceffio backup` covers the mail volume **consistently**, which for Stalwart means stopped:

1. the `stalwart` Deployment is scaled to 0 and Ceffio waits for the pod to be gone
   (Stalwart has no online dump, and a tar taken while RocksDB runs exits 0 without being a
   backup);
2. a helper pod mounts the same PVC and archives `/var/lib/stalwart` (owner 2000:2000) into
   `volumes/stalwart-data.tar.gz`;
3. the Deployment is scaled back to 1 and its rollout is waited for.

The stop budget is 3 minutes. Inbound mail during the window is not lost: no server answers,
so the sending side keeps the message in its queue and retries — the same thing that happens
during any short outage.

The archive also contains the vault tree (`vault/kv-ceffio.json`), so
`kv/ceffio/stalwart/admin`, `kv/ceffio/mail/relay`, `kv/ceffio/mail/noreply` and every
`kv/ceffio/mail/comptes/<username>` app password are covered. The OpenBao **unseal keys are
not** archived: a full vault rebuild stays a documented manual step, see
[secrets.md](secrets.md).

```bash
ceffio backup --dir /var/backups/ceffio
ceffio restore ceffio-backup-20260101-030000.tar.gz --verify-only
ceffio restore ceffio-backup-20260101-030000.tar.gz
```

`ceffio backup` re-reads the archive and checks the fingerprints before declaring success
(`✓ Archive verified: N item(s), fingerprints match`). `restore` refuses a tampered or
incomplete archive, and restores secrets first, then databases, then the vault, then the
volumes.

## Upgrading from 0.10.x

`ceffio upgrade` replays every optional module whose state is `Installed` **or `Degraded`** —
a mail module degraded by a missing DNS record must keep being upgraded — and the existing
`stalwart` Deployment is detected, so the module is replayed with the new code.

The one rule that matters: **an installation that has `mail.relay` settings and no
`mail.server` blob keeps `envoi=relais`.** Defaulting it back to `direct` would silently stop
its outbound mail the day of the upgrade. A fresh 0.11.0 installation has `direct`.

The upgrade also forces a verified backup before it applies anything, and prints the rollback
command (`ceffio restore <archive>`). Full contract: [upgrade.md](upgrade.md).

If the installation still runs Stalwart 0.16, the 1.0 store conversion is a **separate,
offline runbook** — the server cannot open a 0.16 store, and the operation has a rollback:
see [stalwart-1.0.md](stalwart-1.0.md).

## For users

### Nextcloud Mail

An internal user's mailbox is provisioned completely: the Nextcloud Mail account is created
with the right servers, login and app password, so the user opens Nextcloud, clicks Mail and
reads their messages with nothing to configure.

| Setting | Value |
|---|---|
| IMAP | `mail.<domain>` port 993, SSL |
| SMTP | `mail.<domain>` port 465, SSL |
| Login | `<username>@ceffio.local` |
| Address | `<username>@<domain>` |

The account is created with `occ mail:account:create-imap` inside the Nextcloud pod, because
the Mail app has no HTTP endpoint that creates an account for someone else. The app password
is briefly visible in that pod's process list while the command runs; it is accepted because
the alternative — asking the user to type it — reintroduces the manual step the feature
exists to remove, and anyone who can read that process list can already exec into the pod.

### Thunderbird, phones, any IMAP client

Same settings as the table above: **IMAP** `mail.<domain>` 993 SSL/TLS, **SMTP**
`mail.<domain>` 465 SSL/TLS, login `<username>@ceffio.local`.

The address people write to is `<username>@<domain>` — it is an alias on the account. Both
exist because the OIDC directory maps every SSO login to `<username>@ceffio.local`, and
renaming the accounts would break the webmail login of every existing user.

Those ports are published only when `clients_externes=true`. With it off, Nextcloud Mail
still works (the applications get an in-cluster alias), but a phone on the internet cannot
connect at all.

### App passwords

Accounts behind the OIDC directory have **no password**: the credentials belong to Keycloak,
and the only credential a mail client can hold is an app password.

Users create their own, self-service:

1. open `https://mail.<domain>` and sign in through SSO (the account manager is Stalwart's,
   the login is Keycloak's);
2. in the account manager, create an app password;
3. paste it into Thunderbird or the phone instead of a password.

A user can hold **five** app passwords; the sixth is refused. Ceffio itself creates one per
internal user (named after the purpose, `nextcloud-mail`) and stores it in the vault, so
revoking that one does not lock the user out of their webmail — it makes Nextcloud Mail fail
until the mailbox is reprovisioned.

### Autoconfiguration

When `records-autoconfig` is published, Thunderbird and some mobile clients discover the
settings by themselves from `autoconfig.<domain>` and `autodiscover.<domain>`, which the
`mail` Ingress serves from Stalwart. Nothing else is needed, and nothing breaks when those
records are absent: the manual settings above always work.

## Limits and known gaps

Stated rather than hidden, because a check that overstates its coverage is worse than none:

- `mx`, `a-mail`, `ptr`, `port25-out`, `relay` and `tls` can all be **blocking**; a blocking check
  refuses the creation of a mailbox (`ValidateAccount` lists them) and turns the module
  `Degraded`.
- `inbound-25` proves reachability from the checking host only, never the client address, and
  it is a warning.
- The record comparison covers the families listed above; **MTA-STS' policy file itself is
  not fetched**, and `pop3s` is never compared.
- `dnsbl` bypasses `CEFFIO_DNS_SERVERS` and uses the system resolver; a provider that refuses
  the query yields "not applicable", not "clean".
- The certificate must be issued by cert-manager; until then the server serves its
  self-signed certificate and `tls` is blocking.
- Re-applying the server configuration restarts a `Recreate` workload: expect a short outage.
- The volume cannot shrink, and the default quota cannot exceed it.
- App passwords created for Nextcloud Mail are visible in the Nextcloud pod's process list
  for the duration of one `occ` call.

## Where it lives

| Path | Contents |
|---|---|
| `internal/mail/` | Stalwart: deployment, TLS, settings, records, checks, accounts, backup hooks |
| `internal/modules/mail/` | The module contract: install, update, settings, accounts, state, removal |
| `internal/platformmail/` | The platform sender: resolution, Nextcloud and Keycloak wiring, in-cluster alias |
| `cmd/ceffio/mail.go` | `ceffio mail` — deploy the layer alone |
| `cmd/ceffio/module.go` | `ceffio module check mail` |

Writing a module that declares checks or accounts: [adding-a-module.md](adding-a-module.md)
§10 and §11. The design note, the POC results and the PR chain are in
[plan-mail.md](plan-mail.md).