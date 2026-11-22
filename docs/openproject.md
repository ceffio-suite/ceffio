# The `openproject` module

An **optional** module that adds project management at `https://projects.<domain>`:
projects, work packages, Gantt charts, boards, time tracking and file attachments, behind
the suite's single sign-on.

```sh
ceffio module install openproject --domain company.fr
```

Or `--with openproject` during the initial install, or the Modules page in the console.

It is **not installed by default**: OpenProject asks for roughly 4 GiB of RAM for a small
installation, which is a decision, not a side effect.

## What it deploys

| Object | What it is |
|---|---|
| `Deployment/openproject` | One pod, three processes of the upstream image: the **seeder** (init container: migrations and a fresh-database seed), the **web** server on port 8080, and the **worker** (background jobs) |
| `Deployment/openproject-proxy` | `oauth2-proxy` in front of the application, port 4180 — the only thing the Ingress points at |
| `Service/openproject`, `Service/openproject-proxy` | Cluster-internal endpoints |
| `Ingress/openproject` | `projects.<domain>` → the proxy, TLS from cert-manager, HTTP redirected to HTTPS by the middleware of `ceffio-system` |
| `NetworkPolicy/openproject-only-from-proxy` | Refuses every client but the proxy on port 8080 (see [Signing in](#signing-in)) |
| `Deployment/openproject-ldap` | One pod resolving a login for the sign-in, port 1389 — not a directory (see [The lookup the header triggers](#the-lookup-the-header-triggers)) |
| `Service/openproject-ldap` | `openproject-ldap.ceffio-system.svc:1389`, the address the auth source names |
| `NetworkPolicy/openproject-ldap-only-from-app` | Refuses every client but the application pod on port 1389 |
| `PersistentVolumeClaim/openproject-assets` | 10 GiB on the cluster's storage class, mounted in the web **and** worker pods |
| `ServiceAccount/openproject` | One identity for both pods, and the only one the vault policy names |
| One PostgreSQL database and role | `openproject` / `openproject` on the shared cluster of the `data` layer (pod `ceffio-pg-1`) |
| One Keycloak client | `openproject`, confidential, used by the **proxy**; OpenProject itself never talks to Keycloak |

Everything lives in `ceffio-system` — not a namespace of its own, because the console holds
a Role in each platform namespace and that grant is pinned to the ten namespaces that exist
on every installation. An optional module's own namespace would not exist before the
module is installed, and the console's Deployment would then fail to start.

**The secrets are generated once and reused**, in the vault under
`kv/ceffio/openproject/`: `db` (`username`, `password`), `app` (`secret_key_base`,
`admin_password`), `oauth2-proxy` (`client-secret` written by the SSO layer, `cookie_secret`).
Re-running the install never replaces them — a new database password breaks the pair with
the role, a new Rails secret invalidates every session and signed link, a new cookie secret
signs everybody out. The passwords are hexadecimal, computed here: the database password is
spliced into a `postgres://` URL and into SQL, where hexadecimal needs no escaping.

**The install asserts its own vault access before deploying anything.** `ceffio vault`
builds the module policies and the Kubernetes roles from the registry of the binary that
runs it, so a vault deployed by an earlier release has no role for a module it never saw —
and the pods then fail in Init with `invalid role name "openproject"`, after the
15-minute wait. The installer writes the policy and the role itself (same content, so a
re-run changes nothing), with the installation token, before the first secret is read.

Installing waits up to 15 minutes for the first start: a fresh database runs every
migration and the seed, and a Longhorn volume attachment on a fresh disk adds minutes.

**The install needs the vault, therefore the two variables the CLI reads.** The entries
above are created by the module itself, and the CLI reaches OpenBao with `BAO_ADDR` and
`BAO_TOKEN` — no default, no file, no cluster lookup. Without them the install stops before
touching anything:

```
openproject: vault unreadable for openproject/db: no vault configured: cannot read openproject/db
```

```sh
export BAO_ADDR=https://bao.<domain>
export BAO_TOKEN=$(kubectl -n ceffio-vault get secret openbao-installation \
  -o jsonpath='{.data.token}' | base64 -d)
```

`openbao-installation` is the installation token: the vault's own administrative token for
non-interactive writes, still valid after the setup revoked the root token. The same two
variables are what `ceffio upgrade` and the other modules read (see [upgrade.md](upgrade.md)).

## Signing in

OpenProject's **OpenID Connect providers are an Enterprise add-on** — the Community edition
hides the button. What the Community edition does offer is header-based "auth source SSO": a
trusted reverse proxy names the signed-in user in a header, and OpenProject logs that user
in. That is the pattern the suite already uses for the storage interface, and this module
reuses it:

```
browser → Traefik → oauth2-proxy (OIDC with Keycloak) → OpenProject
                         sets X-Forwarded-Preferred-Username
```

A trusted header is only as trustworthy as the set of clients that can send it, so the two
halves of the design are:

1. **Nothing but the proxy reaches OpenProject.** The Ingress points at the proxy, never at
   the application, and the NetworkPolicy refuses every other pod in the cluster. Without
   it, any pod could call `openproject.ceffio-system.svc:8080` with a forged header and act
   as the administrator.
2. **The proxy overwrites the header** from the token it validated (`--pass-user-headers`),
   so a browser cannot smuggle one in.

The proxy uses PKCE (`S256`), a secure cookie valid 8 hours and refreshed hourly, and a
120-second upstream timeout (large uploads and exports outlast the 30-second default).

**Signing out closes both sessions.** OpenProject's own sign-out URL is the proxy's
`/oauth2/sign_out`, which clears the proxy cookie and then redirects to Keycloak's
end-session endpoint for the `openproject` client: the OpenProject session, the proxy
session and the Keycloak session all end, instead of the first two only.

**What this section describes is the transport.** The header arrives safely; OpenProject
then turns the login into a user through the LDAP auth source the account is linked to, so
the module ships the answer to that one lookup — see
[The lookup the header triggers](#the-lookup-the-header-triggers).

## Accounts

**Header SSO creates no account.** OpenProject looks the login up and redirects to a failure
page when nobody matches. The module therefore takes part in the Users page:

- creating a Ceffio user creates the OpenProject account;
- a user created **before** the module was installed appears with a **create** action on
  the Users page, which is what provisions the missing account;
- the Ceffio administrator (`adminceffio`) is an OpenProject administrator; no other user is
  promoted from here — who administers OpenProject is OpenProject's own decision;
- suspend and resume set the account's status, delete removes it.

Accounts are created through Rails (`rails runner` in the application pod), not with SQL:
OpenProject's validations, defaults and callbacks belong to the application. Each account is
linked to an LDAP auth source named `Ceffio SSO`. The link is what marks the account as
authenticated from outside and leaves it **without a password**, so the OpenProject login
form cannot be used against it. Listing accounts, which happens on every page load, is one
SQL query instead: a Rails boot per page load would cost tens of seconds.

### The lookup the header triggers

The link is **necessary but not sufficient**. OpenProject resolves the header's login
*through the auth source*, with an LDAP search (`auth_source_sso.rb` calls
`LdapAuthSource.find_user`), so a source pointing at nothing makes every sign-in fail. That
is what the module did until it shipped a responder: the auth source names
`openproject-ldap.ceffio-system.svc:1389`, and one pod answers the search.

**The responder is not a directory.** It holds no users, no passwords, no e-mail addresses,
and it writes nothing; it parses the search filter, takes the login out of it
(`uid=<login>`), and returns the one entry that names that login. The account row decides
what happens next: header SSO only logs in an account that exists and is active, which is
why the Users page above is still the thing that provisions people.

It is the Ceffio image running its own `ldap-responder` subcommand — a few hundred lines
with no dependency beyond the standard library. The alternatives were rejected on
proportion: OpenLDAP or lldap would need a second volume, a backup path and a
synchronisation of Keycloak's users into it, all to answer a question already contained in
the query; a Rails patch to the vendor image would be overwritten by the next upgrade.

The traffic is plaintext LDAP **inside the cluster only**, and the
NetworkPolicy is what makes that acceptable: the application pod is the only client, the
service is not exposed by any Ingress, and the responder requires no credential to answer —
it authenticates nobody. It runs unprivileged (uid 65532, read-only root filesystem, no
capabilities), on port 1389 because 389 is privileged, with a 64 KiB message cap, a 30-second
timeout and at most 32 concurrent connections.

The seeded local `admin` account is **locked on purpose**, and `admin`, `system` and
`anonymous` cannot be provisioned: a Keycloak user named `admin` would otherwise become the
instance administrator.

## Backup and restore

`ceffio backup` covers the module through both of its data paths:

- the **database** `openproject` — the projects, work packages, users, time entries;
- the **volume** `openproject-assets` — the attachments, under
  `/var/openproject/assets/files`.

The volume is copied **live**, like the Nextcloud and ONLYOFFICE ones: an attachment is a
whole file written once under its own name, so a copy taken during an upload loses at worst
that one file, while stopping the application would cost an outage on every backup.

An installation that does not have the module has neither the database nor the volume, and
the backup **skips them instead of failing**: a missing database or volume is not an
incomplete archive. The distinction is deliberate and tested — a volume that *exists* but
whose pod is gone holds data the backup must not drop, so it is an error, not a skip.

Restoring requires the module to be installed: `ceffio restore` refuses to write an archive
volume into a cluster that has no such volume, and says so.

## Verifying it

```sh
ceffio module status openproject                       # Installed only when both pods are ready
kubectl -n ceffio-system get pods,ingress,pvc
kubectl -n ceffio-system logs deploy/openproject -c seeder   # migrations, on a failed first start
```

The state reads the cluster and never guesses: the application, its proxy **and** its LDAP
responder ready is `Installed`, and any one of them missing is `Degraded` with the reason —
the proxy and the application without the responder signs nobody in, and the application
without the proxy leaves users reaching an error page after signing in (the `seeder`
container's log names the failing migration).

End-to-end: open `https://projects.<domain>`, sign in through Keycloak, create a project,
upload an attachment, then sign out and check that Keycloak's session is closed too.

When a sign-in fails, the responder says which lookup it answered:

```sh
kubectl -n ceffio-system logs deploy/openproject-ldap   # "ldap: lookup uid=<login>: one entry"
kubectl -n ceffio-system logs deploy/openproject -c web | grep auth_source_sso
```

`ldap: lookup without a usable uid value: no entry` means the search carried no login to
resolve; no line at all while OpenProject logs `Connection refused` means the auth source
still names another address (an installation created by an older release — re-running the
install or the Users page rewrites it).

## Removing it

```sh
ceffio module remove openproject --yes
```

**This deletes every project, work package and attachment**: the database is dropped
(`DROP DATABASE ... WITH (FORCE)`, which ends the sessions the terminating pod still holds),
the volume is deleted, and so are the Ingress, the two deployments, the three
NetworkPolicies, the responder's Service, the certificate and its Secret, the ServiceAccount
and the Keycloak client. Keeping the database
without the attachments would leave work packages pointing at files that no longer exist.

**The vault entries are kept**, as for the storage interface: removing them would destroy a
client secret that is still registered in Keycloak if the client deletion failed. They hold
a few short strings and a reinstall reuses them.

## What it does not do

- **No outbound e-mail.** The module configures no SMTP relay, so OpenProject's
  notifications and invitation e-mails are not delivered until one is set in OpenProject's
  own administration. The `mail` module's relay is not wired to it.
- **No high availability.** One web pod, and the update strategy is `Recreate` — a rolling
  update would start the new pod while the old one still writes the shared volume. A
  redeploy therefore interrupts the service for the length of a restart, migrations included.
- **No directory synchronisation.** Accounts are created from the Users page, not imported
  from Keycloak: there is no group or team mapping, and a Keycloak user without an
  OpenProject account does not get one automatically.
- **Enterprise features stay absent.** The Community edition is what is deployed; the
  Enterprise add-ons (OpenID Connect providers among them) are not unlocked by this module.

## What the tests pin

`internal/modules/openproject/module_test.go` renders the manifests and asserts the
properties the design rests on: the route reaches the proxy and not the application, the
NetworkPolicy admits only the proxy, the three processes share one environment (a worker
that believes in another host name sends links to it), the vault agent runs before the
seeder, sign-out closes both sessions, refused logins are refused, the account script
interpolates nothing (data travels as JSON in a non-interpolating heredoc), the auth source
can only name the responder and is re-saved on an existing installation (otherwise an older
row keeps pointing at the loopback address), the responder's policy admits the application
and nothing else, its probes are TCP (the image has no shell to exec one in), the SQL
refuses a password it did not generate, and the state reads the cluster.

The responder's protocol handling has its own tests in `internal/ldapshim`: they hand-build
RFC 4511 messages instead of using the package's own encoder, so what they prove is that a
real LDAP client is understood, not that the encoder agrees with the decoder.

Two guardrails outside the package also see this module: the registry test that every
module is imported in `internal/modules/all.go`, and the console's RBAC non-regression test,
which records the one new right the module needs (`networkpolicies` in `ceffio-system`) and
keeps the total of decided tuples at 1118.