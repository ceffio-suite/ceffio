# Ceffio administration console

Web operations interface for the Ceffio stack. It answers the question the
command line does not make comfortable: **"what is running, and is everything
fine?"** — without typing `kubectl` on the VM.

    https://admin.ceffio.example.com

## What it shows

Views derived from the cluster's real state (never from a cache or a
hand-written list):

| View | What it exposes |
|---|---|
| **User applications** | Every service rendered to users, with its URL, its role, and the computed state of its pods (ready/total) |
| **Certificates** | Every TLS certificate, its host, its expiry date and the number of days left |
| **Infrastructure** | The technical layers (data, identity, files, office, video, system), pod by pod, with the restart count |
| **Users** | The SSO accounts of the Keycloak realm `ceffio` |
| **Nextcloud apps** | The collaboration applications, grouped by category, with their license, their documentation link and a button to enable or disable them |

A service's status is not declared: it is **computed** from the pods that
carry it. A service whose pods are all ready is green; a pod restarting in a
loop shows immediately, with its counter.

## What it lets you do

- **See** the stack's state on one page (dashboard)
- **Manage SSO accounts** — list, create, deactivate, reactivate, reset the
  password in the Keycloak realm `ceffio`
- **Manage Nextcloud applications** — enable or disable catalog apps (see the
  dedicated section below)
- **Follow certificate expiry** before they break a service
- **Rotate secrets** — the console reads and writes them through the OpenBao
  vault

### The administration account is not a user like the others

The account used by the vault's OIDC role (`adminceffio`) is presented in its
own card, apart from the ordinary account list. It carries no destructive
buttons — and that is not only cosmetic: **the API itself refuses** any
deactivation, reactivation, password reset, or creation of a homonymous
account against it, whatever the identifier used (id, name, different case).
A protection that lived only in the page would be one `curl` away from
nothing. Deactivate always has its inverse: the `reactivate` action exists,
because an account deactivated by mistake must not be a dead end.

## Managing Nextcloud applications

The "Nextcloud apps" page presents two **separate, never mixed** lists:

```
Installable applications        checkboxes — one click enables or disables
Applications with an external   read-only — a separate service is required
dependency
```

**Why this separation:** an application that requires an extra server
(Whiteboard and its WebSocket server, Recognize and its AI models, the
antivirus and its ClamAV server) **does not work** after a simple click.
Presenting it as checkable would suggest otherwise, and the user would then
look for why the feature does not work. It is therefore listed for
information, with its dependency written in black and white, but **not
installable** from this page.

What a click does:

```
enable    → the application becomes available to users
disable   → the application disappears from the interface, but stays on disk
            and can be re-enabled (no data is destroyed)
```

**How it works technically:** the console calls the **Nextcloud OCS API**
(`/ocs/v2.php/cloud/apps`), with a dedicated service account
(`ceffio-console`) and a revocable application password. It runs no command in
the cluster and obtains no Kubernetes administration right: it makes
authenticated HTTP calls, nothing else.

> A first version went through Kubernetes Jobs running `occ` inside the
> Nextcloud pod. That was a lot of moving parts — execution ServiceAccount,
> PVC mount (which does not cross namespaces), one pod per operation, log
> reading — for a result the API gives in one call. The API is the right
> approach; the Jobs were removed.

## What it does NOT do

Stated clearly, to avoid false expectations:

- It neither **restarts** nor **deploys** anything (deployment goes through
  the CLI `ceffio install`)
- It does not **download** applications from the app store: the catalog is
  controlled, not open
- It does not permanently **delete** an application or its data (deactivation
  is reversible, destruction is not)
- It does not manage **backups** (see `ceffio backup` / `ceffio restore`)
- It exposes **no** user data: no files, no messages, no meeting content

## Authentication and secrets

Access is protected by a **single key** (token) that lives in the OpenBao
vault, at `kv/ceffio/console/api`. Like every other secret of the suite, it
reaches the console pod through the **OpenBao agent injector**: the pod reads
the rendered `/secrets/env` file itself (the console image has no shell), and
no application credential exists as a Kubernetes Secret anymore.

The public page (`/`) is served without authentication — it is the page that
asks for the key in JavaScript, then sends it in the `Authorization: ***
header on every `/api/*` call. In other words: **no data is accessible without
the key**, the bare page contains nothing.

> **Accepted limit:** the API key is a static token. Human users reach the
> vault itself through OIDC (Keycloak); full SSO lockdown of the console is
> planned as hardening. Treat this key as an administration secret.

## API

Entry points, all behind the key:

    GET  /api/status                     full state: services, certificates, layers
    GET  /api/users                      list of the realm's accounts (the
                                         administration account carries
                                         "protege": true)
    POST /api/users                      creation (password not temporary; the
                                         reserved name is refused)
    POST /api/users/{id}/{action}        action = deactivate | reactivate | password
    GET  /api/apps                       catalog + real state of the applications
    POST /api/apps/{id}/install          enables an application
    POST /api/apps/{id}/uninstall        disables an application

Responses are raw JSON. A call without a valid key answers `401` — never
partial, never silent. Any action attempted against the protected
administration account answers `403`, by id as well as by name.

## How it is built

The server runs **inside the cluster** (`ceffio-system`), and that is what
makes the implementation simple: it talks to the Kubernetes API with the
`ceffio-admin` service account, and to Keycloak through its internal service.
No access from outside is necessary.

    internal/console/
      console.go    HTTP server, routes, key authentication
      status.go     state collection (pods, certificates, services)
      users.go      Keycloak account management (incl. the protected account)
      apps.go       Nextcloud application management (OCS API)
      deploy.go     deployment of the console itself into the cluster
      web/
        index.html  single page (HTML + CSS + JS, no external dependency)

The interface is **a single HTML file**, without framework or CDN: it is
embedded in the Go binary and served as-is. No front build chain, no
`node_modules`, nothing to install to modify it.

Application management goes through the **Nextcloud OCS API**, with a
dedicated service account and an application password. Two practical points:
the credentials live in the vault (`kv/ceffio/console/nextcloud-api`), and
Nextcloud must authorize the cluster's internal ranges to operate without
password confirmation (`allowed_no_password_confirmation_ranges`) — without
which any application change is refused with "Password confirmation is
required".

The call to Keycloak goes through `kcadm` (the administration tool shipped
with Keycloak): it is the only path that guarantees a state Keycloak considers
coherent. Never a direct database write. Every `kubectl exec` names its
container (`-c keycloak`): the injector adds an init-container to the pods,
and an exec without `-c` no longer knows which container to target.

## Required rights

The console uses a dedicated `ClusterRole` (`ceffio-admin`), limited to
**reading** pods, services, deployments, ingresses and certificates. It has no
right to write in the cluster — deployment remains the CLI's business.

## Deployment

Handled by `ceffio install` (phase 11), which builds the image, loads it into
the cluster and creates the ingress `admin.<domain>`. The published image is
built by the
[`ceffio-suite/ceffio-console`](https://github.com/ceffio-suite/ceffio-console)
repository and versioned there. To rebuild it alone:

    cd internal/console
    docker build -t localhost/ceffio-console:<version> .
