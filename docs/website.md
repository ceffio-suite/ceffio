# The `website` module

An **optional** module that publishes a static, bilingual (French/English) landing page on
the installation's **root host** — `https://<domain>/`, the host where nothing else answers
today.

It is not installed by default. A public page is a decision, not a side effect: the module
exists so that an operator who is given a domain can say "this domain is mine, here is what
it serves", without that becoming true for installations that never asked.

```sh
ceffio module install website --domain company.fr
```

Or `--with website` during the initial install, or the Modules page in the console once the
platform chart has created the namespace (see [Why the namespace is declared in the
chart](#why-the-namespace-is-declared-in-the-chart)).

## What it publishes, and what it does not

| It publishes | It does not |
|---|---|
| One page in French (`/`) and one in English (`/en/`), each with a single `<h1>` | A form, a newsletter, a comment box |
| The suite's modules, three steps to get started, five guarantees | Any script, tracker, cookie, analytics or third-party sub-resource |
| `style.css` and `logo.svg`, served from the same namespace | A web font, an image CDN, a CSS framework |
| `robots.txt` and `sitemap.xml` pointing at the same host | A phone number, a postal address, an address nobody configured |
| A contact address **if the operator sets one** (see below) | An address derived from the host, the project or the editor |

The page is written in semantic HTML5 with `<meta>` cards (`description`, Open Graph,
canonical, `hreflang` alternates for `fr`, `en`, and `x-default`). Everything is embedded in
the Ceffio binary with `go:embed` (`internal/website/site/`), so the published bytes are the
bytes of a release — no build step, no asset pipeline, nothing fetched at install time.

## The contact address

The page publishes **no contact address by default**. The ways to reach the operators are
then the console (`https://admin.<domain>`), the GitHub project, and
`https://<domain>/.well-known/security.txt` (published by the ingress layer) — the footer
says so, in the page's language.

An installation that *does* want to publish an address sets it as a setting:

```sh
ceffio module config website landing_page contact_email=contact@company.fr
```

or through the module's **Settings** tab in the console (the generic settings form: no
bespoke page). The value is stored in `ceffio-settings` under the `website.landing_page`
key, like every other module setting, and the page is re-rendered in the same command: the
ConfigMap changes, the `ceffio.io/page-checksum` changes with it, and the pod rolls — nginx
has already read the old page, so a Settings save without the roll would change nothing
visible. No reinstall is needed, and saving the same value twice rolls nothing.

Setting it to the empty string (`contact_email=`) removes the address again and restores the
"no address" sentence.

**Why a setting and not a constant.** A published address is the installation's own
identity: on the project's own domain it is `contact@mandem-it.com`, on a customer's
installation it is the customer's. Committing an address here would publish one
organisation's inbox from every installation, and deriving it from the host would invent an
alias nobody reads. The empty default is the only value that is correct for an installation
that never asked.

The address is validated in two places, with the same pattern (`website.MotifAdresse`): the
settings form refuses a value that is not an address before writing it, and the renderer
refuses it again before the bytes are published. A value that is not `name@host.tld` is an
error, never a broken `mailto:` on the public page.

## Why the page is on the apex host

The console lives on `admin.<domain>`, the services on `cloud.`, `office.` and the rest. The
apex host is the one a visitor types, and today it answers nothing (`404`, no route). The
module's Ingress claims exactly that host:

- rule `Host: <domain>`, path `/`, TLS secret `ceffio-website-tls` (its own certificate,
  not the platform wildcard): removing the page must not touch the certificate every other
  service depends on;
- HTTP router pinned to `websecure`, so the page is only ever served over TLS;
- HTTP-01 challenge routes are untouched: the certificate is issued by cert-manager with the
  same cluster issuer as the rest of the installation (`ingress.PourDomaine`).

**The HTTP apex still answers `404`.** Cross-namespace Traefik middlewares are not enabled
on Ceffio clusters, so the module cannot attach an HTTP→HTTPS redirect to the shared entry
point. That behaviour predates the module and is unchanged by it: a client that insists on
`http://` gets the same nothing it got before.

DNS is *not* handled by the module: the apex `A` record must already point at the machine
(it does on an installation that serves `admin.<domain>` from the same certificate issuer).
`ceffio dns --domain <domain>` lists the records an installation expects; the page adds no
record of its own.

## How it is served

One pod, `ceffio-website/ceffio-website`, running a **pinned** `nginx:1.29.8-alpine` by tag
**and** digest from `internal/version` (`version.Image("nginx")` — the same registry
`ceffio status` and the SBOM read).

- The page, the stylesheet, the logo, `robots.txt` and `sitemap.xml` live in a ConfigMap
  (`ceffio-website`, one key per file), generated at install time from the embedded files.
  The `{{DOMAIN}}`, `{{ADMIN_URL}}` and `{{SECURITY_URL}}` placeholders are resolved with the
  installation's domain — nothing is hardcoded in the shipped HTML. `{{CONTACT_EMAIL}}` is
  the one placeholder that comes from a setting, not from the host: it is filled with
  `landing_page.contact_email`, and the blocks that carry it (`<!-- contact:start -->` …
  `<!-- contact:end -->`) are removed entirely when that setting is empty, together with
  their markers.
- The nginx server block is itself a ConfigMap key, mounted over `/etc/nginx/conf.d`: it is
  the *only* server block nginx loads.
- A `ClusterIP` Service maps port 80 to the container's 8080. The container does not bind a
  privileged port, so it needs no `NET_BIND_SERVICE`.
- The Deployment carries a `ceffio.io/page-checksum` annotation over the published content.
  A page that changes rolls the pod; a re-install that changes nothing does not.

The pod is hardened for the public internet: read-only root filesystem, no service account
token mounted, `allowPrivilegeEscalation: false`, all capabilities dropped except the three
nginx needs to drop privileges (`CHOWN`, `SETGID`, `SETUID`), `seccompProfile:
RuntimeDefault`, and resource requests of `10m` CPU / `16Mi` memory (`200m` / `64Mi` limits).

The server sends the headers itself, so they are present even if someone fetches a file that
is not the page: `Content-Security-Policy: default-src 'none'; img-src 'self' data';
style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
strict-origin-when-cross-origin`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and
`Strict-Transport-Security: max-age=31536000`. `server_tokens off` hides the nginx version.

There is a `/healthz` location returning `200 ok` for the readiness and liveness probes; it
serves no file from the page.

### Why the namespace is declared in the chart

The module declares `ceffio-website` in `Info.Namespaces`, and the platform chart creates it
(`namespaces: website: {}` in `values.yaml`). This is deliberate, and it is the one thing an
optional module needs from the core:

- `ceffio install` runs with an identity that may create namespaces;
- the **console** installs modules with a namespace-scoped identity, which may not.

Declaring the namespace in the chart means a page installed from the console lands in a
namespace that already exists, instead of failing with `forbidden`. On an installation that
never installs the module, it costs one empty namespace.

`Install` still tolerates a missing namespace (it creates it when the identity is allowed to)
and explains the failure when it is not: *"run `ceffio install` once (the platform chart
declares that namespace), then retry"*.

## Verifying it

```sh
# the module's own view: status, detail, blocking reason
ceffio module status website --domain company.fr

# the page, over the public internet, with TLS
curl -sS -D- https://company.fr/ | head -20
curl -sS https://company.fr/ | grep -c '<section'      # 4
curl -sS https://company.fr/en/ | grep -o '<html[^>]*>' # lang="en"

# the certificate is the module's own secret
curl -sSv https://company.fr/ 2>&1 | grep -E 'subject|issuer|expire'

# what the pod is allowed to do
kubectl -n ceffio-website get deploy ceffio-website -o jsonpath='{.spec.template.spec.containers[0].securityContext}'
```

A successful `Install` waits up to three minutes for one ready replica and prints the
progress (`1/1 replica(s) ready`). Certification is **not** waited for: cert-manager issues
it in the background, and the page answers `503` from Traefik until the certificate exists.
That is a normal first-install sequence, not a failure — `ceffio module status website` keeps
reporting the truth meanwhile.

## Removing it

```sh
ceffio module remove website --domain company.fr
```

The command asks for confirmation (unless `--yes`), then deletes the Ingress, the Service,
the Deployment and the ConfigMap, and requests the deletion of the namespace. The namespace
deletion may be refused — the platform chart declares it, and the console's identity cannot
delete namespaces it does not own; the module reports *"namespace ceffio-website kept"* and
considers the removal complete, because nothing is served any more. The apex host returns to
answering nothing.

`Uninstall` is re-runnable: an object that is already gone is not an error, so a retried
removal from the console converges instead of failing on the first missing object.

## What the tests pin

| Test | What it prevents |
|---|---|
| `internal/website/site_test.go` | A published file with an unresolved `{{…}}` placeholder or a leftover contact marker; an embedded file missing from (or extra to) the declared list; a page with a second `<h1>`, a `<script>`, an inline `style=`, or a sub-resource that is not relative; a `mailto:` (or a named address) on an installation without one; an address published in only one language; a configured address that lands in the wrong number of places or is not the configured one; a non-address accepted as one; an IPv4 literal |
| `internal/modules/website/module_test.go` | An install that does not create the namespace / ConfigMap / Service / Deployment / Ingress; a re-install that restarts the pod or leaves drifted content; a page change that does *not* roll the pod; `State` claiming `Absent` without looking (it must say `Unknown`); an `Uninstall` that is not re-runnable; `Info` that stops being optional, non-default, or that starts declaring a Service on the apex host |
| `internal/modules/website/reglages_test.go` | A settings form whose address field is required, has a default, or uses a pattern other than the renderer's; a stored address the published page ignores; a save that does not change the ConfigMap or does not roll the pod; a save of the same value that rolls the pod for nothing; a removal that leaves the old address published; an invalid value written to the store |
| `internal/version/version_test.go` | A hardcoded image outside the registry, a floating tag, an undocumented component |
| `internal/charts/namespaces_test.go` | The `ceffio-website` namespace disappearing from the chart |

## Why not a console route, a CLI subcommand, or a Service entry

- **No CLI subcommand** (`ceffio website serve`): the module contract is `Install`/`State`/
  `Uninstall`; a feature that needs its own binary subcommand is a feature that was not
  expressed where the platform expects it (`docs/adding-a-module.md`, checklist item 11).
- **No bespoke console page**: the page is static, and its one datum is a setting the
  generic Settings tab already renders (`Configurable`, like every other module). A page of
  its own would be a second form for the same ConfigMap key.
- **No `Info.Services` entry**: the console renders a Service as `<sub>.<domain>` and the
  apex has no `<sub>`, so the entry would show as `.<domain>`. The declared absence is
  documented here and pinned by the test.