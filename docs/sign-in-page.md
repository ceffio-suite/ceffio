# The sign-in page

The page every user meets first is Ceffio's, not Keycloak's.

## What it is

A Keycloak login theme that **extends `keycloak.v2` and overrides no template**. That is
the whole design: a Keycloak upgrade keeps every page, every flow and every fix, and only
the look changes.

    internal/identity/theme/ceffio/login/
      theme.properties                              parent=keycloak.v2
      messages/messages_fr.properties               « Connexion à Ceffio »
      messages/messages_en.properties               "Sign in to Ceffio"
      resources/css/ceffio.css                      colours, four-colour edge, buttons
      resources/img/logo.svg, background.jpg, favicon.ico, favicon.svg
      resources/fonts/sora-latin-{400,600}-normal.woff2
      resources/fonts/OFL.txt                       SIL OFL 1.1 for Sora

The files live in the Go package rather than under `branding/`, because `//go:embed`
cannot reach outside the package directory: a copy in both places is how the one that
ships stops being the one that was edited.

## How it reaches the pod

`ceffio identity` — and every `ceffio install` — embeds the theme in the binary, writes it
as a ConfigMap, and mounts it read-only at `/opt/keycloak/themes/ceffio`.

Three details decide whether it works at all, and each fails **silently** when wrong:

- **ConfigMap keys cannot contain a slash.** Paths are flattened and `items[].path`
  rebuilds the tree. Without it, Keycloak finds nothing at `login/theme.properties` and
  renders the **default page with no error anywhere**.
- **Text goes in `data`, binary in `binaryData`.** A JPEG in `data` is refused by the API
  server with a message about invalid UTF-8 that names neither the file nor the reason.
- **A `ceffio.io/theme-checksum` annotation on the pod template is the restart mechanism.**
  Production Keycloak caches themes: replacing the files changes nothing until the process
  restarts. Kubernetes restarts the pod when the value changes, and only then.

## The header, which is not in a template

The logo and the slogan above the card are built by `keycloak.v2` from the realm's
**`displayNameHtml`**:

```html
<div class="kc-logo-text"><span>Ceffio</span></div><p class="ceffio-slogan">La suite collaborative souveraine</p>
```

`kc-logo-text` is the block the parent styles; `ceffio-slogan` is Ceffio's own. A test
reads the classes out of that constant and the selectors out of the stylesheet that ships —
a header whose classes are styled by nothing renders as raw text inside the card, which
looks like a broken theme rather than a missing rule.

## Changing it

A setting: **Settings → module `identity` → group `login_page`**, or

```bash
ceffio module config identity login_page theme=ceffio      # the Ceffio page (default)
ceffio module config identity login_page theme=keycloak.v2 # Keycloak's own page
ceffio module config identity login_page default_locale=fr
```

Changing **which** theme is used needs no restart: Keycloak resolves the realm's
`loginTheme` per request. Shipping a **new** theme restarts the pod, because the files are
cached at startup.

Going back to Keycloak's page is the fastest way to tell a theming problem from a sign-in
problem.

## What is not themed

- **The `master` realm.** That page is how Keycloak itself is administered, and an
  operator who lands on the wrong door must see it.
- **The email templates and the account console.** Separate work, not done.

## Licence

Sora is under the **SIL Open Font License 1.1**. `OFL.txt` ships inside the theme, and
`THIRD_PARTY_LICENSES.md` names it: a theme is a redistributable artifact, so the licence
travels with it rather than being referenced from the repository root.

## See also

- [keycloak-production.md](keycloak-production.md) — Keycloak's own mode and hostname
- [architecture.md](architecture.md) — where the identity layer sits