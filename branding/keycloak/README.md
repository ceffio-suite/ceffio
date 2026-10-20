# The Ceffio login theme for Keycloak

The page users see when they sign in to the suite. It applies to the `ceffio` realm
only — the `master` realm keeps Keycloak's own page, because that is how Keycloak
itself is administered and an operator who lands on the wrong door must see it.

## Where the files are

    internal/identity/theme/ceffio/login/
      theme.properties                              parent=keycloak.v2
      messages/messages_fr.properties               « Connexion à Ceffio »
      messages/messages_en.properties               “Sign in to Ceffio”
      resources/css/ceffio.css                      colours, four-colour edge, buttons
      resources/img/logo.svg, background.jpg, favicon.ico, favicon.svg
      resources/fonts/sora-latin-400-normal.woff2
      resources/fonts/sora-latin-600-normal.woff2
      resources/fonts/OFL.txt                       SIL OFL 1.1 for Sora

They live in the Go package rather than under `branding/` because `//go:embed` cannot
reach outside the package directory: keeping a copy in both places is how the one that
ships stops being the one that was edited.

## How it works

**It extends `keycloak.v2` and overrides no template.** That is the whole design: a
Keycloak upgrade keeps every page, every flow and every fix, and this theme only
changes the look. `theme.properties` chains the stylesheets — the parent's
`css/styles.css` first, then `ceffio.css` — so Ceffio's colours land on top of
PatternFly rather than beside it.

**The colours come from PatternFly's variables**, re-pointed rather than overridden
component by component. `--pf-v5-global--primary-color--100` and its siblings restyle
every page of every flow — login, password reset, OTP, required actions — without
naming a single one of them.

**The header does not come from a template.** The logo and the slogan above the card
are built by `keycloak.v2` from the realm's `displayNameHtml`:

```html
<div class="kc-logo-text"><span>Ceffio</span></div><p class="ceffio-slogan">La suite collaborative souveraine</p>
```

`kc-logo-text` is the logo block the parent styles; `ceffio-slogan` is Ceffio's own.
A test reads the classes out of that constant and the selectors out of the stylesheet
that actually ships — a header whose classes are styled by nothing renders as raw text
inside the card, which looks like a broken theme rather than a missing rule.

## How it reaches the pod

`ceffio identity` (and every `ceffio install`) embeds the theme in the binary, writes
it as a ConfigMap `keycloak-theme-ceffio`, and mounts it read-only at
`/opt/keycloak/themes/ceffio`.

Two details matter:

- **ConfigMap keys cannot contain a slash.** Paths are flattened with a double
  underscore and `items[].path` rebuilds the tree on the volume. Without that, Keycloak
  finds every file at the theme root, looks for `login/theme.properties`, misses it, and
  renders the **default page with no error anywhere**.
- **Text goes in `data`, binary in `binaryData`.** A JPEG in `data` is refused by the API
  server with a message about invalid UTF-8 that names neither the file nor the reason.

A `ceffio.io/theme-checksum` annotation on the pod template is the restart mechanism:
in production Keycloak caches themes, so replacing the files changes nothing until the
process restarts. Kubernetes restarts the pod when the value changes, and only then.

## Changing the page

Settings → module `identity` → group `login_page`, or:

```bash
ceffio module config identity login_page theme=keycloak.v2
ceffio module config identity login_page theme=ceffio default_locale=fr
```

Changing **which** theme is used needs no restart: Keycloak resolves the realm's
`loginTheme` per request. Shipping a **new** theme restarts the pod, because the files
are cached at startup.

Going back to Keycloak's page is the fastest way to tell a theming problem from a
sign-in problem.

## Testing it locally

```bash
kc.sh start-dev            # with the theme copied into $KC_HOME/themes/ceffio
# then: http://localhost:8080/realms/ceffio/account
```

Set the realm's `loginTheme` to `ceffio` in the admin console. `start-dev` does **not**
cache themes, so an edit shows up on reload — which is convenient here and is exactly
why production behaves differently.

## Licence

Sora is under the **SIL Open Font License 1.1**. `OFL.txt` ships inside the theme, and
`THIRD_PARTY_LICENSES.md` names it: a theme is a redistributable artifact, so the
licence has to travel with it rather than be referenced from the repository root.