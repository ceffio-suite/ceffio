# Keycloak in production mode

Ceffio runs Keycloak with `kc.sh start`, not `start-dev`. This page records why,
what it changed, and what was measured when the switch was made.

## Why

Keycloak's own documentation forbids `start-dev` in production. It loosens
protections and **disables the caches, including the theme cache** — so an installed
login theme is silently not served, which is how a themed page can look applied
while users still see the default one.

Nothing fails loudly in that mode: pods are Ready, realms resolve, SSO signs users
in. What is lost is invisible, which is why `ceffio doctor` reports it as an error
rather than a warning.

## The options, and why each is there

| Variable | Value | Why |
|---|---|---|
| `KC_HTTP_ENABLED` | `true` | Traefik terminates TLS; without it, `start` refuses to come up without a certificate |
| `KC_PROXY_HEADERS` | `xforwarded` | The public scheme and host come from Traefik's headers; without it the issuer is built as `http://` and SSO redirects leave TLS |
| `KC_CACHE` | `local` | One replica, so a distributed Infinispan cache only waits for nodes that do not exist |
| `KC_HOSTNAME` | `https://keycloak.<domain>` | The v2 hostname system: a full URL carries both the name and the scheme |
| `KC_HOSTNAME_STRICT` | `false` | Left off until internal callers are tested with it on (see below) |

`KC_PROXY_HEADERS` moved from the ingress phase into the manifest: the pod was wrong
from its first second, and the ingress phase corrected it afterwards.

## `KC_HOSTNAME_URL` no longer exists

It belonged to the v1 hostname system and Keycloak 26 ignores it **silently** —
`kc.sh start --help` does not list it. `KC_HOSTNAME` now accepts a hostname or a
full URL, so `https://keycloak.example.org` carries both pieces. Setting only the
host made Keycloak announce `http://` URLs behind a TLS terminator.

`adoptKeycloakHost` sets it, with the current domain, and the manifest deliberately
does not hardcode it: a frozen value contradicts the ingress phase, which is how an
older installation ended up redirecting to a domain that no longer existed.

## The first start is long, and that is normal

`start` without `--optimized` rebuilds the server configuration at every boot,
because `KC_DB`, `KC_HEALTH_ENABLED` and `KC_METRICS_ENABLED` are build-time options.
A `startupProbe` on `/health/started` gives it **10 minutes** (10 s × 60).

The margin is wide on purpose: when it is too small the failure is not a slow start
but a loop that never converges — the liveness probe kills the pod mid-rebuild, it
starts over, and rebuilds for ever, without ever logging that the kill was the
cause.

An image built ahead (`kc.sh build` at image time, then `--optimized`) would remove
the phase. Out of scope here; recorded as the next improvement.

## The data survives the switch

`start-dev` defaults to an in-memory H2 database, so "we were in development mode"
naturally reads as "the realm might be in memory". It is not: `KC_DB=postgres` with a
JDBC URL to the Postgres service. No account, OIDC client or realm setting is lost,
and a test in `internal/identity` asserts it so the answer does not depend on
someone remembering.

## Measured on the live installation

| | |
|---|---|
| Mode | `Profile prod activated` (was `Profile dev activated`) |
| Startup | **4.9 s** after the first build |
| Restarts | 0 |
| Issuer | `https://keycloak.ceffio.org/realms/ceffio` |
| SSO, Nextcloud | redirects to Keycloak, `client_id=nextcloud`, realm `ceffio` |
| SSO, Stalwart | `ceffio mail sso` reports the authorization endpoint on the identity provider |
| SSO, console | responds 200; the administrator account still authenticates |

## Still open

- `KC_HOSTNAME_STRICT=true` — changes how internal callers (Nextcloud, Stalwart,
  the console) reach Keycloak. Needs a real test of its own.
- A pre-built image with `--optimized`, which removes the rebuild at every boot.
- The email theme and the account console theme are not covered.
