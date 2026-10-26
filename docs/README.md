# Documentation

One subject per file. Everything here is written against the code, and a test fails when
the two drift apart.

## Start here

| Document | What it answers |
|---|---|
| [../README.md](../README.md) | What Ceffio is, what you need, how to install it, and where to sign in |
| [architecture.md](architecture.md) | What runs where, and why the layers are separated that way |
| [adding-a-module.md](adding-a-module.md) | How to add a layer or an optional module to the registry |

## Operating it

| Document | What it answers |
|---|---|
| [secrets.md](secrets.md) | The vault, the injector, and the four Secrets that exist anyway |
| [tls.md](tls.md) | HTTP-01 or DNS-01, the providers, and when a renewal really happens |
| [media-and-firewall.md](media-and-firewall.md) | Talk's ports, the firewall traps, and the one third-party lookup |
| [sign-in-page.md](sign-in-page.md) | The login theme, and how to go back to Keycloak's |
| [console-image.md](console-image.md) | How the console is built, published, and what it may do in the cluster |
| [keycloak-production.md](keycloak-production.md) | Keycloak in production mode: options, hostname, and what was measured |
| [cout-hebergement.md](cout-hebergement.md) | What the machine costs, month by month |

## The console

| Document | What it answers |
|---|---|
| [../internal/console/README.md](../internal/console/README.md) | The tabs, the API routes, the authentication |

## History

Kept for context. **They do not describe the current code.**

| Document | What it was |
|---|---|
| [history/plan-talk-hpb.md](history/plan-talk-hpb.md) | The working note for moving from Matrix/Element to Talk + HPB |
| [plan-capture.md](plan-capture.md) | Feasibility plan: per-participant capture, the `ceffio-capture` image, and its deployment alongside `recording` |
| [history/sso-office-ingress-fixes.md](history/sso-office-ingress-fixes.md) | The note written while fixing the office SSO behind the ingress |
| [history/consoles-archive.md](history/consoles-archive.md) | Why the console image moved out of its own repository |

## The rule for this directory

A document that is not linked from here is a document nobody reads. If you add one, add a
row. `docs_test.go` checks that every relative link in the documentation points at a file
that exists — including the ones in this index.