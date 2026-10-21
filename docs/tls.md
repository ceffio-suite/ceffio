# TLS certificates

Ceffio obtains its certificates from Let's Encrypt through cert-manager. How it proves
ownership of a domain is a **setting**, not a build-time choice: HTTP-01 and DNS-01 are
both supported, and switching is a configuration change.

## The two challenges

| | HTTP-01 | DNS-01 |
|---|---|---|
| How it proves the domain | serves a file on port 80 | writes a TXT record |
| Needs a public port 80 | yes | no |
| Works for a wildcard (`*.domain`) | **no** | yes |
| Needs a DNS provider credential | no | yes |
| Works behind a closed firewall | no | yes |

**The default is HTTP-01**: it needs nothing but an open port 80, and most installations
never need more. You switch to DNS-01 when you want a wildcard, when port 80 cannot be
reached, or when the certificate must be issued before the service is live.

## Choosing the challenge

A setting, in **Settings → module `ingress` → group `tls`**, or from the command line:

```bash
ceffio module config ingress tls challenge=dns01 dns_provider=cloudflare dns_zone=example.org
ceffio module config ingress tls cred_cloudflare_api_token=<token>
```

The **provider is a dropdown**, built from the table in `internal/acme`. Choosing one shows
that provider's credential fields and hides every other provider's — which is the whole
point of the chained conditions in the settings contract. Before that, all 43 credential
fields were drawn at once and the operator had to find their own two among them.

**Only the chosen provider's credentials are stored.** Switching provider **replaces** the
vault entry: a token typed for Cloudflare does not stay behind after a move to OVH, where
it would be read by a solver pointed at a different host.

## The providers

Nineteen hosts have a credential table, and each carries a one-sentence help saying where
to create the credential and with which rights.

`acme-dns`, `Azure DNS`, `Cloudflare`, `ClouDNS`, `deSEC`, `DigitalOcean`, `Gandi`,
`GoDaddy`, `Google Cloud DNS`, `Hetzner`, `Infomaniak`, `IONOS`, `Namecheap`, `OVH`,
`Porkbun`, `PowerDNS`, `RFC 2136` (dynamic DNS), `Route 53`, `Scaleway`.

**Adding a host is a line in a table**, not a change to the Go: `internal/acme/identifiants.go`
declares the fields the solver reads, `internal/acme/providers.go` declares the label and
the help. A host absent from both still works — its credentials are stored as free-form
keys — but it appears in the dropdown with a capitalised name and no help.

## Where the credential lives

The token is stored in **OpenBao**, at `kv/data/ceffio/tls/dns-provider`, with the
provider's name in the same entry. It reaches cert-manager through a Kubernetes Secret,
`cert-manager/ceffio-acme-dns`, because **cert-manager resolves the ClusterIssuer's
`secretRef` itself** and cannot reach OpenBao. That Secret is one of the four documented
exceptions in [secrets.md](secrets.md).

## The wildcard

A wildcard certificate covers `*.example.org` **and** `example.org`. Every host on that
domain is then served by the same certificate, and **adding a host issues nothing new**:
`longhorn.example.org` works the moment its Ingress exists.

That is why the console's TLS page shows the **hosts served** and the certificate that
covers each, rather than only listing certificates: a host that reuses the wildcard has no
certificate of its own and would otherwise appear nowhere.

## Renewal, which is the number that matters

Let's Encrypt certificates last 90 days, and cert-manager renews at about two thirds of
that. The console shows both:

- **Expires** — the date the certificate stops working;
- **Renews** — the date cert-manager **plans to act**.

The second is the one to watch. "88 days left" is reassuring and says nothing about the
automation: a certificate that will expire and never renew looks exactly like a healthy one
until the day it stops. A certificate with no renewal date reads **not scheduled**, because
cert-manager always plans one for a certificate it manages.

## Reading the state, and what the console can and cannot see

The console's TLS page reports the **resolved configuration** of the pod — the challenge,
the provider, the zone — and whether the credential is in place.

It answers that last question from the **certificates themselves**, and the reason is worth
knowing: the console is forbidden to read Secrets in `cert-manager`, and it cannot read the
ClusterIssuer either (cluster-scoped, and its ClusterRole does not carry `cert-manager.io`).
A Certificate that is Ready **proves** the solver could sign — a DNS-01 issuance cannot
succeed without a working credential. So the platform answers on the evidence of what it has
already done.

The route `/api/certificates` is **read-only**. The `POST` it used to carry was removed: it
wrote the same vault entry the ingress module's settings write, and two writers for one
entry is how a value drifts.

## Two pitfalls worth knowing before you debug

1. **`KC_HOSTNAME_URL` does not exist in Keycloak 26.** If a sign-in redirect goes to
   `http://` behind a TLS terminator, the cause is `KC_PROXY_HEADERS`, not a hostname
   variable. See [keycloak-production.md](keycloak-production.md).
2. **A host behind the wildcard has no certificate of its own.** Looking for it in
   `kubectl get certificates` finds nothing, and that is not a fault.

## See also

- [secrets.md](secrets.md) — the vault, and the four Secret exceptions
- [keycloak-production.md](keycloak-production.md) — the identity layer's own hostname and proxy
- [architecture.md](architecture.md) — which layer owns the Ingress objects