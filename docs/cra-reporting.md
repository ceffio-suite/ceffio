# Reporting under the Cyber Resilience Act

Ceffio is developed by **MANDEM** (France). Regulation (EU) 2024/2847 gives a
manufacturer deadlines it cannot improvise: a vulnerability that is **actively
exploited**, or a severe incident, has to be reported through a single EU
channel within hours. This page is the runbook for that day — who does what, in
what order, with what already in hand.

## The two channels, which do not replace each other

| Channel | For | Where |
|---|---|---|
| `security@mandem-it.com` | anyone reporting a vulnerability in Ceffio | `SECURITY.md` |
| **ENISA Single Reporting Platform** | the regulatory notification, to CERT-FR | <https://portal.cra-srp.enisa.europa.eu> |

A report received on the mailbox may become a notification on the platform; the
reverse is not true, and the platform is not a support channel.

**The mailbox is hosted outside any Ceffio installation** — verified by sending
and receiving a message. That is not an accident worth losing: an installation
that is down, or compromised, must not be able to silence the channel through
which its own vulnerability is reported. A security contact hosted on the
product is a contact that fails exactly when it is needed.

**The alias is forwarded to a mailbox that is read every day**, so the message
does not wait in an account nobody opens.

**The clock starts when someone reads it**, not when the message arrives. The
24-hour early warning is counted from the moment MANDEM becomes aware of an
actively exploited vulnerability, and a mailbox nobody watches makes that moment
the next working day. Whoever is on call has to read `security@` at least once a
day; a filter that forwards it to a phone is the difference between a deadline
met and a deadline missed.

## The deadlines

From the moment MANDEM becomes aware of an actively exploited vulnerability or
a severe incident:

| When | What |
|---|---|
| **24 hours** | early warning — the exploit may be in the wild, a fix is not required yet |
| **72 hours** | notification — severity, affected versions, measures taken by users |
| **14 days** after a fix | final report (one month for a severe incident) |

Users hear about it through a Security Advisory and the release notes.

## What has to exist before the day

1. **An EU Login account with MFA enabled** — the platform authenticates
   through EU Login, and refuses a session without a second factor:
   <https://ecas.ec.europa.eu/cas/login> → *Configure my account* → add a
   verification method, then tick *Always require multi-factor authentication*.
   **Declare two methods**, not one: losing the phone must not lock the only
   person able to notify.
2. **The SRP account** — a *Primary Assigned Representative* for MANDEM, created
   on the platform: choose the AR role, then the CSIRT designated as
   coordinator, **CERT-FR** (<https://www.cert.ssi.gouv.fr/contact-us/>), accept
   the legal agreement, confirm the pre-filled identity, enter the manufacturer.
   The association is validated by CERT-FR afterwards, in parallel — it does not
   block a notification.
3. **A second person** — a *Secondary AR*, invited by the Primary once it is
   verified. The invitation link lives **7 days**.

ENISA's own advice: register **when a notification is needed**, not
pre-emptively. The account is not a subscription.

## Where the account stands

| | |
|---|---|
| EU Login | created, for the AR |
| SRP account | **Active**, role *AR Primary User* |
| Manufacturer | MANDEM |
| Coordinating CSIRT | CSIRT France — CERT-FR (ANSSI) |
| Association AR ↔ manufacturer | validated by CERT-FR after registration, **in parallel**; it does not block a notification |
| Secondary AR | **to be invited** — the invitation lives 7 days |

The platform is at <https://portal.cra-srp.enisa.europa.eu>; its state is
published on the [SRP status page](https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp/cra-srp-status)
(a notification due while the platform is down has its own procedure, FAQ
question 25).

## The public contact file

`https://ceffio.org/.well-known/security.txt` (RFC 9116) points a scanner or a
researcher at the mailbox, with `Expires`, the canonical URL and the policy.

**It is served by the project's own installation only.** The console answers 404
on every other domain and creates no route for it — a customer runs their own
service, their security contact is theirs, and our address on their domain would
send reports to the wrong party. A test enforces both halves: the content on
`ceffio.org`, the 404 elsewhere, and an `Expires` that must stay at least 300
days ahead or the build fails.

## What this project gives the person who has to notify

The notification asks what runs, where, and since when. That is exactly what the
rest of this documentation produces:

- `ceffio sbom` — the components of an installation, **with their digests**;
- the SBOM of each release, covered by `checksums.txt` — the exact bytes shipped;
- the Grype scan of each release — what was known at publication time;
- [`SECURITY.md`](../SECURITY.md) — the internal process, and the advisory it
  produces.

A notification written from those documents says "version X, digest Y,
published on Z" instead of "around version X, I think". That difference is the
whole point of the SBOM chapter.
