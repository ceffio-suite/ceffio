# Security policy

Ceffio installs the software that holds an organisation's files, mail, calls and
identities. A vulnerability in Ceffio is a vulnerability in all of that, so
reports are welcome, handled privately, and credited.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Use one of these private channels:

1. **GitHub private vulnerability reporting** (preferred):
   [Report a vulnerability](https://github.com/ceffio-suite/ceffio/security/advisories/new).
   The report stays visible only to you and the maintainers, and the fix can be
   prepared in a private fork attached to the advisory.
2. **E-mail**: `security@mandem-it.com`.

Please include, as far as you can:

- the affected version (`ceffio version`) or commit;
- the component (installer, admin console, a module, the recording relay, the
  capture image, an image published under `ghcr.io/ceffio-suite/`…);
- the steps to reproduce, and what an attacker gains;
- whether you believe it is **already exploited** in the wild — this changes
  our legal deadlines (see below);
- how you would like to be credited, or if you prefer not to be.

You may write in English or in French.

## What happens next

| Step | Our target |
|---|---|
| Acknowledgement of your report | 3 working days |
| First assessment (confirmed or not, severity) | 10 working days |
| Fix for a critical or high severity issue | 30 days |
| Fix for a medium or low severity issue | next planned release |
| Public disclosure | when a fixed release is available, or 90 days after the report, whichever comes first — unless we agree otherwise with you |

We keep you informed at each step. Severity is assessed with CVSS v4.0.

When the fix is released we publish a
[GitHub Security Advisory](https://github.com/ceffio-suite/ceffio/security/advisories),
request a CVE identifier for it, and name the release that fixes it in the
release notes. Reporters are credited in the advisory unless they ask not to be.

## Supported versions

Ceffio is before 1.0. Until then, **only the latest release receives security
fixes**: the fix ships as a new patch release (for example `v0.10.2`), and
upgrading is the remedy.

| Version | Security fixes |
|---|---|
| latest `v0.x` release | ✅ |
| any older release | ❌ — upgrade |

This table will change at 1.0, when a support period will be stated for each
version.

## Scope

**In scope** — the code in this organisation's repositories:

- the `ceffio` binary: installer, CLI, admin console, modules, recording relay;
- the images we build and publish under `ghcr.io/ceffio-suite/`
  (`ceffio`, `ceffio-capture`, `janus-gateway`, `acme-dns-webhook`);
- the configuration Ceffio generates for the components it deploys: an
  exposure, a permission, a default or a secret handling that makes a
  component vulnerable **because of how Ceffio installs it**.

**Upstream components** (Nextcloud, Talk, Keycloak, ONLYOFFICE, Stalwart,
OpenBao, PostgreSQL, Valkey, Longhorn, K3s, Traefik, cert-manager…): please
report a flaw in their own code to their own project first. Tell us as well if
it affects a Ceffio installation: we will update the pinned version
(`internal/version`) and say so in a release.

**Out of scope**: findings that need an attacker who is already an
administrator of the host or of the cluster; denial of service by volume;
reports produced by a scanner with no demonstrated impact; social engineering.

## Testing safely

Test only on an installation you own. Do not access, modify or keep data that
is not yours, do not degrade a service used by others, and stop as soon as you
have shown the problem. Research done in good faith within these rules will not
lead to any complaint or legal action from MANDEM.

## EU Cyber Resilience Act

Ceffio is developed by **MANDEM** (France). Under Regulation (EU) 2024/2847
(Cyber Resilience Act), when a vulnerability in Ceffio is **actively
exploited**, or a severe incident affects its security, MANDEM notifies it
through the ENISA Single Reporting Platform, to CERT-FR as the coordinating
CSIRT:

- an early warning within **24 hours** of becoming aware of it;
- a notification within **72 hours**;
- a final report within **14 days** after a fix is available (one month for a
  severe incident).

Users are informed of such a vulnerability, and of the measures to take,
through a Security Advisory and the release notes.

The software bill of materials of each release is described in
[`docs/sbom.md`](docs/sbom.md).

## Contact

Security contact: `security@mandem-it.com` — MANDEM, France.
