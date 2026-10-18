# Contributing to Ceffio

Ceffio is a sovereign collaborative suite: SSO, files, documents, mail and
video — deployed on Kubernetes with a single command. It ships real
infrastructure (Keycloak, Nextcloud, ONLYOFFICE, Janus, OpenBao); contributing
to it means respecting what makes it deployable.

## How we work: GitFlow

| Branch | Role | Protected |
|---|---|---|
| `main` | every commit is a releasable state | yes — PR + green CI required |
| `develop` | integration branch | yes — PR + green CI required |
| `feature/<name>` | one feature, merged into `develop` | no |
| `release/x.y.z` | stabilisation only, from `develop` | no |
| `hotfix/x.y.z` | production fix, from `main` | no |

### Daily flow

```bash
git checkout develop && git pull
git checkout -b feature/my-thing
# … commit, test locally …
git push origin feature/my-thing
# then open a Pull Request: feature/my-thing → develop
```

Merge conventions:

- PR title follows [Conventional Commits](https://www.conventionalcommits.org/):
  `fix(talk): announce the public address, not the private one` — the title
  becomes the commit message and feeds the release notes.
- One PR does one thing. A PR that "also" touches something else gets asked to
  split, not to be trusted.
- The CI must be green before review. Reviews are required (see branch
  protection) — a merge is two people agreeing, not one person being fast.

### Releasing

Releases are cut on `release/*` branches, tagged, and published by the
`release.yml` workflow — nothing is created by hand:

```bash
# 1. start the release from develop
git checkout develop && git pull
git checkout -b release/1.4.0
# only stabilisation commits here: fixes, docs, version bumps. No features.

# 2. tag it (this triggers the Release workflow)
git tag -a v1.4.0 -m "Ceffio 1.4.0"
git push origin release/1.4.0
git push origin v1.4.0

# 3. after the workflow publishes: merge back, both ways
git checkout main && git merge --no-ff release/1.4.0
git checkout develop && git merge --no-ff release/1.4.0
git branch -d release/1.4.0
```

The Release workflow refuses to publish unless the CI of the tagged commit is
green — it waits for it, checks it, and only then builds. It publishes:

- `ceffio-linux-amd64` and `ceffio-linux-arm64`, built from that exact commit;
- `checksums.txt` (SHA-256) next to them;
- release notes generated from the commit history since the previous tag.

Tags must be `vMAJOR.MINOR.PATCH`. Candidates use `v1.4.0-rc.1` and are marked
prerelease so they never become the "latest" users receive.

### Hotfixes

`main` holds the released state; a production fix branches from it and merges
back into both `main` and `develop`:

```bash
git checkout main && git pull
git checkout -b hotfix/1.4.1
# … fix …
git tag -a v1.4.1 -m "Ceffio 1.4.1 (hotfix)"
git push origin hotfix/1.4.1 && git push origin v1.4.1
git checkout main && git merge --no-ff hotfix/1.4.1
git checkout develop && git merge --no-ff hotfix/1.4.1
```

## Before submitting

```bash
make build   # go build ./cmd/ceffio
make vet     # static analysis
make test    # tests (CI also runs them with -race)
gofmt -l .   # must print nothing
```

The CI is the same ladder, plus the real binary build for amd64 and arm64.
A failure locally costs you a round-trip; a failure on `main` costs everyone
the release channel.

## The rules this codebase follows

They are not style preferences — each one exists because breaking it produced a
real failure. New code that breaks one must justify it in the PR.

1. **A version, once released, never changes.** If a release was cut from the
   wrong commit, the answer is a new version, not a force-push. The binary you
   are running is the version it announces.

2. **Every image is pinned.** `latest` is never accepted as a tag in
   `internal/version`: an image with no version cannot be compared, upgraded
   reproducibly, or audited after an incident. A test enforces this.

3. **Secrets live in OpenBao, nowhere else.** No application reads a Kubernetes
   Secret, no secret is written in a versioned file, no value is ever printed —
   a length or a fingerprint is not a secret. If you need a secret to debug,
   you are reading the wrong thing.

4. **Infrastructure identifiers never enter the repository.** Real IPs, real
   domains, account names and internal project names are reconnaissance: a
   public repo is a map of the deployment for anyone looking. Use
   `example.com`, `<cluster-ip>`, placeholders — as this repo already does.

5. **A control that cannot fail is not a control.** When you add a check, prove
   it rejects something. Many bugs here survived because a script compared an
   empty value to an empty value and declared "coherent".

6. **Read after writing.** Every operation on live systems ends by reading the
   exact target back. A successful exit code means the command ran, not that
   the task happened.

7. **Comments explain WHY, and keep their evidence.** "Measured: UDP
   reflexive addr …", "happened twice while writing this file" — the sentence
   that looks like trivia is usually the one that stops the next person
   repeating the mistake. Write code and comments in English; keep quoted
   outputs from other tools verbatim, they are evidence.

8. **The idempotency promise**: `ceffio install` run twice must be a no-op or
   an update, never a destruction. Every new deployment step is written to be
   re-runnable, and said so in its comment.

9. **A new optional feature is a module — nothing else.** It ships as a Go
   package implementing `module.Module` and one blank import in
   `internal/modules/all.go`; the installer, the CLI and the console read the
   registry and must not change. No feature-specific route, no
   feature-specific console section, no hardcoded feature list: the
   hand-written HaRP and transcription endpoints were folded into the generic
   module API precisely because each new feature duplicated them. See
   [`docs/adding-a-module.md`](docs/adding-a-module.md).

## Reporting an issue

Include, in this order: what you ran, what you expected, what happened (exact
output, not a paraphrase), and what you already checked. `ceffio doctor`
exists to answer the last point — its output belongs in the report.

Never paste real secrets, real domains or real IP addresses into an issue:
redact them. A public issue is indexed by search engines within hours.

## Licensing

By contributing you accept that your contribution is licensed under the
GNU Affero General Public License v3.0 or later, like the whole project
(see `LICENSE`). Copyright © MANDEM.
