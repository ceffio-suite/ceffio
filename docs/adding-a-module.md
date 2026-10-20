# Adding a module

How to add a feature to Ceffio without touching the installer, the CLI or the
console. A feature is one Go package implementing `module.Module`; everything
the operator sees — install flags, CLI commands, console page, status, doctor,
RBAC — is generated from the module registry.

The claim is not aspirational: the demonstration module
(`internal/modules/demo`) was added in one commit (`56e9b7b`) that touched no
installer, CLI or console file — its own package, one tagged blank-import
line, and one pre-existing test corrected because it froze the registry at
exactly thirteen modules — and demo appears in `install --with`, `ceffio
module list`, `GET /api/modules`, the status catalog and the generated RBAC
grant anyway. Its integration test (`go test -tags demo ./...`) builds the
real CLI and proves each surface.

This guide walks through a real module, `recording`
([`internal/modules/recording/module.go`](../internal/modules/recording/module.go)),
which installs the Talk call-recording server. Recording is interesting
because its uninstall did not exist before modularisation and had to be
written — a module is not just "install code with extra steps"; it owns its
full lifecycle.

## 1. What a module is

The contract lives in
[`internal/module/module.go`](../internal/module/module.go). The package
imports no other internal package, so a module can never create an import
cycle with the frontends that consume it:

```go
type Module interface {
	Info() Info
	Install(ctx context.Context, env Env) error
	State(ctx context.Context, env Env) State
	Uninstall(ctx context.Context, env Env) error
}
```

Two of the four methods carry hard contracts, stated in the interface itself:

- **`Install` MUST be idempotent.** It is called by the CLI, by the console,
  and again after any interruption — re-running it on an installed module
  must be a no-op or an update, never a corruption. This is the same promise
  `ceffio install` makes (CONTRIBUTING.md, rule 8), now per feature.
- **`Uninstall` MUST remove workloads, services and volumes it created.** A
  leftover PVC keeps consuming disk on a machine that believes the module is
  gone; a leftover Service keeps an exposure open. Uninstall must also be
  re-runnable: a console retry after a partial removal must not error on the
  object it already deleted (see how `recording.Remove` treats every deletion
  as best-effort, and how the demo module returns `nil` on `IsNotFound`).

`Env` carries what a module needs to act: the base `Domain`, a
`kubernetes.Interface` (`Kube`), and an `io.Writer` (`Out`) that is stdout for
the CLI and the operation journal for the console.

## 2. Kind: Core or Optional

```go
const (
	Core     Kind = iota // always installed, by the install sequence
	Optional             // installed on request, from the CLI or the console
)
```

**Core** is reserved for the ten layers that *are* the product (platform,
data, vault, identity, files, office, talk, ingress, mail, console). The
install sequence deploys them; their `Uninstall` deliberately *refuses* —
`ceffio module remove` rejects a Core module and directs the operator to
`ceffio uninstall`, and a test
(`TestLesDixCouchesDuSocleSontDesModulesCore`) enforces the refusal. A Core
module wraps an existing layer so that status and doctor can read it from the
registry; it does not move the install sequence into the registry.

**Optional** is everything else: a feature an operator chooses. `ceffio
install` picks Optional modules up through `--with`/`--without`, and `ceffio
module install/remove` manages them afterwards. If you are adding a new
feature, you are writing an Optional module. Adding a Core layer is an
architectural decision, not a contribution pattern.

## 3. The Info struct, field by field

`Info()` describes the module statically — everything the frontends must know
*without* installing it. This is what `recording` returns (permissions
abridged, full text in the source):

```go
func (m *recordingModule) Info() module.Info {
	return module.Info{
		ID:          "recording",
		Title:       "Recording",
		Description: "Records Talk calls: a hidden participant joins the room, renders it and uploads the result to Nextcloud.",
		Kind:        module.Optional,
		Default:     true,
		Namespaces:  []string{nsVideo}, // "ceffio-video"

		Permissions: []module.Permission{
			{Namespace: nsVideo, Rules: []rbacv1.PolicyRule{ /* … */ }},
			{Namespace: nsNextcloud, Rules: []rbacv1.PolicyRule{ /* … */ }},
		},
	}
}
```

- **`ID`** — stable, kebab-case (`^[a-z0-9]+(-[a-z0-9]+)*$`). It is the
  registry key, appears in Kubernetes resource names and in console URLs, so
  `Register` *panics at startup* on an empty, malformed or duplicate ID. A
  loud failure at init beats a missing module discovered hours later.

- **`Title`, `Description`** — shown in the console's Modules page and in
  `ceffio module status`. One or two sentences; the operator reads them
  before deciding to install.

- **`Kind`** — see above.

- **`Default`** — does `ceffio install` deploy the module without an explicit
  request? Recording is `Default: true`: every standard installation gets it,
  and `--without recording` sets it aside. Live transcription is
  `Default: false` — ~9 GB disk and ~16 GB RAM, installed only via
  `--with live-transcription` or the console. For a Core module `Default` is
  always `true` (the sequence installs it by definition); the field exists on
  Core too so frontends that filter on `Default` get the same answer as
  frontends that filter on `Kind`. Flipping a module's `Default` silently
  changes what every installation receives — which is why
  `recording/module_test.go` pins the value.

- **`Requires`** — module IDs that must be installed first. Declare the
  dependency; do not order anything yourself. The registry does the rest:
  - `module.All()` returns modules in **topological order** (deterministic,
    ties broken alphabetically) and **panics** on an unknown dependency or a
    cycle, naming it (`"a -> b -> a"`);
  - `ceffio install` expands the closure transitively and *says so*
    (`∙ live-transcription requires exapps-daemon: adding it`);
  - `ceffio module install` installs missing dependencies before the target;
  - `ceffio module remove` **refuses** to remove a module that another
    *installed* module requires — removing a dependency from under a running
    module would leave it broken with nothing in the logs pointing at the
    cause;
  - `module.Blocked()` queries each dependency's observed `State` and returns
    a full sentence ("required module \"exapps-daemon\" is not installed
    (status: absent)") that feeds `State.Blocked` — the answer to "why is the
    install button greyed out?" without any frontend recomputing the graph.

  Live transcription is the worked example: it is HaRP that creates the
  ExApp's workload, so `Requires: []string{"exapps-daemon"}` is the whole
  wiring — order, expansion, removal guard and greyed-out button all derive
  from that one line.

- **`Namespaces`** — where the module's pods live. Status, doctor and the
  console read layers through this list (see §6): a namespace no module
  declares is invisible. Recording declares `ceffio-video`, shared with the
  Core `talk` module — several modules may share a namespace; the layer is
  named after the Core module that claims it first.

- **`Services`** — public exposures, for the status page: `Sub` (the
  subdomain), `Name`, `Role`, `SSO`, `Technical`, `PodPrefixes`. Recording
  declares none: the recorder has no public endpoint, Talk calls it inside
  the cluster. A module with a public URL declares it here and the status
  catalog (`/api/status`) serves it with no change in
  `internal/console/status.go`.

- **`Resources`** — a human string, e.g. `"~9 GB disk, ~16 GB RAM"`, shown by
  `ceffio module list`, `install --help` and the console before the operator
  commits. Empty when negligible — recording leaves it empty on purpose: the
  workload is limited to 2 GiB of RAM and downloads no model, negligible next
  to the neighbouring Janus/signaling components. "Negligible" is a decision
  you document in a comment, not an omission.

- **`Warning`** — the sentence the operator must read before acting. The
  console shows it as an inline confirmation before any action (install or
  uninstall); `ceffio module remove` prints `⚠ <warning>` and still asks for
  confirmation. Use it for irreversible or surprising behaviour, verbatim
  from what the operator needs to know, e.g. live transcription's "Its
  settings cannot be changed once installed — the app has to be removed and
  installed again."

- **`Permissions`** — the RBAC rights the **console** needs to install and
  uninstall the module. The CLI runs as admin and needs nothing declared; the
  console runs under the `ceffio-admin` ServiceAccount with minimal rights.
  `console.AdminRights()` is the **sum** of every module's `Permissions`,
  merged on `(namespace, apiGroup, resource, verb)` tuples — so a new module
  widens the console's grant by declaring it, with no change in
  `internal/console/deploy.go`. The sum is pinned by a non-regression test
  (`internal/console/rbac_nonregression_test.go`) that compares it, tuple by
  tuple *in both directions*, against a frozen copy of the former
  hand-written ClusterRole: a rule lost fails as a regression, a rule added
  fails as "EXTRA privilege (widened grant, nobody decided it)". Declare
  exactly what your Install/State/Uninstall touch — recording lists the
  ServiceAccount, Deployment and Service it manages in `ceffio-video`, plus
  `pods` and `pods/exec` in `ceffio-files` because its Talk wiring runs `occ`
  in the Nextcloud pod — and expect the non-regression test to make you
  justify anything broader. Core-layer modules reuse
  `socle.StandardPermission(namespace)`; an Optional module writes its own
  subset, because narrowing is a privilege decision made on purpose.

## 4. Install, State, Uninstall — the recording example

Recording is a **wrapper, not a rewrite**: the install already existed in
`internal/recording` (secrets, Deployment/Service, Talk wiring), proven in
production. The module plugs it into the contract:

```go
// Install delegates to recording.Deploy, unchanged.
func (m *recordingModule) Install(ctx context.Context, env module.Env) error {
	return recording.Deploy(ctx, env.Domain)
}
```

`recording.Deploy` is idempotent by construction: it reads or creates the
vault secrets, `kubectl apply`s the manifests, waits for readiness, and
re-writes the Talk setting. Re-running it converges.

**The only feature the modularisation batch ADDED was the uninstall** — it
existed nowhere. `recording.Remove` is the exact mirror of `Deploy`: it
clears the Talk setting via `occ`, then deletes the Deployment, the Service
and the ServiceAccount, each deletion best-effort (an already-absent resource
is the normal case on a second removal). Two things it deliberately does
*not* remove, both documented in the code: the signaling configuration (the
signaling has no `[recording]` block — Talk calls the recorder directly over
HTTP, verified against the signaling sources) and the vault entry (regenerating
it at the next Deploy is pointless, and its presence costs nothing). When you
write an Uninstall, "everything it created" means the resources whose absence
would cost disk, exposure or lies — not every byte the install ever wrote.

**`State` reads the cluster; it never guesses.** Recording's state is two
reads: is the Deployment ready, and does Talk know the recorder (`occ
config:app:get spreed recording_servers`)? The four combinations map onto the
statuses, and the two half-states get a `Detail` that names the actual
symptom:

```go
switch {
case pret && branche:
	return module.State{Status: module.Installed}
case pret && !branche:
	return module.State{
		Status: module.Degraded,
		Detail: "Le serveur tourne mais n'est pas declare dans Talk : le bouton d'enregistrement resterait grise.",
	}
case !pret && branche:
	return module.State{
		Status: module.Degraded,
		Detail: "Declare dans Talk, mais le pod du serveur d'enregistrement est absent.",
	}
default:
	return module.State{Status: module.Absent}
}
```

Two rules every State follows:

1. **`Degraded` exists precisely for half-installed modules.** A recorder
   that runs but that Talk does not know leaves the recording button greyed
   out — the state must be able to *name* that, not round it to
   installed/absent.
2. **Failure to look is `Unknown`, never `Absent`.** No Kubernetes client,
   unreachable API, failed exec: `Unknown` with a `Detail`. Absence is an
   observed fact, not a default when nobody looked — offering "install" on
   top of a module that may already be running is worse than saying we do not
   know. (`TestEtatSansClientDitInconnu` enforces this on the Core modules;
   the demo module's tests enforce it on itself.)

A failed read must also never conclude the positive case: recording leaves
`branche` at `false` when the exec fails, exactly like the deployer module
leaves `enregistre` at `false`.

If your module depends on others, start `State` with the registry's verdict:

```go
etat := module.State{Blocked: module.Blocked(ctx, env, m)}
```

— as `live-transcription` does, so the console greys out its install button
when HaRP is missing, without the console knowing what HaRP is.

## 5. Registering: `init()` and one line in `all.go`

The module registers itself from its own package:

```go
type recordingModule struct{}

func init() { module.Register(&recordingModule{}) }
```

But Go only runs the `init()` of packages the binary actually imports — a
module nobody imports never registers, and the omission is **completely
silent**: no error, just a module that cannot be found. So the module must be
blank-imported in [`internal/modules/all.go`](../internal/modules/all.go),
the single aggregation point both frontends import:

```go
import (
	// …
	_ "github.com/ceffio-suite/ceffio/internal/modules/recording"
	// …
)
```

Forgetting the line is a real failure mode, so a guardrail refuses it:
`TestToutModuleEstImporteDansAllGo` (`internal/modules/all_test.go`) walks
every `.go` file of the repository with `go/parser` (an AST walk, not a grep,
so comments and aliased imports cannot fool it), collects every package that
calls `module.Register`, and fails `make test` if one of them is missing from
`all.go`: *"its init() would never run"*. That test is the reason step 5 is
two lines and not a debugging session.

That is the entire wiring. There is no installer change, no CLI change, no
console change — see §6 for what those two lines buy.

## 6. What registration gives you for free

Every surface below reads `module.All()` (or its projections). None of them
names a single module. The demo module's integration test asserts most of
them (items 2–5 and 7) against a real compiled binary; the references here
are to the code that does it.

1. **`ceffio install --with / --without`.** `selectedOptionalModules`
   (`cmd/ceffio/install.go`) resolves the flags against the registry:
   unknown IDs are an error before anything is provisioned, `--with`/
   `--without` on the same module is refused, dependencies are expanded
   transitively (announced as they are added), and the result is installed in
   registry (topological) order by `installerModulesOptionnels`, which calls
   your `Install` through the contract.

2. **`ceffio install --help`.** `optionalModulesHelp` walks the registry and
   lists every Optional module with its `Resources`, its `Requires` and its
   default status — the flag documentation can never drift from what the
   binary installs.

3. **`ceffio module list|install|remove|status`** (`cmd/ceffio/module.go`).
   `list` prints ID, kind, observed state and resources for every module.
   `install <id>` plans the dependency closure, checks `module.Blocked`,
   skips what is already installed. `remove <id>` refuses Core modules,
   refuses when an installed module requires it, prints your `Warning`, asks
   for confirmation ("including the volumes it created"), then calls your
   `Uninstall`. `status <id>` prints everything, including `Detail` and
   `Blocked`.

4. **The console's Modules page and API.** `GET /api/modules` serves the
   registry `Info` (minus `Permissions`, which are an installer concern, not
   operator-facing display) plus the observed state; `POST /api/modules/{id}`
   runs your `Install`/`Uninstall` asynchronously (202 + operation journal,
   because a synchronous request is what a proxy cuts); the page generates a
   card per module from that JSON and polls every 3 s while an operation
   runs. `internal/console/modules.go` and `web/index.html` contain no
   feature list — the former feature-specific endpoints (`/api/exapps`,
   `/api/transcription`) survive only as aliases that delegate to the generic
   module handler.

5. **Status.** The layer catalog is registry-derived twice over:
   `registryNamespaces` (`internal/console/status.go`) feeds `/api/status`
   with every namespace the registry declares, and `registryLayers`
   (`cmd/ceffio/module.go`) feeds `ceffio status` with the same walk. The
   hand-written table these replaced knew seven namespaces and was silently
   blind to mail, vault and exapps — a broken mail server was invisible to
   `ceffio status`. Declaring your `Namespaces` is what keeps the next module
   from reproducing that hole.

6. **Doctor.** `ceffio doctor` diagnoses the registry-derived layers
   (`useRegistryLayers`), and calibrates severity from `Kind` through
   `namespaceOnlyOptional`: a missing pod in a namespace only Optional
   modules claim is a warning (the operator may never have asked for the
   feature); anywhere else it is critical.

7. **Console RBAC.** `console.AdminRights()` sums every module's declared
   `Permissions` into the namespace-scoped Roles the installer applies
   (`AdminRolesManifest`), tuple-merged and deterministic. Your declaration
   is the console's grant — no `deploy.go` edit, and the non-regression test
   is the audit trail.

If you find yourself editing any of those files to make your module appear
somewhere, stop: the registry projection is broken or you are adding a
feature-specific surface, and both are bugs. The CONTRIBUTING.md rule is
explicit — no new route, no feature-specific console section.

## 7. Tests expected of a module

**Always: `Info` validity** (`recording/module_test.go` is the model): ID
non-empty, kebab-case, and equal to the planned name; Title and Description
non-empty; Namespaces non-empty and real; `Kind` and `Default` pinned —
flipping either silently changes what every installation receives, so the
test says so. If the module has dependencies, assert `Requires` contains them
explicitly (`transcription/module_test.go`: without the `exapps-daemon`
entry, the app installs and never activates, with no error pointing at the
missing deployer).

**For a module that installs resources itself** (rather than delegating to a
pre-existing installer): prove the contract with
`k8s.io/client-go/kubernetes/fake`, no cluster needed. `demo/module_test.go`
is the reference:

- `TestInstallCreePuisMetAJour`: first `Install` creates, a simulated drift
  is reconciled, second `Install` must not fail `AlreadyExists` — the
  idempotency promise, observed;
- `TestEtatSuitLeConfigMap`: `State` is `Absent` before, `Installed` after,
  and `Unknown` (never `Absent`) without a client;
- `TestUninstallSupprimeEtEstRejouable`: removal works, and a second
  `Uninstall` is a no-op, not an error;
- `TestInstallSansClientRefuse`: without a client, `Install` and `Uninstall`
  fail loudly instead of pretending to succeed.

A wrapper module (recording, exapps-daemon, live-transcription) tests its
`Info` and any logic that is its own; the delegated installer keeps its own
tests where it lives.

Then run the whole ladder: `gofmt -l .` (must print nothing), `go build
./...`, `go vet ./...`, `make test`, and `go test -tags demo ./...` (which
also runs the demo integration test — it compiles real binaries and takes a
few minutes on a cold cache).

## 8. The demonstration module

`internal/modules/demo` is the executable proof of this document's premise.
Every file carries `//go:build demo`, so a production build does not even see
the directory; the wiring is one tagged blank import in
`internal/modules/all_demo.go` (a second file, because build constraints
apply per file and `all.go` must stay untagged). Under the tag:

```bash
go test -tags demo ./...          # unit tests + the integration proof
go build -tags demo -o /tmp/ceffio ./cmd/ceffio
/tmp/ceffio module list           # demo appears, kind "optional"
/tmp/ceffio install --help        # demo appears under --with
```

`TestDemoModuleEstBranchePartout` spawns the real console and asserts, against
a real tagged binary, that demo reaches the install help, `ceffio module
list`, `GET /api/modules`, the `/api/status` namespace catalog and the
`AdminRights` sum (§6 items 2–5 and 7) from the registry alone;
`TestDemoAbsentDuBinaireDeProduction` builds *without* the tag and asserts
demo is nowhere in it. The module itself does deliberately almost nothing —
one ConfigMap in `ceffio-system` — but declares everything a real module
declares (Namespaces, Permissions, Resources, Warning), so every frontend
exercises the same code paths at zero cluster cost. Read it before writing
yours: it is the smallest complete example, and its commit (`git show
56e9b7b`) is the smallest complete diff — four new files (the package and
the tagged import), plus one pre-existing test that had to be corrected
because it asserted `len(module.All()) == 13`, a hard count that would fail
on *any* new module. A normal module addition should not need that second
part; the corrected test now checks what it was really defending (no Core
module missing from the declared lists) and lets the registry grow.

One subtlety worth knowing before you copy it: demo registers through a
function value (`var register = module.Register`) rather than calling
`module.Register` directly, because the `all.go` guardrail test parses files
without evaluating build tags and would demand an untagged import of a
tagged-only package. A normal module has no such problem — call
`module.Register` directly and add your line to `all.go`.

## 9. Settings

Installing, observing and removing a feature needed only its package. **Settings
did not** — they were written by hand in the console (the TLS page, the SMTP
page), so the next feature with settings would have forced a console change. A
module now **declares** its settings, and the console, the CLI and the installer
serve them without knowing what they mean.

The contract lives in `internal/module/reglages.go`: `Group`, `Field`,
`Values`, `Validate`, and two **optional** interfaces.

### Declaring a group

```go
func (m *yourModule) Settings() []module.Group {
    return []module.Group{{
        ID:          "relay",           // stable, snake_case: routes and storage
        Title:       "Relay",
        Description: "One sentence shown above the form.",
        Fields: []module.Field{
            {Key: "hote", Label: "Host", Type: module.Text, Required: true},
            {Key: "port", Label: "Port", Type: module.Number, Default: "587"},
            {Key: "mode", Label: "Mode", Type: module.Choice, Options: []module.Option{
                {Value: "simple", Label: "Simple"},
                {Value: "fancy", Label: "Fancy"},
            }},
            {Key: "token", Label: "Token", Type: module.Secret},
            {Key: "colour", Label: "Colour", Type: module.Text, Pattern: `^#[0-9A-Fa-f]{6}$`,
                ShowWhen: &module.Condition{Key: "mode", Equals: "fancy"}},
        },
    }}
}
```

**Five field types, and no more**: `text`, `number`, `bool`, `choice`, `secret`.
A sixth is a CONTRACT change — declared in `internal/module`, drawn once in the
console's `settingsField` — never a section written for one module. If a setting
does not fit, say so rather than inventing a type.

`ShowWhen` may only point at a `Choice` or a `Bool` **of the same group, not
itself conditional**: a field depending on a conditional field can never be
reached. `verifierGroupes` refuses that shape at registration, which is where you
find out — at startup, not on the operator's page.

### The three methods

```go
func (m *yourModule) Current(ctx context.Context, env module.Env, group string) (module.Values, error)
func (m *yourModule) Apply(ctx context.Context, env module.Env, group string, v module.Values) error
func (m *yourModule) Test(ctx context.Context, env module.Env, group string, v module.Values) module.TestResult
```

`Test` is on a **separate interface** (`module.Testable`): verification is not
possible for every setting — a colour has nothing to test — and a button that
always answers OK teaches the operator to ignore it. Implement it only when the
group can genuinely be checked.

### The rules that carry the design

**A secret never travels back.** `Current` answers `module.SecretSet` (`••••`)
for a stored secret and `""` for an unset one, and `internal/settings` enforces
it in the one place that reads on behalf of a frontend. A module returning the
value leaks it to the console, the CLI and any proxy log at once.

**An empty secret KEEPS the stored one.** A form is re-saved to change a port and
the password field comes back empty because the value never reached the browser.
`module.SecretSet` means the same thing: storing the placeholder would replace a
working credential with `••••`.

**An unknown key is refused**, not stored: a typo would be written, never read,
and the setting would look like it had no effect.

**A hidden field is not validated**: the console submits what it drew, and
refusing a value the operator cannot see is not actionable.

### Where the values are stored

By default, `internal/settings`: ordinary values in the `ceffio-settings`
ConfigMap (`ceffio-system`), one key per `<module>.<group>`; secrets in OpenBao
under `kv/ceffio/settings/<module>/<group>`, with a Kubernetes Secret per module
when no vault is configured. Both are picked up by `ceffio backup`.

**A module MAY store elsewhere**, and must say why. Two cases exist today:

- `ingress` writes its DNS credential to `kv/data/ceffio/tls/dns-provider`,
  because the solver and the ClusterIssuer read it THERE — moving it would need a
  migration and two copies to keep in step;
- `files` writes the relay password to `smtp/relais`, for the same reason.

A module that stores elsewhere still goes through `module.Validate`, so both
frontends accept exactly the same values.

### What it gives you for free

- the console's **Settings** tab, one card per configurable module, forms drawn
  from `Field`, `ShowWhen` applied live, Test and Save buttons;
- `ceffio module config <id> [<group> [key=value …]]`, with `--test` and secrets
  read from standard input (`token=-`) so they never appear in `ps`;
- `ceffio backup` / `restore` carry the settings without anyone thinking about it.

### The guardrail

Two tests keep the promise from decaying, and neither searches for module IDs by
name — `files`, `data`, `mail` and `console` are ordinary words, and a search
would flag prose:

- `TestRoutesConsoleAppartiennentALAListeFermee`: every route on the console's
  mux belongs to a closed list. A route outside it is a console change made for
  one feature;
- `TestLaPageNAppelleAucunModuleEnDur`: `index.html` calls no `/api/modules/<id>`
  literally and holds no module ID as a quoted string.

**If you need an interface element the contract does not cover, EXTEND THE
CONTRACT** — declared in `internal/module`, drawn once by the console — never a
section written for your module. That is the rule these tests enforce, and the
reason the seventh feature costs as little as the first.

## Checklist

1. New package under `internal/modules/<name>/`, SPDX header, comments in
   English explaining WHY.
2. `Info`, `State`, `Uninstall`, `Install` (idempotent, with a complete and
   re-runnable `Uninstall`).
3. Fill `Info` honestly: `Kind: module.Optional`, a deliberate `Default`,
   `Requires` for every dependency, real `Namespaces`, `Resources` and
   `Warning` when they inform a decision, `Permissions` limited to what the
   console must do.
4. **If the feature has settings**: implement `Configurable` (`Settings`,
   `Current`, `Apply`), and `Testable` when the group can genuinely be checked.
   Declare the groups and their fields; do NOT add a console route, a console
   section or a CLI subcommand — they are served by the contract.
5. `func init() { module.Register(&yourModule{}) }`.
6. One blank-import line in `internal/modules/all.go`.
7. Tests: `Info` validity, (if the module installs resources itself) the
   fake-clientset contract tests, and the settings round trip
   (`Current` → `Apply` → `Current`) when it has settings.
8. `gofmt -l .`, `go build ./...`, `go vet ./...`, `make test`,
   `go test -tags demo ./...` — all green.
9. **Nothing else.** If anything else changed, you changed too much — and the
   test of the demo module's settings checks exactly that for its own package.
   A console route, a page in `web/index.html` or a CLI subcommand named after
   your feature means the contract was not extended where it should have been.

---

## Second complete example: `longhorn-ui`

`internal/modules/longhornui` is worth reading after the demo module, because it does
the one thing the demo cannot: **it declares its own OIDC client**, without touching
`internal/sso`'s list of core clients.

```go
secret, err := sso.AssurerClient(ctx, sso.Client{
	ID:              "longhorn",
	Redirects:       "https://longhorn." + domaine + "/oauth2/callback",
	PostLogout:      "https://longhorn." + domaine + "/",
	Audience:        true,           // the relying party verifies `aud`
	CoffreComposant: "longhorn-ui",  // the MODULE's own vault path
	CoffreChemin:    "oauth2-proxy",
})
```

WHAT THAT BUYS, and why it is the generic form rather than a shortcut: the core's
clients stay in `clientsOIDC`, the module's client is declared where the feature lives,
and `internal/sso` never learns the module's name.

FOUR THINGS THIS MODULE DOES THAT ARE WORTH COPYING:

1. **It validates before it contacts anything.** A wrong description — no ID, no
   redirect URI — is refused before the vault or the cluster is touched, so an operator
   with a sealed vault learns about their mistake rather than about the vault.

2. **It reuses its secrets instead of regenerating them.** The cookie secret is created
   once and kept: regenerating it would sign every user out after each upgrade, while
   looking like a working deployment.

3. **It writes what the form shows AND what the process reads.** `Apply` stores the
   setting and rewrites the ConfigMap the proxy mounts; writing only the first makes the
   form agree with itself while the proxy keeps the old value — the worst kind of change,
   because it looks saved.

4. **It declares a `Warning` that decides the install.** The interface can delete
   volumes; that sentence is why the module is `Optional` with `Default: false`, and why
   it is not in the core.

WHAT IT DOES *NOT* DO, and this is the part that keeps the console generic: there is no
route for `longhorn-ui`, no section in `web/index.html`, no CLI subcommand. Its settings
group (`access`) appears in Settings and in `ceffio module config` because the contract
draws it. If you find yourself adding any of those for your module, the right move is to
extend the contract — declared in `internal/module`, drawn once by the console — not to
add a section named after your feature.

ONE THING TO WATCH, learned by deploying: a module that ships a Deployment **must create
its ServiceAccount first**. A Deployment whose ServiceAccount does not exist reports
`0/1` and names the account without saying who was meant to create it, and the pod is
never even attempted.
