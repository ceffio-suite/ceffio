> **Historical working note, kept for context. Does not describe the current code.**
> The report the plan asked for, written at the end of the work; the code it
> describes was delivered with PRs #100, #101 and #102.

# Capture module and recording relay — final report

Plan: `plan-capture-relais.md` (parts A, B, C). Installation used for the real
tests: `ceffio.org`, single-node K3s, Talk + HPB + recorder + capture.

## Pull requests and commits

| Part | Branch | Commits | PR |
|---|---|---|---|
| A — corrections of the module | `fix/capture` | `cef0a46` (A1 dependency), `26cde25` (A2 state), `c9569e8` + `384531c` (A3 settings), `2e23af5` (A4 mechanism), `fe4ace7` (A4 `longhorn-ui`), `34a8f82` (A5 small fixes) | #100 |
| B — the relay | `feat/capture-relay` | `6261d40` (B1 relay), `488e2fd` (B2 container), `2ab0c9f` (B3 image v0.8.0), `46d315d` (deposit fix), `790ba6d` (close fix), `bb076df` (in-image test), `f5b6f24` + `fc30f7c` (B5 secret, rights, pin), `91caf31` + `e672dbb` (stop shape, pin v0.8.2) | #101 |
| B — the image | `fix/capture` in `ceffio-capture` | `2ab0c9f`, `46d315d`, `790ba6d`, tags `v0.8.0`, `v0.8.1`, `v0.8.2` | ceffio-capture#1 |
| C — personal data | `docs/capture-privacy` | `1d1faa4` | #102 |

## The enquiries

**B2 — does the recorder accept requests from `127.0.0.1`?** `/api/v1/room/<token>`
is not filtered by source address: the control is the HMAC signature, with the
secret looked up by the `Talk-Recording-Backend` URL. `TrustedProxiesFix` only
rewrites `REMOTE_ADDR` when the peer is in `trustedProxies`; sending no
`X-Forwarded-For` therefore leaves the recorder seeing `127.0.0.1`, which is
true — the relay is in the same pod. **No header was added.**

**B3.3 — is the room language available through the signaling?** No. The vendored
client's join reply does not carry it (it only handles `event`, `message`,
`bye`), and Talk keeps the value in `oc_talk_rooms`. With the database gone, the
capture falls back to per-track detection, with `CEFFIO_LANGUE` as an
installation-wide override. The consequence is written in `docs/plan-capture.md`:
a French call ending in one Arabic sentence can come back wholly in Arabic. The
operator accepted this trade when they accepted the plan's fallback.

**B4 — can the `.srt` be deposited through the official OCS route?** No.
`/ocs/v2.php/apps/spreed/api/v1/recording/<token>/store` accepts only
`audio/ogg`, `video/ogg`, `video/mp4`, `video/webm` and `video/x-matroska`
(`DEFAULT_ALLOWED_RECORDING_FORMATS`, `lib/Service/RecordingService.php`), so a
subtitle file is refused on its MIME type and then on its extension. The
`pods/exec` right in `ceffio-files` stays, by decision, and `docs/plan-capture.md`
says why.

**C2 — can the notice be posted automatically in the conversation?** Partly.
Talk already posts `recording_started`, and says nothing about the transcription.
A bot can post with `POST /ocs/v2.php/apps/spreed/api/v1/bot/{token}/message`
(signed with its secret, no user session), and the relay knows the token at that
moment. But a bot must be set up **in each conversation** (`occ talk:bot:setup`,
which a moderator can undo), and later conversations do not have it: an automatic
notice would be automatic only where someone remembered. Not implemented; the
enquiry and a reusable notice template are in `docs/capture-privacy.md`.

## The real test (B6)

A 65-second meeting, two participants, started and stopped from Talk's interface:

```
side 4nvg22Kx: shift -7.6s   language fr (0.86)
side jsXg99cA: shift -1.1s   language fr (0.95)
{"segments": 7}              deposited .../Recording 2026-10-27 23-11-26.srt
```

`/status`: `transcribed`, 15.1 s. The `.srt` names the speakers and sits next to
the `.webm` in the owner's files; the work directory was removed afterwards.

The other checkpoints: recording without the capture answers `200` in ~155 ms and
logs one debug line; `pods/exec` in `ceffio-data` answers **no**; a forged
notification answers **403**.

**Three defects the real tests found, none of which a unit test would have
invented:**

1. Talk sends `"stop": []` (empty array) when no participant is given; the relay
   decoded it as an object, dropped the notification, and the capture kept
   running — the transcript was never written.
2. `deposer()` in the image had a local `dossier` shadowing the function of the
   same name: `UnboundLocalError` after a successful transcription, and the
   `.srt` stayed in the work directory.
3. PyAV writes audio only at `close()`; the agent killed the client with SIGTERM
   first, so the tracks were **zero bytes** while the `.webm` held audible
   speech. Measured in the container: 50 packets → 0 bytes, 387 after close().

Two recordings lost to (1) and (3) were recovered from their `.webm` mix
(without speaker names, labelled `participant`) and deposited, scanned with 0
errors. **The automatic fallback to the mix was deliberately not implemented** —
the operator asked for the failure to stay visible rather than for a transcript
without names.

## RBAC, before and after

Removed from the capture (module declaration and cluster):

| Namespace | Resource | Verbs |
|---|---|---|
| `ceffio-data` | `pods` | `get`, `list` |
| `ceffio-data` | `pods/exec` | `get`, `create` |

Kept, on purpose: `ceffio-files` `pods` (`get`, `list`) and `pods/exec`
(`get`, `create`) — the deposit is still an exec, see B4.

Added: nothing. The console's grant is unchanged (the `data` module still
declares its own rights on `ceffio-data`).

## Where the code and the plan disagreed

- **The pod's secret.** The plan suggested the relay read `/secrets/env` "the
  same way" as the recorder. The recorder can source that file because its image
  has a shell; the Ceffio image is `FROM scratch`. The injector renders a second
  file, `/secrets/relay-secret`, in 0400, and the agent runs as 65532 so the
  relay can read it. Written down in B2's commit and PR.
- **`longhorn-ui`.** The plan allowed keeping its Secret if oauth2-proxy could
  not read a file. It can: `--client-secret-file` / `--cookie-secret-file` are
  read with `os.ReadFile` and not trimmed, so the Secret is gone and the module
  declares its own vault access.
- **The module declares its own access** (`Info.Vault`) — the plan's A4 — which
  is what made the `longhorn-ui` migration possible at all.
- **Language.** The plan's fallback is in place, and its cost is documented
  rather than hidden.
