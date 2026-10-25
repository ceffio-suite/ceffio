# Feasibility plan — per-participant capture and recording transcription

Status: phase 1 delivered. The `capture` module and its deployment exist
(`internal/capture`, `internal/modules/capture`); the image is published by its
own repository,
[ceffio-suite/ceffio-capture](https://github.com/ceffio-suite/ceffio-capture),
versioned independently and pinned in `internal/version`.

## 1. Goal

When a participant starts a recording in a Talk call:

1. one **audio track per participant** is captured from the first second;
2. when the recording stops, a **named** transcript is produced (who spoke);
3. the `.srt` and the per-participant `.opus` files are written **next to the
   `.webm`**, in the files of the person who started the recording;
4. the subtitles are **muxed into the `.webm`**, so that "Share to chat" shares
   the recording together with its transcript.

Out of scope for v1: live transcription (that is `live-transcription`, already
running), summaries, translation.

## 2. What the prototype proved

| Element | State |
|---|---|
| Signaling + WebRTC client, one track per participant | proven (two real tracks, 29 s and 49 s) |
| Start on Talk's recording state (`call_recording`) | proven |
| Language: room selector + per-track detection | proven (`fr` detected at 0.93 and 0.97) |
| CPU transcription | faster-whisper int8, **×7–11 real time** measured |
| Participant names | roster + `oc_talk_sessions` |
| Subtitle re-alignment | measured by correlation (6.4 s and 11.2 s per track) |
| Opus tracks at 32 kbit/s | ×11 to ×19 smaller than WAV |
| Muxed subtitles | WebVTT track, stream copy, +683 bytes |

## 3. Architecture

The image is built and published by **its own repository**. It carries a Python
stack (WebRTC, whisper) and its own release cadence; bundling it into the main
image would tie a 1.5 GB dependency to every Ceffio release, including
installations that never record.

The Ceffio repository keeps only the **module**: it pins the image version in
`internal/version` (the same rule as janus) and deploys it with `recording` as a
declared dependency.

Rejected alternatives: a Go rewrite of the signaling client (1 450 proven lines,
undocumented protocol, cgo for whisper) and a new ExApp (no natural access to
user files, extra AppAPI dependency).

## 4. Objects deployed by the module

Namespace `ceffio-video`, next to the recorder.

| Object | Role |
|---|---|
| `Deployment ceffio-capture` (1 replica) | watch, capture, finalise |
| `Service ceffio-capture` (`/healthz`) | supervision |
| `ServiceAccount` + `Role`/`RoleBinding` | two exec rights, nothing else |
| `PersistentVolumeClaim` (2 Gi, mounted `/models-extra`) | additional models (`medium`), optional |
| Native `Secret` | signaling internal secret, read from the vault, never regenerated |
| Module settings | visible in the console |

Rights, and nothing more:

- `ceffio-files`: `pods/exec` on the Nextcloud pod (deposit + `occ files:scan`);
- `ceffio-data`: `pods/exec` to read the recording state and the room language
  (the application database user cannot reach the Nextcloud database — verified:
  `permission denied for database "nextcloud"`).

## 5. Flow

```
Talk                          ceffio-capture                    Nextcloud
 │                                  │                               │
 │ moderator starts the recording   │                               │
 │──── call_recording = 3 ─────────▶│ (watch, 1 s)                  │
 │                                  │── joins the call (internal ───│
 │                                  │   client, aiortc)             │
 │   one track per participant ◀────│                               │
 │                                  │                               │
 │   stop (call_recording = 0) ────▶│                               │
 │                                  │── whisper int8 (CPU) ────┐    │
 │                                  │── Opus 32k per track ────┤    │
 │                                  │── named, re-aligned .srt ┘    │
 │                                  │── WebVTT muxed in the .webm ──│
 │                                  │──── deposit + files:scan ────▶│
```

## 6. Hard points and answers

**Track offsets.** Each WebRTC subscription arrives at a different moment
(measured: 6.4 s and 11.2 s after the `.webm` start). Each track is timestamped
when it opens, and every subtitle is computed in absolute time before being
mapped back to the recording timeline.

**Participant names.** The room roster maps the HPB session to the Nextcloud
session; `oc_talk_sessions` joined to `oc_talk_attendees` gives the display
name. No dependency on signaling logs.

**Writing into the launcher's files.** Through `pods/exec` in the Nextcloud pod
(write, `chown www-data`, `occ files:scan`) — the same path Ceffio already uses
for `occ`. WebDAV is the fallback if that right is ever refused.

**Models.** The `small` whisper model is **baked into the image**: an
installation works with no download at all, which is the point of a
self-hosted appliance. Larger models (`medium`) can be fetched into the
`/models-extra` volume, and ffmpeg is in the image rather than in a `/tmp` that
disappears on the next restart.

**CPU.** whisper `small` int8 at ×7–11 real time on 8 threads; one hour of
meeting with three participants is ~20–30 minutes of computation **after** the
call. Container limits keep it from starving the signaling the next call
depends on.

**Several `.webm` per meeting.** Talk restarts the recording when the
composition changes; the transcript must be split at each file boundary (start
from the file name, duration from the metadata).

## 7. Phases

| Phase | Content | Duration |
|---|---|---|
| 1 | Image (own repository), module, deployment, RBAC, state detection | 5–7 d — **done** |
| 2 | Client extraction, capture and finalisation in the image, console settings | 5–7 d — **done in the image, to validate on ceffio.org** |
| 3 | Nextcloud deposit, muxing, multi-`.webm` split, names | 4–6 d |
| 4 | CI multi-arch, docs, load tests (3–5 participants), prototype migration | 3–5 d |

## 8. Risks

| Risk | Impact | Answer |
|---|---|---|
| Undocumented signaling protocol | high | the Python client is proven; pinned and tested on each Talk upgrade |
| whisper on CPU | medium | int8, bounded threads, `small` baked in, `medium` on request |
| Dependency on `exec` in the Nextcloud pod | medium | already used for `occ`; WebDAV fallback |
| Silent failure | high | `/healthz`, and a state in the console (last recording: transcribed / failed) |
| Dialects (Darija) | medium | per-track detection + `medium` option; documented limit |

## 9. Decisions taken

1. Separate `capture` module (not an extension of `recording`).
2. `small` model baked into the image; `medium` as an option.
3. Opus tracks kept next to the recording (no automatic purge in v1).
4. New recordings only; retroactive transcription is a later action.
5. Transcript as files next to the `.webm`; no Nextcloud application in v1.
