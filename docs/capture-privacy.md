# What the capture processes, and what the organisation must do

A named transcript is **personal data**, and it is not the same data as the video.
The recording already exists in the owner's files; the transcript adds **who said
what**, in text, with timings. Ceffio runs the whole chain on the customer's own
server and sends nothing anywhere — but the organisation that records remains the
controller, with the obligations that come with it.

This page says what the software does, what it does not do, and what is left to
the organisation.

## What is processed

| Data | Where it comes from | Where it ends up |
|---|---|---|
| The voice of each participant | the call, through the signaling, one Opus track per participant | the capture's work directory, then **deleted** |
| The participants' names | the roster at the moment of capture (`userId`, otherwise `displayName`) | written in the `.srt`, as `name : text` |
| The speech timings | the transcription, per segment | written in the `.srt` |
| The transcript text | Whisper, on this server's CPU | written in the `.srt` |
| The room, owner, start, end, result, error, duration | the relay's notification and the job | `/status`, readable by the console |

What is **not** processed: the video, the chat, the shared files, the
participants' addresses. The capture joins the call as a hidden participant and
receives audio only.

## Where it lives, and for how long

**The audio tracks** live in the capture pod's ephemeral filesystem
(`/work/salons/<token>/pistes`). They are removed as soon as the transcription
has been deposited. If the transcription **fails**, they are kept for 24 hours
(`CEFFIO_KEEP_FAILED_HOURS`) so the job can be retried — a failed transcription
that also deletes its audio is a meeting lost for good. A pod restart loses them,
by design: nothing durable is kept on the node.

**The transcript** is written next to the recording, in the files of the person
who started it:
`<owner>/files/Talk/Recording/<token>/Recording <date>.srt`. It therefore has
**the same lifetime as the recording** — deleting the `.webm` does not delete the
`.srt`, and neither is deleted by the capture.

**The model** is executed on the same server: `small` is baked into the image,
`medium` can be fetched into `/models-extra`. Nothing is sent to a third party,
and there is no transcription service on the internet.

**`/status`** exposes the last job — room, owner, start, end, result, error,
duration — and **never the transcript text**. The console reads that status; it
never reads a file.

**The logs** name room tokens and tracks, and the per-track shift. They do not
contain speech.

## What the software does not do

- It does not send audio or text anywhere: no telemetry, no cloud model.
- It does not deliver a copy of the audio: the tracks are the capture format,
  decoded in memory and dropped once the transcript exists.
- It does not keep the `.srt` in the vault, nor in a database: it is a file, in
  the owner's account, like the recording.
- It does not decide a retention period — it has no way to know the
  organisation's.

## What the organisation must do

1. **Inform the participants.** Talk already posts a `recording_started` system
   message in the conversation, so the recording itself is announced — but it
   says nothing about the transcription, and it arrives when the recording
   starts, not before.
2. **Say who is named.** The transcript attributes each sentence to a person by
   name. A meeting where people did not expect to be named is a meeting where the
   information was insufficient.
3. **Fix a retention period**, and apply it to both files. The `.srt` follows the
   recording; a policy that only deletes `.webm` leaves the transcript behind.
4. **Handle access and erasure requests.** The files sit in the owner's account;
   an erasure request is a file deletion, to be done by the organisation.
5. **Consider a data-protection impact assessment.** Systematic processing of
   voices with named transcripts, in an administration or a company, is the kind
   of processing a DPIA (GDPR art. 35) is meant for.
6. **Keep the processing register up to date**, with the installation's host as
   processor if the platform is not operated by the controller itself.

## Could the notice be automatic? (enquiry)

The plan asked whether a message could be posted in the conversation when a
capture starts — "this recording will also be transcribed" — with Talk's bots.

**What Talk already does.** The conversation receives a system message when a
recording starts, stops or fails (`recording_started`, `audio_recording_started`,
`recording_stopped`, `recording_failed`, in `lib/Chat/SystemMessage/Listener.php`).
The start message is posted by the moderator who starts it. Nothing in it
mentions the transcription.

**What a bot could add.** Talk's bot API can post a message into a conversation
with `POST /ocs/v2.php/apps/spreed/api/v1/bot/{token}/message`, signed with the
bot's shared secret (`X-Nextcloud-Talk-Bot-Signature`) — no user session, so the
relay could do it, since it knows the room token at the moment the recording
starts. Installing the bot is one command
(`occ talk:bot:install --feature response`), and the secret belongs in OpenBao.

**Why it is not free, and why this lot does not implement it.**
A bot must be **set up in each conversation** (`occ talk:bot:setup <bot-id>
<token>`, which a moderator can also do or undo), and a conversation created
afterwards does not have it. An automatic notice would therefore be automatic
for the rooms where someone remembered to set it up — which is the worst of both
worlds: it looks systematic and is not. On top of that, the bot API sends no
*recording* event, so the trigger has to come from us (the relay), adding a
Nextcloud endpoint and a bot secret to a component that today talks to nobody.

**Verdict:** feasible, worth revisiting if the platform is operated for several
organisations and the notice must be uniform — but the reliable path today is the
information notice below, given before the meeting, plus Talk's own
"recording started" message.

## Notice template

To be adapted and given to the participants **before** the meeting (invitation,
agenda, or a message in the conversation).

**Français**

> Cette réunion est enregistrée, et l'enregistrement est transcrit
> automatiquement afin d'en produire une version écrite. La transcription
> identifie chaque personne qui parle par son nom, et elle est conservée avec
> l'enregistrement dans les fichiers de la personne qui a lancé celui-ci, pendant
> [durée]. Aucun son ni texte ne quitte le serveur de [organisation] et aucun
> prestataire extérieur n'intervient. Pour exercer vos droits d'accès ou de
> suppression, ou pour toute question : [contact].

**English**

> This meeting is recorded, and the recording is transcribed automatically to
> produce a written version. The transcript identifies each speaker by name, and
> it is stored with the recording in the files of the person who started it, for
> [duration]. No audio or text leaves [organisation]'s server, and no external
> provider is involved. To exercise your rights of access or erasure, or for any
> question: [contact].
