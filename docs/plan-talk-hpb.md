# Ceffio — Migration to Nextcloud Talk + HPB

**Replacing the Matrix/Element + Jitsi stack with Nextcloud Talk with
High Performance Backend.**

Decision of 2026-10-09. Status: plan validated, execution not started.

---

## 1. Decision and rationale

Ceffio becomes a **Nextcloud product**, not a Matrix product: everything lives
in Nextcloud, with **a single login** (Keycloak, already wired to Nextcloud).

| | Before | After |
|---|---|---|
| Files / office | Nextcloud | Nextcloud |
| SSO | Keycloak | Keycloak |
| Chat | Synapse + Element | **Talk** |
| Visio | Jitsi | **Talk + HPB** |
| Editing | ONLYOFFICE | ONLYOFFICE |

**6 bricks, 2 messengers → 4 bricks, 1 messenger.**

Rationale: the Matrix↔Jitsi authentication bridge (OIDC adapter, UVS, tokens)
cost hours of maintenance and was never satisfactory. Talk authenticates
**natively** via Nextcloud, so the problem disappears by construction rather
than being worked around.

### What we lose, accepted

- Matrix federation (talking to other Matrix servers)
- Textual E2EE by default (Talk encrypts the transport and does E2EE **in calls**)
- Matrix bridges (Slack, IRC, Telegram, WhatsApp)
- Element's maturity/ecosystem

Not blocking for the target (small SMBs, internal use, simplicity, no
subscription). These are lost capabilities, not needs.

---

## 2. Components

Recorded from `docker/docker-compose.yml` of the official repository
`strukturag/nextcloud-spreed-signaling` — **5 services, not 4**.

| Service | Role | License | Origin |
|---|---|---|---|
| **Talk** (`spreed`) | Nextcloud app: chat + visio | AGPL-3.0 | Already present, to enable |
| **signaling** | Coordination (lightweight, Go) | AGPL-3.0 | Official Docker Hub image `strukturag/nextcloud-spreed-signaling` |
| **Janus** 1.3.0 | SFU: media transport | GPL-3.0 | **Compiled from source** (official Dockerfile) |
| **NATS** 2.10 | Inter-signaling messaging (scalability) | Apache-2.0 | `nats:2.10` |
| **coturn** 4.6 | TURN relay (restrictive networks) | BSD | `coturn/coturn:4.6` |

Correspondence with Jitsi (for those who know it):

```
Interface        Jitsi Meet          →  Talk
Coordination     Prosody (XMPP)      →  signaling + NATS
Media transport  JVB (SFU)           →  Janus (SFU)
Conductor        Jicofo              →  signaling
TURN             coturn (integrated) →  coturn (separate)
```

⚠️ **coturn is not optional**: present in the official compose. Without it, a
participant behind a corporate network or filtered 4G has **no** media path.

---

## 3. Target architecture

```
                        Caddy (OPNsense)  :443
                                 │
                        Traefik (k3s, VM 310)
                                 │
              ┌──────────────────┴──────────────────┐
              │                                     │
      cloud.<domain>                       spreed.<domain>
      (Nextcloud)                           (signaling, HTTPS + WS)
              │                                     │
        Talk app ─── internal HTTP call ──► signaling server
        (browser)                                  │
                                          ┌─────────┴─────────┐
                                        NATS               Janus
                                                              │
                                                           coturn
                                                    (relay, if needed)
```

WebRTC media **does not go through an L7 proxy**: it takes the NAT
redirections to Janus. Same principle as another suite's JVB.

---

## 4. Network — ports to open (OPNsense)

**Ceffio has its DEDICATED ports** — decision: complete isolation from the
other RTC suites (same reasoning as "two separate LiveKit"). No shared
service, no common secret, no common NAT rule.

```
spreed.<domain>      443/tcp       via Caddy — already routed by *.ceffio
20000-20100/udp      Janus media                 ← TO OPEN
3479/udp             TURN coturn (Ceffio)        ← TO OPEN (3478 = other RTC suite)
5349/tcp             TURN-over-TLS               ← TO OPEN
49152-49200/udp      coturn relay                ← TO OPEN
```

TURN port distribution in the infrastructure:

```
3478/udp       other RTC suite — DO NOT TOUCH
3479/udp       Ceffio                 (readable choice: neighbor of the standard)
```

The TURN port number is **free** (it is not a fixed standard like 443). The
only imperative: **the same number on both sides** (coturn config ↔ NAT rule),
otherwise the relay is unreachable.

Verified on VM 310: `3479`, `5349`, `49152-49200`, `20000-20100` are
**all free** (no local conflict). The conflict with the other suite only
exists on the public IP, via the NAT rules — and it is resolved by the
dedicated port.

Janus's default range is `20000-40000` (read in `conf/janus.jcfg.sample.in`).
We **reduce it to 100 ports**: plenty for an SMB, and it avoids opening
20,000 ports.

Setting to apply (`rtp_port_range` in `janus.jcfg`):
```
rtp_port_range = "20000-20100"
```

### Network pitfalls (already met, do not repeat)

1. **For a range, the OPNsense rule's "local port" field must stay EMPTY** —
   filled in, pf collapses the whole range onto a single port. Error already
   made for another RTC suite, documented in the wiki.
2. **Check overlaps**: another RTC suite occupies `50000-60000/udp`,
   `30000-40000/udp`, `3478/udp`. Settled: Ceffio uses ranges and a TURN port
   **entirely distinct** (see above), and a different VM (<cluster-ip> vs
   <autre-hote>). No NAT rule is shared.
3. k3s pods do not read the node's `/etc/hosts`: `hostAliases` or CoreDNS to
   resolve by public name.

---

## 4bis. Network isolation — traceability decision

**Decision: Ceffio and another RTC suite share NO network resource.**

Rationale: a company does not host several critical services on the same
ports, with the same secret and the same NAT rule. Sharing the TURN would mean
that a failure of one relay cuts both products' visio, that a config change
for one breaks the other, and that the other RTC suite's TURN credentials
would open the Ceffio relay. It is exactly the reasoning applied to the two
separate LiveKit instances.

```
                    VM                  media ports       TURN
another RTC suite  <autre-hote>  (at-livekit)   50000-60000/udp   3478/udp
                                      30000-40000/udp
Ceffio      <cluster-ip> (VM 310)     20000-20100/udp   3479/udp
                                      49152-49200/udp
```

No overlap. No shared NAT rule. No common secret.

Honest reservation: TURN is **not mandatory at startup**. Janus works without
it, as long as the users are on networks allowing direct UDP. coturn serves
those who are blocked (corporate 4G, hotel networks). One can therefore deploy
Talk **without** coturn first, and add it only if users complain — it is a
test that costs nothing.

## 5. What to automate in `ceffio install`

```
1.  Generate the secrets        hash_key, block_key, shared_secret,
                               turn_static_secret  (never in Git)
2.  Build/push Janus            image built from source → GitLab registry
3.  Deploy NATS                 Deployment + Service
4.  Deploy Janus                Deployment + Service + ConfigMap (reduced port)
5.  Deploy coturn               Deployment + Service + static secret
6.  Deploy the signaling        Deployment + Service + ConfigMap server.conf
7.  Enable Talk                 occ app:enable spreed
8.  Wire Nextcloud ↔ HPB        occ config:app:set spreed signaling_server_url
                               + shared secret (via occ, NEVER by hand)
9.  Expose spreed.<domain>      ingress + DNS + Caddy handler (ceffio expose)
```

**Design point — Janus image.** The official Dockerfile **compiles Janus from
source** (the compose does `build:`). On a k3s without a toolchain:
- **recommended**: build the image once, push it into the GitLab registry,
  pin the tag — consistent with the rule "pinned versions, never `latest`";
- alternative: prebuilt public Janus image (less reproducible).

---

## 6. Removal — the COMPLETE inventory

A `kubectl apply` **never** removes what it no longer knows, and the
environment variables set by a patch **survive** redeployments. An explicit
cleanup is needed, like `internal/media/sans_sso.go` did for the Jitsi SSO.

### 6.1 Matrix (Synapse + Element)

```
workloads    deploy/synapse, deploy/element, corresponding svc
ingress      chat.<domain>, matrix.<domain>
secrets      synapse-db, synapse-secrets, synapse-oidc
base         PostgreSQL `synapse`   (DROP DATABASE)
volume       PVC synapse-media
Keycloak     OIDC client `synapse`  (+ k8s secret synapse-oidc)
code         internal/chat/         (chat.go, ConfigureOIDC, ensureSynapseDB…)
             cmd/ceffio/install.go  → remove the chat.Deploy + ConfigureOIDC call
             cmd/ceffio/redeploy.go → idem
backup       remove `synapse` from the list of backup databases
status       remove the `chat` layer from the admin console
```

### 6.2 Jitsi

```
workloads    deploy/web, prosody, jicofo, jvb + services
loadbalancer the one carrying UDP 10000 / TCP 4443
ingress      meet.<domain>
secrets      jitsi-secrets
volume       PVC jitsi-config
code         internal/media/media.go (the Jitsi Deploy)
             internal/media/sans_sso.go (SSO cleanup, now useless)
NAT          OPNsense rules UDP 10000 + TCP 4443
registry     ghcr.io/jitsi/* images in internal/version
config.json  Element: the "jitsi" key (the object disappears with Element)
```

### 6.3 Related bits and pieces

```
Keycloak     webOrigins + frame-ancestors set for the Jitsi widget
             (already neutralized at the SSO removal — check that they go)
console      `chat` and `meet` entries of internal/console/status.go
doc          docs/sso-office-ingress-fixes.md mentions Jitsi/Matrix
```

---

## 7. Execution order

```
Phase 0   Measure VM 310's resources                          ← BLOCKING
Phase 1   Build + push the Janus image (GitLab registry)
Phase 2   Deploy NATS, Janus, coturn, signaling                without touching the rest
Phase 3   Enable Talk + wire to the HPB
Phase 4   Real tests (see §8)
Phase 5   Jitsi removal          ONLY if phase 4 OK
Phase 6   Synapse/Element removal ONLY if phase 4 OK
Phase 7   OPNsense cleanup (ports), DNS, docs, console
```

**Phases 5 and 6 are deliberately dissociated**: we only cut the existing
stack after proof that the new one works. Jitsi and Element remain the
fallback option throughout the migration.

---

## 8. Tests that count (not "it looks like it works")

```
1.  1:1 call in Talk                        → 2 participants, sound + image
2.  Group call (5-6)                        → goes through Janus, not P2P
    Proof: Janus logs showing the streams, or `chrome://webrtc-internals`
3.  External guest via link                 → without a Nextcloud account
4.  Restrictive network (4G / tethering)    → coturn does its job
    Proof: coturn logs showing the allocation
5.  SSO: the call uses the Nextcloud login  → no extra prompt
6.  Recording (if enabled)                  → file in Nextcloud Files
7.  Load: measure at 10-15 participants     → Janus CPU/RAM
8.  Ports open from outside                 → NAT rule effective
    Reminder: a UDP test with an empty packet ALWAYS returns a timeout
    (false negative) — capture with tcpdump, do not conclude on the timeout
```

---

## 9. Points to settle before starting

1. ~~VM 310 resources~~ — **MEASURED, LARGELY SUFFICIENT** (2026-10-09):

   ```
   machine        8 cores · 31 Gi RAM · 96 G disk (23 % used)
   available      26 Gi RAM · ~7.9 cores · 75 G disk
   current pods   0.45 core requested · 6.8 Gi requested (8.3 Gi limit)
   HPB need       ~3.8 Gi (Janus 2 + coturn 1 + signaling 0.5 + NATS 0.25)
   after deployment   > 20 Gi of free RAM
   ```

   These figures are those of a VM **at rest**: they prove there is room to
   install without degrading Nextcloud/Keycloak/ONLYOFFICE, but not the
   behavior under real load (which depends on the **bandwidth**, ~1.5 Mbps per
   participant in both directions — not measurable without a call in
   progress).
2. ~~TURN 3478/udp conflict with another RTC suite~~ — **RESOLVED**: dedicated
   port 3479 for Ceffio, complete isolation.
3. **Janus image** — build and version (recommended) or public image?
4. **The `--video` flag** — becomes the Talk visio. Rename, or Talk by
   default?
5. **Transcription** — Talk has a `live_transcription` app but it requires an
   AI backend to host. **Out of scope**, separate decision.
6. **Data migration** — the Matrix chat histories and the existing Jitsi
   recordings: export, or abandon?

---

## 10. Rules to respect (lessons already paid for)

- **Everything in one command**: `ceffio install` must deploy AND configure
  without intervention. A self-contained product does not ask for a "then do
  this by hand".
- **`occ` to configure Nextcloud**, never a manual change in the database.
- **Pinned versions**, never `latest`; images in the GitLab registry.
- **Secrets never in Git**; generated at deploy time.
- **Verify a tag by a pull**, not by "it exists".
- **tmux** for any long work on a VM.
- **A check that does not distinguish before from after verifies nothing**:
  the final test is a real call, not a `kubectl get pods`.
