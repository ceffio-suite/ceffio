# Media and firewall

Talk needs ports that ordinary web serving does not. This document lists them, and the
firewall mistakes that make a call connect with no audio.

## Ports

| Port | Protocol | What it carries | Exposed on |
|---|---|---|---|
| 80 | TCP | HTTP — the ACME challenge in HTTP-01 mode, and the redirect to HTTPS | the host |
| 443 | TCP | HTTPS — every web interface | the host |
| 3479 | TCP + UDP | TURN relay (coturn) | the host, **directly** |
| 5349 | TCP | TURN over TLS | the host, **directly** |
| 49152–49200 | UDP | coturn relay range — the ports relayed media actually uses | the host, **directly** |
| 20000–20100 | UDP | Janus media (the SFU carries the video itself) | the host, **directly** |
| 19302 | UDP | STUN, outbound only — learning the public address; no inbound rule needed | — |

`talk.<domain>` is the name that resolves to the machine for TURN and STUN. It is **not**
behind Traefik: browsers reach these ports directly, and coturn serves its own certificate.
`spreed.<domain>` is the signaling endpoint, and *that* one goes through Traefik like any
other web host.

## Why port 3479 and not 3478

3478 is the standard TURN port, and it is also what several other RTC services claim on
the same machine. Ceffio uses **3479** to avoid the collision. A firewall rule that opens
3478 "because that's the TURN port" leaves the relay unreachable.

## The relay range, which is the one that gets forgotten

49152–49200, UDP. coturn announces the relay port it allocated, and the peer connects back
to **exactly that number**: a translating NAT breaks the return path even when the
allocation looked fine. It must be forwarded 1:1.

The failure when it is closed is deceptive: **the allocation succeeds** (it goes over 3479),
the server believes the relay is up, and **no media ever passes**. A browser that cannot
reach the range falls back to direct candidates, and on a restrictive network there are
none — so the call fails saying "a TURN server is probably required" while the TURN server
is in fact perfectly healthy.

Janus also needs **20000–20100 UDP**, for the media it carries itself.

## Verifying it, from the Internet

```bash
turnutils_uclient -u "<user>" -w "<credential>" -y \
    -e <public-ip> -p 3479 talk.<domain>
```

A healthy server prints a **public** relay address with a port inside 49152–49200:

```
INFO IPv4. Received relay addr: 82.64.251.96:49198
INFO Total lost packets 0 (0.000000%)
```

A **private** relay address means the external address was not applied: the browser then
receives a candidate it cannot reach, which is the same failure by another route.

## The firewall mistakes, in the order they happen

1. **Opening the ports on the wrong interface.** A host firewall that allows the ports and
   a provider firewall that does not still blocks them. Check both.
2. **Forgetting UDP.** 3479 and the media range need UDP. A rule written as TCP only looks
   right in the console and blocks every packet that matters.
3. **NAT without the media range.** If the machine is behind NAT, the range must be
   forwarded **and** the public address declared, or coturn advertises an address browsers
   cannot reach.
4. **Opening 3478 instead of 3479.** See above.
5. **Closing port 80 too early.** In HTTP-01 mode, the certificate is issued over port 80.
   A firewall that opens only 443 produces a first installation that never gets a
   certificate.

## Checking it works

`turnutils_uclient` ships with coturn and is the honest test: it performs a real TURN
allocation, which is what a browser does.

```bash
turnutils_uclient -T -u <user> -w <password> -p 3479 talk.example.org
```

A successful run prints the relay address it was given. A failure names the phase — this is
the difference between "the port is closed" and "the credential is wrong", and it is worth
using instead of guessing from a browser console.

## Where the public address comes from

Nothing has to be supplied at installation: a small reporter (module `public-ip`,
`ceffio publicip serve`) discovers the machine's public IPv4 address and publishes it in
the ConfigMap `ceffio-system/ceffio-public-ip`. Janus and coturn read that value when
their pod starts; the console and `ceffio status` display it with its age.

**Several sources, and they must agree.** The reporter queries a list of STUN servers
over UDP — the same NAT path the media uses, which is why STUN comes first — and accepts
an address only when at least two sources corroborate it. If the STUN path is filtered it
falls back to HTTP echo services. A disagreement is reported rather than hidden: two NAT
pools answering differently is a diagnosis, not a value.

The default list (Settings → module `public-ip` → group `network`) is
`stun.nextcloud.com:443`, `stun.cloudflare.com:3478` and `global.stun.twilio.com:3478`,
with `ipv4.icanhazip.com`, `checkip.amazonaws.com` and `api.ipify.org` as HTTP fallback.
Google's STUN server is **not** in the list: the suite claims sovereignty, and one vendor
is one point of trust as much as one point of failure. It stays available as a setting,
along with a static address for an air-gapped installation (discovery is then disabled
and the value republished unchanged).

**When the address changes**, the reporter republishes it and rolls the Deployments
labelled `ceffio.io/consumes-public-ip=true`; their pods resolve the new value from the
ConfigMap at start. There is no manual step and no stale candidate — a deployment whose
pods read the address once, at start-up, and are never rolled would keep announcing an
address that no longer exists.

**To diagnose**, run `ceffio publicip check`: it tests every source separately and prints
which one fails. This is deliberately not the consensus path — the consensus hides a dead
source as long as two others agree, and the dead source is exactly what is being looked
for.

The coturn instance of the installation cannot serve as the reporter's STUN server: asked
from inside the cluster, it sees the pod's private address. The lookup has to leave.

## See also

- [architecture.md](architecture.md) — where Talk sits, and how the HPB works
- [tls.md](tls.md) — the certificate for `talk.<domain>`, served by coturn itself