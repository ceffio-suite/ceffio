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
| 19302 | UDP | STUN, used once at start-up to discover the public address | the host |

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

## The one dependency on a third-party service

Ceffio discovers its public address at start-up by asking **`stun.l.google.com:19302`**
(`internal/talk/talk.go`, `stunPublic`).

This is the only outbound call the platform makes to a service it does not own, and it is
worth stating plainly: the README used to claim there was no dependency on a third-party
service at all, which is not true.

It is a **lookup**, not a tunnel: no user data crosses it, and a successful call does not
use it afterwards. But it is a dependency, and a machine with no route to that address will
fail to configure the relay.

Making the STUN server a setting is a known improvement, not done yet.

## See also

- [architecture.md](architecture.md) — where Talk sits, and how the HPB works
- [tls.md](tls.md) — the certificate for `talk.<domain>`, served by coturn itself