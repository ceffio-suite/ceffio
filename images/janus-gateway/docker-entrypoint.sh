#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © MANDEM
# Janus entrypoint for Ceffio.
#
# Role: make Janus usable behind the firewall NAT, WITHOUT freezing the public
# address into the image.
#
# WHY: Janus must announce to browsers an address they can actually reach.
# Behind a NAT, its interfaces are private: if it announces them as-is in the
# ICE candidates, the media never gets through. The fix is `nat_1_1_mapping`
# (1:1 mapping private IP ↔ public IP) — but the public IP changes with each
# deployment, so it cannot live in the image.
#
# Recognized variables:
#   JANUS_PUBLIC_IP     Public IP announced by Janus (nat_1_1_mapping).
#                       If empty, no mapping is set (local deployment).
#   JANUS_DEBUG_LEVEL   Log level (0-7). Default: 4 (warn).
#   JANUS_RTP_PORT_RANGE  UDP media range. Default: 20000-20100.
#   JANUS_STUN_SERVER   STUN server: enables AUTOMATIC DETECTION of the public
#                       IP. This is the recommended way — see below.
#                       MUST be reachable from the Internet: a local STUN
#                       (on the same network) returns the PRIVATE address and
#                       the detection is useless. A hostname is accepted and
#                       resolved to IPv4 (see section 4).
#   JANUS_STUN_PORT     STUN server port (default: 3478; 19302 for
#                       stun.l.google.com).
set -e

CFG=/opt/janus/etc/janus/janus.jcfg

# ---------------------------------------------------------------------------
# 1. Public IP (nat_1_1_mapping)
# ---------------------------------------------------------------------------
if [ -n "${JANUS_PUBLIC_IP:-}" ]; then
    if grep -q "^[[:space:]]*nat_1_1_mapping" "$CFG"; then
        sed -i "s|^[[:space:]]*nat_1_1_mapping.*|nat_1_1_mapping = \"${JANUS_PUBLIC_IP}\"|" "$CFG"
    else
        # insert right after the opening of the nat { block
        sed -i "/^nat: {/a\\\tnat_1_1_mapping = \"${JANUS_PUBLIC_IP}\"" "$CFG"
    fi
    echo "janus: nat_1_1_mapping = ${JANUS_PUBLIC_IP}"
else
    echo "janus: no JANUS_PUBLIC_IP — no NAT mapping (local deployment)"
fi

# ---------------------------------------------------------------------------
# 2. Log level
# ---------------------------------------------------------------------------
if [ -n "${JANUS_DEBUG_LEVEL:-}" ]; then
    sed -i "s|^[[:space:]]*debug_level.*|debug_level = ${JANUS_DEBUG_LEVEL}|" "$CFG"
fi

# ---------------------------------------------------------------------------
# 3. Media range
# ---------------------------------------------------------------------------
if [ -n "${JANUS_RTP_PORT_RANGE:-}" ]; then
    sed -i "s|^[[:space:]]*rtp_port_range.*|rtp_port_range = \"${JANUS_RTP_PORT_RANGE}\"|" "$CFG"
    echo "janus: rtp_port_range = ${JANUS_RTP_PORT_RANGE}"
fi

# ---------------------------------------------------------------------------
# 4. STUN server — AUTOMATIC DETECTION OF THE PUBLIC IP
#
# WHY THIS IS PREFERABLE TO JANUS_PUBLIC_IP: a variable that must be known
# BEFORE deploying is an obstacle for a self-contained product. Janus does
# better: at startup, if a STUN server is configured, it sends a real STUN
# packet over UDP, reads the XOR-MAPPED-ADDRESS from the reply, and calls
# janus_add_public_ip() with the result (src/ice.c) — the SAME function as the
# one used by nat_1_1_mapping. The public IP is thus discovered on its own,
# with no extra port to open: the packet goes out through the NAT, on an
# ephemeral source port (or on the media range, already open).
#
# Verified in the Janus 1.3.0 source code, then in real execution.
# ---------------------------------------------------------------------------
if [ -n "${JANUS_STUN_SERVER:-}" ]; then
    STUN_PORT="${JANUS_STUN_PORT:-3478}"

    # RESOLUTION TO IPv4 — ESSENTIAL.
    #
    # Janus accepts a hostname here, but it resolves it via getaddrinfo, which
    # returns IPv6 FIRST on a dual-stack machine. Janus then only queries the
    # STUN over IPv6 and announces a public IPv6 address — measured:
    #   >> Our public address is 2a01:e0a:ff3:7830:be24:11ff:fe52:3cea
    # Result: browsers that only have IPv4 receive no reachable candidate and
    # the media does not get through.
    #
    # We therefore pin IPv4 here. The hostname remains accepted as input; only
    # the address written to the configuration is a literal IPv4.
    case "${JANUS_STUN_SERVER}" in
        *[!0-9.]*)
            # Not a literal IPv4: resolve it.
            STUN_IP4="$(getent ahostsv4 "${JANUS_STUN_SERVER}" 2>/dev/null | awk 'NR==1{print $1}')"
            if [ -n "$STUN_IP4" ]; then
                echo "janus: ${JANUS_STUN_SERVER} resolved to IPv4 = ${STUN_IP4}"
                JANUS_STUN_SERVER="$STUN_IP4"
            else
                echo "janus: WARNING — ${JANUS_STUN_SERVER} does not resolve to IPv4." >&2
                echo "janus: STUN detection may announce an IPv6 address" >&2
                echo "janus: and make the media unreachable. Prefer IPv4." >&2
            fi
            ;;
    esac

    if grep -qE "^[[:space:]]*stun_server" "$CFG"; then
        sed -i "s|^[[:space:]]*stun_server.*|stun_server = \"${JANUS_STUN_SERVER}\"|" "$CFG"
    else
        sed -i "/^nat: {/a\\\tstun_server = \"${JANUS_STUN_SERVER}\"" "$CFG"
    fi
    if grep -qE "^[[:space:]]*stun_port" "$CFG"; then
        sed -i "s|^[[:space:]]*stun_port.*|stun_port = ${STUN_PORT}|" "$CFG"
    else
        sed -i "/^[[:space:]]*stun_server/a\\\tstun_port = ${STUN_PORT}" "$CFG"
    fi
    echo "janus: stun_server = ${JANUS_STUN_SERVER}:${STUN_PORT} (auto-detection of the public IP)"
fi

# ---------------------------------------------------------------------------
# 5. Self-signed certificates for DTLS
#
# Janus needs a certificate for DTLS (the WebRTC handshake). The certificate
# shipped in the image is self-signed, which is normal and accepted by
# browsers for DTLS — unlike website TLS. It is only regenerated if absent.
# ---------------------------------------------------------------------------
CERTDIR=/opt/janus/share/janus/certs
if [ ! -f "$CERTDIR/mycert.pem" ]; then
    # The certificate is normally created at build time. We only get here if
    # the directory was replaced (a volume mounted on top of it, for example).
    # Do NOT let it fail: without a certificate Janus starts but DTLS fails,
    # and a startup error would be more misleading than useful.
    echo "janus: certificate missing, generating"
    mkdir -p "$CERTDIR" 2>/dev/null || true
    if openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
        -keyout "$CERTDIR/mykey.pem" -out "$CERTDIR/mycert.pem" \
        -subj "/CN=janus" >/dev/null 2>&1; then
        cat "$CERTDIR/mycert.pem" > "$CERTDIR/mycert-fullchain.pem"
        : > "$CERTDIR/mycacert.pem"
    else
        echo "janus: WARNING — DTLS certificate not generated (directory not writable?)" >&2
    fi
fi

echo "janus: starting — $*"
exec "$@"