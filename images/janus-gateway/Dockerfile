# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © MANDEM
# Janus WebRTC Gateway — image for Ceffio (Talk High Performance Backend)
#
# Rebuilds the official nextcloud-spreed-signaling Dockerfile
# (docker/janus/Dockerfile) REPRODUCIBLY: pinned versions, no floating
# `master`, and configuration adapted to Ceffio.
#
# WHY THIS REPOSITORY: the official spreed-signaling compose does a local
# `build:`. A k3s cluster has no toolchain — a published image is needed. This
# repository produces that image, versioned, pushed to the registry.
#
# Reference source (to follow for updates):
#   https://github.com/strukturag/nextcloud-spreed-signaling/blob/master/docker/janus/Dockerfile

FROM alpine:3.21

# ---------------------------------------------------------------------------
# Build dependencies
# ---------------------------------------------------------------------------
# `openssl-dev` provides the HEADERS (for libsrtp/Janus), but NOT the
# command-line binary: the `openssl` package is needed too. Without it, the
# `openssl req` that generates the DTLS certificate fails with 127 — observed
# at runtime, then at build.
RUN apk add --no-cache \
      curl autoconf automake libtool pkgconf build-base \
      glib-dev libconfig-dev libnice-dev jansson-dev \
      openssl openssl-dev zlib libsrtp-dev gengetopt libwebsockets-dev \
      git curl-dev libogg-dev

# ---------------------------------------------------------------------------
# usrsctp — required for DataChannels (SCTP over DTLS)
# Pinned version: never use `master`.
# ---------------------------------------------------------------------------
ARG USRSCTP_VERSION=b28f0b55b00bde67f6be80d6623e2775b88026b8
RUN cd /tmp \
 && git clone --depth 1 https://github.com/sctplab/usrsctp \
 && cd usrsctp \
 && git fetch --depth 1 origin ${USRSCTP_VERSION} \
 && git checkout ${USRSCTP_VERSION} \
 && ./bootstrap \
 && ./configure --prefix=/usr \
 && make -j"$(nproc)" \
 && make install \
 && rm -rf /tmp/usrsctp

# ---------------------------------------------------------------------------
# libsrtp
# ---------------------------------------------------------------------------
ARG LIBSRTP_VERSION=2.6.0
RUN cd /tmp \
 && wget -q https://github.com/cisco/libsrtp/archive/v${LIBSRTP_VERSION}.tar.gz \
 && tar xf v${LIBSRTP_VERSION}.tar.gz \
 && cd libsrtp-${LIBSRTP_VERSION} \
 && ./configure --prefix=/usr --enable-openssl \
 && make shared_library -j"$(nproc)" \
 && make install \
 && rm -rf /tmp/libsrtp-${LIBSRTP_VERSION} /tmp/v${LIBSRTP_VERSION}.tar.gz

# ---------------------------------------------------------------------------
# Janus Gateway
# ---------------------------------------------------------------------------
ARG JANUS_VERSION=1.4.3
RUN mkdir -p /usr/src/janus \
 && cd /usr/src/janus \
 && curl -sL https://github.com/meetecho/janus-gateway/archive/refs/tags/v${JANUS_VERSION}.tar.gz | tar xz \
 && cd janus-gateway-${JANUS_VERSION} \
 && ./autogen.sh \
 && ./configure --disable-rabbitmq --disable-mqtt --disable-boringssl \
                --prefix=/opt/janus \
 && make -j"$(nproc)" \
 && make install \
 && make configs \
 && rm -rf /src

# Two essential fixes, BOTH observed in real execution
# (the container exited with 127 without them):
#
#  1. The binary is installed in /opt/janus/bin (a consequence of --prefix),
#     which is NOT in the PATH. Without this symlink: "janus: not found".
#
#  2. Janus 1.3.0 does NOT create /opt/janus/share/janus/certs (make install
#     does not install it). Yet it needs a certificate for the DTLS handshake,
#     and the entrypoint failed generating one in a missing directory — the
#     container died BEFORE starting Janus, with the misleading 127 error.
#     We therefore create the directory AND the certificate here: no more
#     writes at startup, which also makes the container read-only compatible.
RUN ln -sf /opt/janus/bin/janus /usr/local/bin/janus \
 && mkdir -p /opt/janus/share/janus/certs /opt/janus/share/janus/recordings \
 && cd /opt/janus/share/janus/certs \
 && openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
        -keyout mykey.pem -out mycert.pem -subj "/CN=janus" >/dev/null 2>&1 \
 && cat mycert.pem > mycert-fullchain.pem \
 && : > mycacert.pem \
 && chmod 644 *.pem

# ---------------------------------------------------------------------------
# Default Ceffio configuration
#
# Two essential settings for our deployment:
#
#   1. rtp_port_range = 20000-20100
#      Janus's factory value is 20000-40000 (20,001 UDP ports to open on the
#      firewall side). For an SMB, 100 ports is plenty — each participant
#      consumes 1 to 2 ports. We therefore reduce both the range and the
#      exposed surface.
#
#   2. nat_1_1_mapping + interfaces
#      Janus runs behind a firewall doing NAT. Without the public IP being
#      provided, it announces its internal addresses in the ICE candidates and
#      browsers cannot reach it. The value is injected at startup by the
#      entrypoint (JANUS_PUBLIC_IP variable), so that no IP is frozen into the
#      image.
# ---------------------------------------------------------------------------
COPY janus.jcfg /opt/janus/etc/janus/janus.jcfg
COPY janus.transport.websockets.jcfg /opt/janus/etc/janus/janus.transport.websockets.jcfg
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8088/tcp 8188/tcp
EXPOSE 20000-20100/udp

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["janus", "--full-trickle"]