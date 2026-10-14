# Janus WebRTC Gateway — image pour Ceffio (Talk High Performance Backend)
#
# Reconstruit le Dockerfile officiel de nextcloud-spreed-signaling
# (docker/janus/Dockerfile) de façon REPRODUCTIBLE : amendes figées, pas de
# `master` flottant, et configuration adaptée à Ceffio.
#
# POURQUOI CE DÉPÔT : le compose officiel de spreed-signaling fait un `build:`
# local. Un cluster k3s n'a pas de toolchain — il faut une image publiée. Ce
# dépôt produit cette image, versionnée, poussée dans le registry.
#
# Source de référence (à suivre pour les mises à jour) :
#   https://github.com/strukturag/nextcloud-spreed-signaling/blob/master/docker/janus/Dockerfile

FROM alpine:3.21

# ---------------------------------------------------------------------------
# Dépendances de compilation
# ---------------------------------------------------------------------------
# `openssl-dev` fournit les EN-TÊTES (pour libsrtp/Janus), mais PAS le binaire
# en ligne de commande : il faut aussi le paquet `openssl`. Sans lui, le
# `openssl req` qui génère le certificat DTLS échoue en 127 — constaté à
# l'exécution puis au build.
RUN apk add --no-cache \
      curl autoconf automake libtool pkgconf build-base \
      glib-dev libconfig-dev libnice-dev jansson-dev \
      openssl openssl-dev zlib libsrtp-dev gengetopt libwebsockets-dev \
      git curl-dev libogg-dev

# ---------------------------------------------------------------------------
# usrsctp — requis pour les DataChannels (SCTP sur DTLS)
# Version figée : ne jamais utiliser `master`.
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
ARG JANUS_VERSION=1.3.0
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

# Deux corrections indispensables, TOUTES DEUX constatées en exécution réelle
# (le conteneur sortait en 127 sans elles) :
#
#  1. Le binaire est installé dans /opt/janus/bin (conséquence de --prefix),
#     qui n'est PAS dans le PATH. Sans ce lien : « janus: not found ».
#
#  2. Janus 1.3.0 ne crée PAS /opt/janus/share/janus/certs (make install ne
#     l'installe pas). Or il lui faut un certificat pour le handshake DTLS, et
#     l'entrypoint échouait en le générant dans un répertoire absent — le
#     conteneur mourait AVANT de lancer Janus, avec l'erreur trompeuse 127.
#     On crée donc le répertoire ET le certificat ici : plus aucune écriture
#     au démarrage, ce qui rend aussi le conteneur compatible read-only.
RUN ln -sf /opt/janus/bin/janus /usr/local/bin/janus \
 && mkdir -p /opt/janus/share/janus/certs /opt/janus/share/janus/recordings \
 && cd /opt/janus/share/janus/certs \
 && openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
        -keyout mykey.pem -out mycert.pem -subj "/CN=janus" >/dev/null 2>&1 \
 && cat mycert.pem > mycert-fullchain.pem \
 && : > mycacert.pem \
 && chmod 644 *.pem

# ---------------------------------------------------------------------------
# Configuration par défaut de Ceffio
#
# Deux réglages essentiels pour notre déploiement :
#
#   1. rtp_port_range = 20000-20100
#      La valeur d'usine de Janus est 20000-40000 (20 001 ports UDP à ouvrir
#      côté pare-feu). Pour une PME, 100 ports suffisent largement — chaque
#      participant consomme 1 à 2 ports. On réduit donc la plage ET la surface
#      exposée.
#
#   2. nat_1_1_mapping + interfaces
#      Janus tourne derrière un pare-feu qui fait du NAT. Sans indication de
#      l'IP publique, il annonce ses adresses internes dans les candidats ICE
#      et les navigateurs ne peuvent pas le joindre. La valeur est injectée au
#      démarrage par l'entrypoint (variable JANUS_PUBLIC_IP), pour ne pas figer
#      une IP dans l'image.
# ---------------------------------------------------------------------------
COPY janus.jcfg /opt/janus/etc/janus/janus.jcfg
COPY janus.transport.websockets.jcfg /opt/janus/etc/janus/janus.transport.websockets.jcfg
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8088/tcp 8188/tcp
EXPOSE 20000-20100/udp

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["janus", "--full-trickle"]