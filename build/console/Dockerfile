# Image de la console d'administration — publiée par release.yml.
#
# Ce Dockerfile reprend à l'identique celui que l'ancien dépôt
# ceffio-suite/ceffio-console écrivait à la volée dans son workflow, à UNE
# différence près, voulue : le binaire n'est plus recompilé ici. Ce sont les
# binaires de la release (octet pour octet), déjà présents dans le contexte de
# build sous dist/, et l'ARG TARGETARCH sélectionne celui de l'architecture
# cible. Une seconde compilation produirait un binaire potentiellement
# différent de celui attaché à la release — l'image perdrait sa reproductibilité.
#
# Contexte de build attendu : la racine du dépôt, avec
#   dist/ceffio-linux-amd64
#   dist/ceffio-linux-arm64

FROM alpine:3.20 AS certs

FROM scratch

# TARGETARCH est fourni par BuildKit pour chaque plateforme d'un build
# multi-architecture (linux/amd64, linux/arm64). C'est ce qui permet à UN SEUL
# Dockerfile d'embarquer le bon binaire par architecture, sans étape
# intermédiaire ni émulation : aucune instruction n'exécute quoi que ce soit,
# BuildKit ne fait que copier des fichiers.
ARG TARGETARCH

# Les autorités de certification : la console appelle l'API Kubernetes et
# Keycloak en HTTPS, elle doit vérifier leurs certificats.
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY dist/ceffio-linux-${TARGETARCH} /usr/local/bin/ceffio

EXPOSE 8088

ENTRYPOINT ["/usr/local/bin/ceffio"]
CMD ["console", "--addr", ":8088"]
