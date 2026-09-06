#!/usr/bin/env sh
set -eu

# Bootstrap minimal : télécharge le binaire Ceffio et lance `ceffio install`.
# Ce script ne contient volontairement AUCUNE logique métier (celle-ci vit dans le CLI Go).
#
# À compléter avant production :
#   - vérification de checksum / signature
#   - pin de version
#   - retry et support proxy
#   - support air-gap

INSTALL_URL="${CEFFIO_RELEASE_URL:-https://releases.ceffio.io}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$OS" != "linux" ]; then
  echo "Only Linux is currently supported." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BIN="$TMP_DIR/ceffio"

curl -fsSL \
  "$INSTALL_URL/latest/ceffio-linux-$ARCH" \
  -o "$BIN"

chmod +x "$BIN"

install -m 0755 "$BIN" /usr/local/bin/ceffio

exec /usr/local/bin/ceffio install "$@"
