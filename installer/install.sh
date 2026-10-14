#!/usr/bin/env sh
set -eu

# Minimal bootstrap: downloads the Ceffio binary and runs `ceffio install`.
# This script deliberately contains NO business logic (that lives in the Go CLI).
#
# IT FETCHES FROM GITHUB RELEASES — the real publication channel, produced by
# the release.yml workflow. There is no other distribution server: an
# installation URL pointing at a domain nobody serves is a silent failure for
# the first user who tries it.
#
# IT VERIFIES THE CHECKSUM, and refuses to install what does not match. The
# release publishes checksums.txt next to the binaries precisely so the
# operator — or this script — can verify BEFORE executing. Installing an
# unverified binary that then receives root on a host holding an
# organisation's data is not a trade-off this project makes.
#
# To be completed:
#   - signature verification (checksum proves integrity, not origin)
#   - version pinning option
#   - retry and proxy support
#   - air-gap support

REPO="${CEFFIO_REPO:-ceffio-suite/ceffio}"
# CEFFIO_VERSION pins an exact release (e.g. v1.0.0); empty means "latest".
VERSION="${CEFFIO_VERSION:-}"

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

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO- "$1"; }
else
  echo "curl or wget is required." >&2
  exit 1
fi

if [ -z "$VERSION" ]; then
  # The GitHub "latest" redirect resolves to the newest NON-prerelease: a
  # release candidate is never installed by accident.
  VERSION="$(fetch "https://api.github.com/repos/$REPO/releases/latest" |
    grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 |
    sed 's/.*"\([^"]*\)"$/\1/')"
  if [ -z "$VERSION" ]; then
    echo "No published release found for $REPO." >&2
    echo "Build from sources instead: https://github.com/$REPO#installation" >&2
    exit 1
  fi
fi

ASSET="ceffio-linux-$ARCH"
BASE="https://github.com/$REPO/releases/download/$VERSION"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BIN="$TMP_DIR/$ASSET"
SUMS="$TMP_DIR/checksums.txt"

fetch "$BASE/$ASSET" > "$BIN"
fetch "$BASE/checksums.txt" > "$SUMS"

# VERIFY BEFORE EXECUTING. sha256sum is checked against the published file; a
# mismatch aborts the installation — the downloaded file is never run.
EXPECTED="$(grep " $ASSET\$" "$SUMS" | awk '{print $1}')"
if [ -z "$EXPECTED" ]; then
  echo "checksum for $ASSET not found in checksums.txt — refusing to install." >&2
  exit 1
fi
ACTUAL="$(sha256sum "$BIN" | awk '{print $1}')"
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "CHECKSUM MISMATCH for $ASSET — refusing to install." >&2
  echo "  expected: $EXPECTED" >&2
  echo "  actual:   $ACTUAL" >&2
  exit 1
fi

chmod +x "$BIN"

install -m 0755 "$BIN" /usr/local/bin/ceffio

echo "Ceffio $VERSION installed (checksum verified)."
exec /usr/local/bin/ceffio install "$@"
