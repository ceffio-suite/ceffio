#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © MANDEM
#
# Applies the Ceffio theme to the Nextcloud of a running Ceffio installation.
#
# Uses only the built-in Theming app (occ theming:config): no theme folder, no
# custom CSS, nothing that a Nextcloud upgrade can overwrite. Idempotent: run it
# again at any time, it sets the same values.
#
# Usage:
#   ./apply-theming.sh                      # defaults below
#   CEFFIO_URL=https://ceffio.example.org ./apply-theming.sh
#   CEFFIO_IMPRINT_URL=… CEFFIO_PRIVACY_URL=… ./apply-theming.sh
set -euo pipefail

NS="${NS:-ceffio-files}"
DEPLOY="${DEPLOY:-deploy/nextcloud}"
CONTAINER="${CONTAINER:-nextcloud}"
DIR="$(cd "$(dirname "$0")" && pwd)"
DEST=/tmp/ceffio-theme

NAME="${CEFFIO_NAME:-Ceffio}"
SLOGAN="${CEFFIO_SLOGAN:-La suite collaborative souveraine}"
URL="${CEFFIO_URL:-https://github.com/ceffio-suite/ceffio}"
PRIMARY="${CEFFIO_PRIMARY:-#2B4FD8}"      # buttons, links, focus
BACKGROUND="${CEFFIO_BACKGROUND:-#12151C}" # ground behind the background image

kx() { kubectl -n "$NS" exec -i "$DEPLOY" -c "$CONTAINER" -- "$@"; }
occ() { kx php occ "$@"; }

echo "∙ copying the theme images into the Nextcloud pod"
kx mkdir -p "$DEST"
for f in logo.svg logoheader.svg favicon.png background.jpg; do
  kx sh -c "cat > $DEST/$f && chmod 0644 $DEST/$f" < "$DIR/$f"
done

echo "∙ texts and colours"
occ theming:config name "$NAME"
occ theming:config slogan "$SLOGAN"
occ theming:config url "$URL"
occ theming:config primary_color "$PRIMARY"
occ theming:config background_color "$BACKGROUND"
[ -n "${CEFFIO_IMPRINT_URL:-}" ] && occ theming:config imprintUrl "$CEFFIO_IMPRINT_URL"
[ -n "${CEFFIO_PRIVACY_URL:-}" ] && occ theming:config privacyUrl "$CEFFIO_PRIVACY_URL"

echo "∙ images"
# Image keys take an ABSOLUTE path inside the container.
occ theming:config logo "$DEST/logo.svg"
occ theming:config logoheader "$DEST/logoheader.svg"
# PNG, not SVG: Nextcloud only accepts an SVG favicon when ImageMagick has SVG
# support, which the official image does not guarantee.
occ theming:config favicon "$DEST/favicon.png"
# JPEG, not SVG: Nextcloud derives the text colour over the background from
# the image itself, which needs a raster image.
occ theming:config background "$DEST/background.jpg"

kx rm -rf "$DEST"
echo "✓ Ceffio theme applied"
