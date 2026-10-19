# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © MANDEM
#
# Builds the Ceffio Nextcloud theme assets.
import sys
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

font_path, out = sys.argv[1], sys.argv[2]
f = TTFont(font_path)
gs = f.getGlyphSet(); cmap = f.getBestCmap(); upm = f['head'].unitsPerEm

def word_path(text, size, x0, baseline, tracking_em):
    s = size / upm
    pen = SVGPathPen(gs)
    x = 0.0
    xmax = 0
    for ch in text:
        g = cmap[ord(ch)]
        tp = TransformPen(pen, (s, 0, 0, -s, x0 + x * s, baseline))
        gs[g].draw(tp)
        x += gs[g].width + tracking_em * upm
    return pen.getCommands(), x0 + (x - tracking_em * upm) * s

ID, FILES, DOCS, TALK, INK, PAPER = '#6A3FC8', '#0B8A6F', '#2B4FD8', '#F28C28', '#12151C', '#F6F5F1'
# Lighter variants for dark grounds (readable on #12151C)
ID_L, FILES_L, DOCS_L, TALK_L = '#9A7BEA', '#2DBB98', '#6F8CFF', '#F5A55A'

def mark(cursor, sw=16, colors=(ID, FILES, DOCS, TALK)):
    c = colors
    return (f'<path d="M85.71 29.36 A40 40 0 0 0 46.98 22.18" fill="none" stroke="{c[0]}" stroke-width="{sw}"/>'
            f'<path d="M41.84 24.36 A40 40 0 0 0 20.10 57.21" fill="none" stroke="{c[1]}" stroke-width="{sw}"/>'
            f'<path d="M20.10 62.79 A40 40 0 0 0 41.84 95.64" fill="none" stroke="{c[2]}" stroke-width="{sw}"/>'
            f'<path d="M46.98 97.82 A40 40 0 0 0 85.71 90.64" fill="none" stroke="{c[3]}" stroke-width="{sw}"/>'
            f'<rect x="93" y="46" width="8" height="28" rx="2" fill="{cursor}"/>')

def svg(w, h, body, label):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'role="img" aria-label="{label}">{body}</svg>\n')

# Wordmark: mark 120 + gap 22 + text at size 104 (x-height matches the mark)
d, xend = word_path('ceffio', 104, 142, 92, -0.045)
W = int(xend + 8)
lockup_light = svg(W, 120, mark('#FFFFFF', colors=(ID_L, FILES_L, DOCS_L, TALK_L)) + f'<path d="{d}" fill="#FFFFFF"/>', 'Ceffio')
lockup_ink = svg(W, 120, mark(INK) + f'<path d="{d}" fill="{INK}"/>', 'Ceffio')
open(f'{out}/logo.svg', 'w').write(lockup_light)
open(f'{out}/logo-ink.svg', 'w').write(lockup_ink)
open(f'{out}/logoheader.svg', 'w').write(svg(120, 120, mark('#FFFFFF', colors=(ID_L, FILES_L, DOCS_L, TALK_L)), 'Ceffio'))
fav = '<rect x="0" y="0" width="120" height="120" rx="27" fill="#FFFFFF"/><g transform="translate(9 9) scale(0.85)">' + mark(INK, sw=17) + '</g>'
open(f'{out}/favicon.svg', 'w').write(svg(120, 120, fav, 'Ceffio'))

# Background: ink ground, one oversized ring bleeding off the right edge, faint grid.
bg = [f'<rect width="2560" height="1440" fill="{INK}"/>']
bg.append('<defs><pattern id="g" width="64" height="64" patternUnits="userSpaceOnUse">'
          '<path d="M64 0H0V64" fill="none" stroke="#FFFFFF" stroke-opacity="0.035" stroke-width="1"/></pattern>'
          '<radialGradient id="v" cx="0.3" cy="0.45" r="0.9"><stop offset="0" stop-color="#1D2330"/>'
          f'<stop offset="1" stop-color="{INK}" stop-opacity="0"/></radialGradient></defs>')
bg.append('<rect width="2560" height="1440" fill="url(#v)"/><rect width="2560" height="1440" fill="url(#g)"/>')
bg.append('<g transform="translate(1640 -80) scale(13.5)" opacity="0.22">' +
          mark('#FFFFFF', sw=16, colors=(ID_L, FILES_L, DOCS_L, TALK_L)) + '</g>')
open(f'{out}/background.svg', 'w').write(svg(2560, 1440, ''.join(bg), 'Fond Ceffio'))
print('wordmark width', W)
