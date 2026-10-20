// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package theming

import (
	"bytes"
	imgo "image"
	_ "image/jpeg" // registers the JPEG decoder for the background
	"image/png"
	"testing"
)

// TestLeFondNeFinitPasSurUneBandeNoire guards against a regression that shipped
// once: the Nextcloud background had a black band about 80 px high along the
// bottom edge, from a generation mistake.
//
// IT IS MEASURED, NOT DESCRIBED. The defect is a property of the pixels — the last
// rows are black — so the test reads the pixels. A file-existence test or a
// checksum would have passed on the broken image, which is exactly what happened.
//
// THE THRESHOLD IS READ FROM THE ASSET, so an intentional redesign that darkens the
// bottom of the image still passes as long as it is not literally black: the
// failure this catches is an unfilled area, not a taste in colour.
func TestLeFondNeFinitPasSurUneBandeNoire(t *testing.T) {
	brut, err := assets.ReadFile("assets/background.jpg")
	if err != nil {
		t.Fatalf("the background is missing from the embedded assets: %v", err)
	}

	img, _, err := imgo.Decode(bytes.NewReader(brut))
	if err != nil {
		t.Fatalf("the background does not decode: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != 2560 || b.Dy() != 1440 {
		t.Errorf("the background is %d×%d, expected 2560×1440: the theme grid is drawn "+
			"for that size, and a different one is scaled and crops", b.Dx(), b.Dy())
	}

	// THE LAST 40 ROWS, WHICH IS WHERE THE BAND WAS. Reading 40 is enough to catch
	// it and cheap enough to run on every commit; the original band was ~80 px.
	const lignes = 40
	if b.Dy() < lignes {
		t.Fatalf("the image is %d px high, too small to check its bottom edge", b.Dy())
	}

	var somme float64
	var n int
	for y := b.Max.Y - lignes; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			// Standard luminance weights, on 8-bit values.
			somme += 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(bl>>8)
			n++
		}
	}
	moyenne := somme / float64(n)

	// A LITERAL BLACK BAND GIVES 0.0 — measured on the broken asset. Anything above
	// 10 is a real image: dark grey, a photograph in shadow, a gradient.
	if moyenne <= 10 {
		t.Errorf("the bottom %d rows have a mean luminance of %.1f, which is black.\n"+
			"The background shipped once with a black band about 80 px high along the "+
			"bottom edge, from a generation mistake: the image was cropped short and "+
			"padded rather than resized. Check the asset against the one in "+
			"branding/nextcloud/, which is the source of truth.", lignes, moyenne)
	}
}

// TestLIconeNEstPasCoupee guards the second defect that shipped: the favicon was
// drawn on a 425 px tall surface inside a 512×512 canvas, so the bottom of the logo
// was cut off and the rest sat on transparency.
//
// THE CHECK IS THE BOUNDING BOX of the non-transparent pixels: a full 512×512 box
// means the artwork reaches every edge. A smaller box means part of the canvas was
// never drawn — which is what "cropped" looks like in a PNG.
func TestLIconeNEstPasCoupee(t *testing.T) {
	brut, err := assets.ReadFile("assets/favicon.png")
	if err != nil {
		t.Fatalf("the favicon is missing from the embedded assets: %v", err)
	}

	img, err := png.Decode(bytes.NewReader(brut))
	if err != nil {
		t.Fatalf("the favicon does not decode as PNG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != 512 || b.Dy() != 512 {
		t.Errorf("the favicon is %d×%d, expected 512×512", b.Dx(), b.Dy())
	}

	// The bounding box of the alpha channel is the artwork's extent.
	minX, minY, maxX, maxY := b.Max.X, b.Max.Y, b.Min.X, b.Min.Y
	trouve := false
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := img.At(x, y).RGBA()
			if a == 0 {
				continue
			}
			trouve = true
			if x < minX {
				minX = x
			}
			if y < minY {
				minY = y
			}
			if x > maxX {
				maxX = x
			}
			if y > maxY {
				maxY = y
			}
		}
	}
	if !trouve {
		t.Fatal("the favicon is entirely transparent")
	}

	larg, haut := maxX-minX+1, maxY-minY+1
	if larg != 512 || haut != 512 {
		t.Errorf("the artwork covers %d×%d of a 512×512 canvas, starting at (%d,%d).\n"+
			"It shipped once at 512×425: drawn on a shorter surface and never extended "+
			"to the bottom, so the logo was cut off and the rest sat on transparency. "+
			"Check the asset against branding/nextcloud/favicon.png.",
			larg, haut, minX, minY)
	}
}
