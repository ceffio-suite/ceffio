// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package office

import (
	"strings"
	"testing"
)

// TestOfficeServiceSeTermineParUnSlash locks the trailing slash on the internal
// ONLYOFFICE address.
//
// WHY THIS IS WORTH A TEST: the connector builds its conversion URL by
// CONCATENATION — `$documentServerUrl . "converter"` in DocumentService.php.
// Without the slash the result is "…svcconverter", an unresolvable host, so
// every document conversion fails (thumbnails, previews, PDF export, markdown
// to JPG) while opening an editor keeps working, because the editor uses a
// different path.
//
// The failure is expensive to diagnose: Nextcloud shows "ONLYOFFICE
// indisponible" and the log fills with "cURL error 6: Could not resolve host",
// neither of which points at a missing slash. Nothing in the code fails to
// compile, and the address looks correct to the eye — which is exactly why the
// rule is written down here and not only in a comment.
//
// MEASURED, on a live installation: the internal URL without the slash produced
// "…svcconverter?shardkey=thumb_…" and every conversion failed. With the slash,
// the same request reaches the Document Server.
func TestOfficeServiceSeTermineParUnSlash(t *testing.T) {
	if !strings.HasSuffix(officeService, "/") {
		t.Errorf("officeService = %q: must end with a slash — the connector "+
			"concatenates it with \"converter\" and would build %q",
			officeService, officeService+"converter")
	}
}

// TestUrlDeConversionEstBienFormee applies the connector's concatenation to the
// address we write, and checks the result is the URL we expect.
//
// The rule above is stated as an invariant; this test reproduces the ACTUAL
// consumer, so that a future change that keeps the slash but alters the address
// (a path prefix, a port) is still checked against what the connector does with
// it.
func TestUrlDeConversionEstBienFormee(t *testing.T) {
	// This is DocumentService.php:135, verbatim:
	//     $urlToConverter = $documentServerUrl . "converter";
	obtenu := officeService + "converter"

	attendu := "http://onlyoffice.ceffio-office.svc/converter"
	if obtenu != attendu {
		t.Errorf("the connector would request %q, expected %q", obtenu, attendu)
	}
	if strings.Contains(obtenu, "svcconverter") {
		t.Errorf("the connector would request %q: missing separator between "+
			"the host and the path", obtenu)
	}
}
