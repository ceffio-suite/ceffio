// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"fmt"
	"io"
	"net/http"
)

// DomaineDuProjet is the domain whose installation speaks for the PROJECT.
//
// A security.txt says where to report a vulnerability IN THE SOFTWARE. Only the
// editor can say that: a customer who installs Ceffio on their own domain runs
// their own service, and their security contact is theirs — publishing ours
// would send a researcher to the wrong party, and make Mandem answer for an
// installation it does not operate.
const DomaineDuProjet = "ceffio.org"

// expirationSecurityTxt is the RFC 9116 `Expires` field, and it is a canary:
// a test refuses to ship this file when the date is less than a year away, so
// a stale security.txt fails the build instead of quietly outliving its author.
const expirationSecurityTxt = "2027-11-01T00:00:00.000Z"

// securityTxt is the content served on the project's own installation.
const securityTxt = `Contact: mailto:security@mandem-it.com
Expires: %s
Preferred-Languages: en, fr
Canonical: https://%s/.well-known/security.txt
Policy: https://github.com/ceffio-suite/ceffio/blob/main/SECURITY.md
`

// handleSecurityTxt serves /.well-known/security.txt (RFC 9116).
//
// ANSWERING 404 FOR EVERY OTHER DOMAIN IS DELIBERATE: a 403 would confirm that
// the route exists and is special, and would invite the question "why not me?".
// The honest answer is that this file is not part of the software's behaviour —
// it is out of scope unless the operator IS the editor.
func (s *Server) handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	if s.Domain != DomaineDuProjet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// A SECURITY CONTACT MAY CHANGE, and a cached copy is a contact that no
	// longer exists. One hour is short enough to fix a mistake, long enough not
	// to hit the console on every request.
	w.Header().Set("Cache-Control", "max-age=3600")
	_, _ = io.WriteString(w, fmt.Sprintf(securityTxt, expirationSecurityTxt, DomaineDuProjet))
}
