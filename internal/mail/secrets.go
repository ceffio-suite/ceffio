// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package mail

// scriptAvecSecrets sources the secrets the OpenBao injector wrote, then runs
// the given command.
//
// WHY THIS EXISTS, and why every `kubectl exec` into Stalwart must use it:
// the injector writes /secrets/env, and the CONTAINER'S OWN command sources it
// for the Stalwart process. A `kubectl exec` opens a NEW shell that inherits
// nothing of that environment. A command reading $STALWART_RECOVERY_ADMIN
// without this prefix therefore sees an empty value: curl is called with an
// empty -u, prompts for a password it cannot read, and the API answers 401 —
// which reads like a wrong credential rather than a missing source, and cost
// a production deployment to diagnose.
//
// `set -a` exports everything the file defines, so later commands in the same
// shell see the values. Only the NAMES reach the process table; the values
// never appear on a command line.
//
// If the file is absent (an injector that never ran), the source fails
// silently and the command runs without credentials — failing loudly on the
// 401 instead of pretending to succeed.
func scriptAvecSecrets(commande string) string {
	return `set -a; . /secrets/env 2>/dev/null; set +a; ` + commande
}
