// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package backup

import (
	"context"
	"io"
	"strings"
	"testing"
)

// kubectlFactice stands in for the cluster in the mail-volume and vault tests.
//
// WHY THIS EXISTS: those two paths are the only ones in this package that must
// be exercised WITHOUT a cluster — a stop-the-server copy and a vault dump are
// exactly the operations that cannot be rehearsed on the demo host (the host
// where the maintainer's mail is live). The seam is executerKubectl; the fake
// records every call (arguments and stdin) so the tests can assert on what was
// asked of kubectl, not merely on the returned error.
type kubectlFactice struct {
	repondre func(args []string, entree string) (string, error)
	appels   []appelKubectl
}

type appelKubectl struct {
	Args   []string
	Entree string
}

func (f *kubectlFactice) executer(_ context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	entree := ""
	if stdin != nil {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		entree = string(b)
	}
	f.appels = append(f.appels, appelKubectl{Args: args, Entree: entree})
	sortie, err := f.repondre(args, entree)
	if stdout != nil && sortie != "" {
		if _, werr := io.WriteString(stdout, sortie); werr != nil {
			return werr
		}
	}
	return err
}

// installerFauxKubectl puts the fake in place of the seam and restores the real
// one when the test ends. The real one shells out to kubectl, so a test that
// forgot to restore it would try to reach a cluster from the test process.
func installerFauxKubectl(t *testing.T, f *kubectlFactice) {
	t.Helper()
	ancien := executerKubectl
	executerKubectl = f.executer
	t.Cleanup(func() { executerKubectl = ancien })
}

// aFait says whether a command with these leading arguments was run at least
// once.
func (f *kubectlFactice) aFait(prefixe ...string) bool {
	for _, a := range f.appels {
		if commencePar(a.Args, prefixe) {
			return true
		}
	}
	return false
}

// commandes renvoie, dans l'ordre, les commandes dont les arguments commencent
// par prefixe.
func (f *kubectlFactice) commandes(prefixe ...string) [][]string {
	var out [][]string
	for _, a := range f.appels {
		if commencePar(a.Args, prefixe) {
			out = append(out, a.Args)
		}
	}
	return out
}

func commencePar(args, prefixe []string) bool {
	if len(args) < len(prefixe) {
		return false
	}
	for i := range prefixe {
		if args[i] != prefixe[i] {
			return false
		}
	}
	return true
}

func argsEnTexte(args []string) string {
	return strings.Join(args, " ")
}
