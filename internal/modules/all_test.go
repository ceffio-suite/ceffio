// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package modules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

const cheminModule = "github.com/ceffio-suite/ceffio"

// racineDepot walks up from THIS file to the repository root (the one
// containing go.mod). It is identified by go.mod rather than by a fixed
// number of "..": moving this test would not break it silently.
func racineDepot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory unreadable: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found: the test is not running inside the repository")
		}
		dir = parent
	}
}

// packagesQuiEnregistrent walks every Go source of the repository (excluding
// _test.go files: the registry handles fake modules there) and returns the
// import path of each package that calls module.Register.
//
// WHY go/parser AND NOT A GREP: a grep on "module.Register" would catch
// comments, strings and homonyms; the AST, on the other hand, only keeps the
// real calls, with the import alias actually used (which may not be
// "module").
func packagesQuiEnregistrent(t *testing.T, racine string) map[string]bool {
	t.Helper()
	trouves := map[string]bool{}

	err := filepath.WalkDir(racine, func(chemin string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			nom := d.Name()
			// Neither dependencies nor artifacts: only our sources.
			// .gomodcache / .gopath / .cachego: the caches some environments
			// keep INSIDE the repository (a sandbox that cannot write $HOME).
			// Walking them parses the Go toolchain's own testdata — files that
			// are deliberately invalid — and reports a dozen parse errors that
			// have nothing to do with this project.
			if nom == "vendor" || nom == "bin" || nom == ".git" || nom == "node_modules" ||
				nom == ".gomodcache" || nom == ".gopath" || nom == ".cachego" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(chemin, ".go") || strings.HasSuffix(chemin, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		fichier, err := parser.ParseFile(fset, chemin, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parsing %s: %v", chemin, err)
			return nil
		}
		// The local name under which internal/module is imported in THIS
		// file ("module", or an alias).
		nomLocal := ""
		for _, imp := range fichier.Imports {
			if imp.Path.Value == `"`+cheminModule+`/internal/module"` {
				nomLocal = "module"
				if imp.Name != nil {
					nomLocal = imp.Name.Name
				}
			}
		}
		if nomLocal == "" {
			return nil
		}

		// We now need the COMPLETE file to walk the calls.
		fichier, err = parser.ParseFile(fset, chemin, nil, 0)
		if err != nil {
			t.Errorf("parsing %s: %v", chemin, err)
			return nil
		}
		enregistre := false
		ast.Inspect(fichier, func(n ast.Node) bool {
			appel, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := appel.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == nomLocal && sel.Sel.Name == "Register" {
				enregistre = true
			}
			return true
		})
		if enregistre {
			rel, err := filepath.Rel(racine, filepath.Dir(chemin))
			if err != nil {
				return err
			}
			trouves[cheminModule+"/"+filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	return trouves
}

// importsDeAllGo returns the paths imported (blank or not) by all.go.
func importsDeAllGo(t *testing.T, racine string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	fichier, err := parser.ParseFile(fset, filepath.Join(racine, "internal", "modules", "all.go"), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing internal/modules/all.go: %v", err)
	}
	imports := map[string]bool{}
	for _, imp := range fichier.Imports {
		imports[strings.Trim(imp.Path.Value, `"`)] = true
	}
	return imports
}

// TestToutModuleEstImporteDansAllGo is the GUARDRAIL of the registry.
//
// WHY THIS TEST EXISTS: a module that calls module.Register in its init()
// but that nobody imports NEVER registers — and Go says nothing. The
// omission would be perfectly silent: the module would disappear from the
// CLI and the console with no error anywhere. This test makes the omission
// loud, as early as `make test`.
func TestToutModuleEstImporteDansAllGo(t *testing.T) {
	racine := racineDepot(t)
	enregistres := packagesQuiEnregistrent(t, racine)
	imports := importsDeAllGo(t, racine)

	if len(enregistres) == 0 {
		t.Fatal("no package calling module.Register was found — the walk is broken, not the registry empty")
	}

	for chemin := range enregistres {
		if chemin == cheminModule+"/internal/module" {
			continue // the registry package itself (definition, not usage)
		}
		if !imports[chemin] {
			t.Errorf("package %s registers a module but is not imported in internal/modules/all.go: its init() would never run", chemin)
		}
	}
}

// TestLeRegistreContientLesTroisModules verifies, through the actual
// execution of the init() (this package imports all.go, hence every module),
// that the expected catalog is there.
func TestLeRegistreContientLesTroisModules(t *testing.T) {
	for _, id := range []string{"exapps-daemon", "live-transcription", "recording"} {
		if _, ok := module.Get(id); !ok {
			t.Errorf("module %q is not registered", id)
		}
	}
}
