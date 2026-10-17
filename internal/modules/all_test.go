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

// racineDepot remonte depuis CE fichier jusqu'à la racine du dépôt (celle qui
// contient go.mod). On l'identifie par go.mod plutôt que par un nombre de
// « .. » figé : déplacer ce test ne le casserait pas silencieusement.
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

// packagesQuiEnregistrent parcourt toutes les sources Go du dépôt (hors
// fichiers _test.go : le registre y manipule des modules factices) et renvoie
// le chemin d'import de chaque package qui appelle module.Register.
//
// POURQUOI go/parser ET PAS UN GREP : un grep sur « module.Register »
// attraperait les commentaires, les chaînes et les homonymes ; l'AST, lui,
// ne retient que les appels réels, avec l'alias d'import réellement utilisé
// (qui peut ne pas être « module »).
func packagesQuiEnregistrent(t *testing.T, racine string) map[string]bool {
	t.Helper()
	trouves := map[string]bool{}

	err := filepath.WalkDir(racine, func(chemin string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			nom := d.Name()
			// Ni les dépendances, ni les artefacts : seuls nos sources.
			if nom == "vendor" || nom == "bin" || nom == ".git" || nom == "node_modules" {
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
		// Le nom local sous lequel internal/module est importé dans CE
		// fichier (« module », ou un alias).
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

		// Il faut maintenant le fichier COMPLET pour parcourir les appels.
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

// importsDeAllGo renvoie les chemins importés (blank ou non) par all.go.
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

// TestToutModuleEstImporteDansAllGo est le GARDE-FOU du registre.
//
// POURQUOI CE TEST EXISTE : un module qui appelle module.Register dans son
// init() mais que personne n'importe ne s'enregistre JAMAIS — et Go ne dit
// rien. L'oubli serait parfaitement silencieux : le module disparaîtrait du
// CLI et de la console sans aucune erreur nulle part. Ce test rend l'oubli
// bruyant, dès `make test`.
func TestToutModuleEstImporteDansAllGo(t *testing.T) {
	racine := racineDepot(t)
	enregistres := packagesQuiEnregistrent(t, racine)
	imports := importsDeAllGo(t, racine)

	if len(enregistres) == 0 {
		t.Fatal("no package calling module.Register was found — the walk is broken, not the registry empty")
	}

	for chemin := range enregistres {
		if chemin == cheminModule+"/internal/module" {
			continue // le package du registre lui-même (définition, pas usage)
		}
		if !imports[chemin] {
			t.Errorf("package %s registers a module but is not imported in internal/modules/all.go: its init() would never run", chemin)
		}
	}
}

// TestLeRegistreContientLesTroisModules vérifie, par l'exécution réelle des
// init() (ce package importe all.go, donc tous les modules), que le catalogue
// attendu est bien là.
func TestLeRegistreContientLesTroisModules(t *testing.T) {
	for _, id := range []string{"exapps-daemon", "live-transcription", "recording"} {
		if _, ok := module.Get(id); !ok {
			t.Errorf("module %q is not registered", id)
		}
	}
}
