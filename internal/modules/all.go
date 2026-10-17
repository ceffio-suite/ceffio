// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package modules n'abrite aucune logique : il existe uniquement pour que Go
// exécute les init() de chaque module.
//
// POURQUOI CE FICHIER EXISTE : chaque module s'enregistre lui-même dans le
// registre global depuis un func init() dans son propre package. Or Go
// n'exécute les init() que des packages réellement importés par le binaire —
// un module que personne n'importe ne s'enregistrerait JAMAIS, et son absence
// serait totalement silencieuse (pas d'erreur, juste un module introuvable).
// Ces imports blank (« _ ») forcent l'exécution des init() sans référencer
// aucun symbole ; les deux frontaux (CLI, console) n'ont plus qu'à importer
// ce package unique pour voir tout le catalogue.
//
// Le test all_test.go est le garde-fou : il vérifie que tout package appelant
// module.Register figure bien ici.
package modules

import (
	_ "github.com/ceffio-suite/ceffio/internal/modules/exappsdaemon"
	_ "github.com/ceffio-suite/ceffio/internal/modules/recording"
	_ "github.com/ceffio-suite/ceffio/internal/modules/transcription"
)
