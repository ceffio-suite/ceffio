// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package upgrade

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/backup"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// Execution options for an upgrade.
type Options struct {
	Domain    string
	BackupDir string
	Progress  func(string)
	// Appliquer replays the full deployment (idempotent). This is what
	// actually updates the images: each module's Deploy() targets the
	// version pinned in the registry.
	Appliquer func(ctx context.Context) error

	// ToujoursRejouer forces the apply phase even when the plan finds no version
	// drift in the registry.
	//
	// WHY: an upgrade is a CONVERGENCE, not only a version bump. The optional
	// modules installed after the fact keep an image that is not a registry
	// component — the plan cannot see it — and they follow the binary only if
	// the replay runs. Without this flag, a fully up-to-date core answers
	// "nothing to do" while a relay stays three releases behind.
	ToujoursRejouer bool
}

// Resultat reports what happened, including on failure.
type Resultat struct {
	Sauvegarde string   `json:"sauvegarde"`
	BackupOK   bool     `json:"backup_ok"`
	Applique   bool     `json:"applique"`
	Erreurs    []string `json:"erreurs,omitempty"`
	Rollback   string   `json:"rollback,omitempty"` // rollback instructions
}

// Executer applies the upgrade.
//
// Sequence, and why it is in this order:
//
//  1. The plan is rebuilt here (not passed by the caller): an upgrade must
//     not be able to start on a stale plan.
//  2. The backup happens BEFORE any modification. If it fails, we stop:
//     upgrading without a net is taking a risk no gain justifies.
//  3. The backup is VERIFIED. An unread archive is not a net.
//  4. The deployment is replayed (idempotent), which applies the new pinned
//     versions.
//  5. The state is re-read afterwards and compared to the plan: without
//     this re-read, we could not tell "the command succeeded" from "it
//     changed".
func Executer(ctx context.Context, cible []version.Composant, o Options) (*Resultat, error) {
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	res := &Resultat{}

	// 1. Fresh plan.
	o.Progress("preflight")
	plan := Preparer(ctx, cible)
	if !plan.Pret {
		res.Erreurs = append(res.Erreurs, plan.Blocages...)
		return res, fmt.Errorf("preflight refused: %s", strings.Join(plan.Blocages, " ; "))
	}
	if len(plan.Changements) == 0 && !o.ToujoursRejouer {
		o.Progress("no version drift: nothing to do")
		res.Applique = true
		return res, nil
	}
	if len(plan.Changements) == 0 {
		o.Progress("no version drift in the registry: replaying the installation")
	}

	// 2. Mandatory backup.
	dir := o.BackupDir
	if dir == "" {
		dir = "."
	}
	o.Progress("backup (mandatory before modification)")
	archive, err := backup.Sauvegarder(ctx, dir, func(e string) { o.Progress("  " + e) })
	if err != nil {
		res.Erreurs = append(res.Erreurs, "backup impossible: "+err.Error())
		return res, fmt.Errorf("upgrade cancelled: the backup failed (%w)", err)
	}
	res.Sauvegarde = archive

	// 3. Is the backup usable? An archive we cannot re-read protects from
	//    nothing.
	o.Progress("backup verification")
	man, err := backup.Verifier(archive)
	if err != nil || !man.Complete {
		msg := "unreadable archive"
		if err != nil {
			msg = err.Error()
		} else if len(man.Errors) > 0 {
			msg = strings.Join(man.Errors, " ; ")
		}
		res.Erreurs = append(res.Erreurs, "backup unusable: "+msg)
		return res, fmt.Errorf("upgrade cancelled: the backup is unusable (%s)", msg)
	}
	res.BackupOK = true
	res.Rollback = "ceffio restore " + archive

	// 4. Apply.
	o.Progress("applying the new versions")
	if o.Appliquer == nil {
		return res, fmt.Errorf("no apply action provided")
	}
	if err := o.Appliquer(ctx); err != nil {
		res.Erreurs = append(res.Erreurs, "application : "+err.Error())
		return res, fmt.Errorf("failure during apply — rollback possible with: %s (%w)",
			res.Rollback, err)
	}
	res.Applique = true

	// 5. Re-read: did the versions actually change?
	o.Progress("state verification after upgrade")
	time.Sleep(5 * time.Second) // let the new pods start
	apres := Preparer(ctx, cible)
	for _, e := range apres.Etats {
		if e.Nom == "" {
			continue
		}
	}
	if len(apres.Changements) > 0 {
		for _, c := range apres.Changements {
			res.Erreurs = append(res.Erreurs,
				fmt.Sprintf("%s : still on %s (target %s)", c.Nom, c.Installee, c.Cible))
		}
	}
	return res, nil
}

// ConsigneRetourArriere produces the text to hand to the user on failure:
// without this sentence, "there was a problem" is useless.
func ConsigneRetourArriere(res *Resultat) string {
	if res.Rollback == "" {
		return "no backup available: rollback is not possible"
	}
	var sb strings.Builder
	sb.WriteString("Rollback:\n")
	sb.WriteString("  " + res.Rollback + "\n")
	sb.WriteString("  then restart the applications (kubectl rollout restart)\n")
	return sb.String()
}

var _ = os.Getenv
