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

// Options d'exécution d'une mise à niveau.
type Options struct {
	Domain    string
	BackupDir string
	Progress  func(string)
	// Appliquer rejoue le déploiement complet (idempotent). C'est ce qui met
	// réellement à jour les images : chaque module Déploy() vise la version
	// épinglée dans le registre.
	Appliquer func(ctx context.Context) error
}

// Resultat rend compte de ce qui s'est passé, y compris en cas d'échec.
type Resultat struct {
	Sauvegarde string   `json:"sauvegarde"`
	BackupOK   bool     `json:"backup_ok"`
	Applique   bool     `json:"applique"`
	Erreurs    []string `json:"erreurs,omitempty"`
	Rollback   string   `json:"rollback,omitempty"` // consigne de retour arrière
}

// Executer applique la mise à niveau.
//
// Séquence, et pourquoi elle est dans cet ordre :
//
//  1. Le plan est reconstruit ici (et non passé par l'appelant) : une mise à
//     niveau ne doit pas pouvoir démarrer sur un plan périmé.
//  2. La sauvegarde passe AVANT toute modification. Si elle échoue, on s'arrête :
//     mettre à niveau sans filet, c'est prendre un risque qu'aucun gain ne
//     justifie.
//  3. La sauvegarde est VÉRIFIÉE. Une archive non lue n'est pas un filet.
//  4. Le déploiement est rejoué (idempotent), ce qui applique les nouvelles
//     versions épinglées.
//  5. L'état est relu après coup et comparé au plan : sans cette relecture, on
//     ne pourrait pas distinguer « la commande a réussi » de « ça a changé ».
func Executer(ctx context.Context, cible []version.Composant, o Options) (*Resultat, error) {
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	res := &Resultat{}

	// 1. Plan à jour.
	o.Progress("préflight")
	plan := Preparer(ctx, cible)
	if !plan.Pret {
		res.Erreurs = append(res.Erreurs, plan.Blocages...)
		return res, fmt.Errorf("préflight refusé : %s", strings.Join(plan.Blocages, " ; "))
	}
	if len(plan.Changements) == 0 {
		o.Progress("aucun écart de version : rien à faire")
		res.Applique = true
		return res, nil
	}

	// 2. Sauvegarde obligatoire.
	dir := o.BackupDir
	if dir == "" {
		dir = "."
	}
	o.Progress("sauvegarde (obligatoire avant modification)")
	archive, err := backup.Sauvegarder(ctx, dir, func(e string) { o.Progress("  " + e) })
	if err != nil {
		res.Erreurs = append(res.Erreurs, "sauvegarde impossible : "+err.Error())
		return res, fmt.Errorf("mise à niveau annulée : la sauvegarde a échoué (%w)", err)
	}
	res.Sauvegarde = archive

	// 3. La sauvegarde est-elle exploitable ? Une archive qu'on ne sait pas
	//    relire ne protège de rien.
	o.Progress("vérification de la sauvegarde")
	man, err := backup.Verifier(archive)
	if err != nil || !man.Complete {
		msg := "archive illisible"
		if err != nil {
			msg = err.Error()
		} else if len(man.Errors) > 0 {
			msg = strings.Join(man.Errors, " ; ")
		}
		res.Erreurs = append(res.Erreurs, "sauvegarde non exploitable : "+msg)
		return res, fmt.Errorf("mise à niveau annulée : la sauvegarde n'est pas exploitable (%s)", msg)
	}
	res.BackupOK = true
	res.Rollback = "ceffio restore " + archive

	// 4. Application.
	o.Progress("application des nouvelles versions")
	if o.Appliquer == nil {
		return res, fmt.Errorf("aucune action d'application fournie")
	}
	if err := o.Appliquer(ctx); err != nil {
		res.Erreurs = append(res.Erreurs, "application : "+err.Error())
		return res, fmt.Errorf("échec pendant l'application — retour arrière possible avec : %s (%w)",
			res.Rollback, err)
	}
	res.Applique = true

	// 5. Relecture : les versions ont-elles réellement changé ?
	o.Progress("vérification de l'état après mise à niveau")
	time.Sleep(5 * time.Second) // laisser les nouveaux pods démarrer
	apres := Preparer(ctx, cible)
	for _, e := range apres.Etats {
		if e.Nom == "" {
			continue
		}
	}
	if len(apres.Changements) > 0 {
		for _, c := range apres.Changements {
			res.Erreurs = append(res.Erreurs,
				fmt.Sprintf("%s : toujours en %s (cible %s)", c.Nom, c.Installee, c.Cible))
		}
	}
	return res, nil
}

// ConsigneRetourArriere produit le texte à remettre à l'utilisateur en cas
// d'échec : sans cette phrase, « il y a eu un problème » ne sert à rien.
func ConsigneRetourArriere(res *Resultat) string {
	if res.Rollback == "" {
		return "aucune sauvegarde disponible : le retour arrière n'est pas possible"
	}
	var sb strings.Builder
	sb.WriteString("Retour arrière :\n")
	sb.WriteString("  " + res.Rollback + "\n")
	sb.WriteString("  puis relancer les applications (kubectl rollout restart)\n")
	return sb.String()
}

var _ = os.Getenv
