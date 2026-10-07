package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// Restaurer remet en place une sauvegarde.
//
// Ordre imposé par les dépendances, et non par confort :
//  1. les Secrets d'abord — les bases restaurées ne servent à rien si les mots
//     de passe applicatifs ne correspondent plus ;
//  2. les bases ensuite — identités, comptes, métadonnées ;
//  3. les volumes enfin — les documents, qui référencent les métadonnées.
//
// La restauration des bases est DESTRUCTIVE (pg_restore --clean) : l'appelant
// doit avoir confirmé. Le CLI s'en charge, cette fonction ne le fait pas à sa
// place — mais elle le dit dans son rapport.
func Restaurer(ctx context.Context, archive string, progress func(string)) (*Manifest, error) {
	if progress == nil {
		progress = func(string) {}
	}

	// Vérification avant tout : restaurer une archive incomplète ne ferait
	// qu'ajouter une panne à la panne.
	man, err := Verifier(archive)
	if err != nil {
		return nil, err
	}
	if len(man.Errors) > 0 {
		return man, fmt.Errorf("archive incomplète ou altérée : %s", strings.Join(man.Errors, " ; "))
	}

	work, err := os.MkdirTemp("", "ceffio-restore-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	if err := decompress(archive, work); err != nil {
		return nil, err
	}

	pod := pgPodName(ctx)
	if pod == "" {
		return man, fmt.Errorf("pod PostgreSQL introuvable : impossible de restaurer les bases")
	}

	// 1. Secrets.
	progress("secrets applicatifs")
	if err := restoreSecrets(ctx, filepath.Join(work, "secrets/applicatifs.json"), &man.Errors); err != nil {
		man.Errors = append(man.Errors, "secrets : "+err.Error())
	}

	// 2. Bases.
	for _, e := range man.Entries {
		if e.Kind != "base" {
			continue
		}
		progress("base " + e.Name)
		if err := restoreBase(ctx, pod, e.Name, filepath.Join(work, e.File)); err != nil {
			man.Errors = append(man.Errors, fmt.Sprintf("base %s : %v", e.Name, err))
		}
	}

	// 3. Volumes.
	for _, e := range man.Entries {
		if e.Kind != "volume" {
			continue
		}
		v, ok := volumeByName(e.Name)
		if !ok {
			man.Errors = append(man.Errors, "volume inconnu : "+e.Name)
			continue
		}
		progress("volume " + e.Name)
		podName := podFor(ctx, v.Namespace, v.PodLabel)
		if podName == "" {
			man.Errors = append(man.Errors, fmt.Sprintf("volume %s : aucun pod %s", e.Name, v.PodLabel))
			continue
		}
		if err := restoreVolume(ctx, v, podName, filepath.Join(work, e.File)); err != nil {
			man.Errors = append(man.Errors, fmt.Sprintf("volume %s : %v", e.Name, err))
		}
	}

	man.Complete = len(man.Errors) == 0
	return man, nil
}

func volumeByName(name string) (Volume, bool) {
	for _, v := range Volumes {
		if v.PVC == name {
			return v, true
		}
	}
	return Volume{}, false
}

// restoreSecrets réapplique les Secrets, en créant les namespaces manquants.
func restoreSecrets(ctx context.Context, path string, errs *[]string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("fichier de secrets absent de l'archive")
	}
	var doc struct {
		Secrets []struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Data      map[string]string `json:"data"`
		} `json:"secrets"`
		Manquants []string `json:"manquants"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	// Les secrets absents de la sauvegarde correspondent à des couches non
	// installées au moment du backup (ex. la visio sans --video). Ce n'est pas
	// une erreur de restauration : on le signale sans bloquer.
	if len(doc.Manquants) > 0 {
		fmt.Printf("  (secrets non présents dans la sauvegarde : %s)\n", strings.Join(doc.Manquants, ", "))
	}
	for _, s := range doc.Secrets {
		// Le namespace peut ne pas exister sur une machine reconstruite à neuf.
		kubectlOut(ctx, "create", "namespace", s.Namespace)

		// Remplacement franc plutôt que `kubectl apply` : apply refuse un objet
		// créé impérativement (annotation last-applied-configuration absente).
		// Or c'est précisément le cas ici — les Secrets ont été créés par
		// `kubectl create secret` lors de l'installation. On supprime puis on
		// recrée, ce qui remet EXACTEMENT l'état sauvegardé.
		kubectlOut(ctx, "delete", "secret", s.Name, "-n", s.Namespace, "--ignore-not-found")

		obj := map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata":   map[string]any{"name": s.Name, "namespace": s.Namespace},
			"type":       "Opaque",
			"data":       s.Data,
		}
		b, _ := json.Marshal(obj)
		cmd := k8s.Command(ctx, "kubectl", "create", "-f", "-")
		cmd.Stdin = strings.NewReader(string(b))
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := oneLine(stderr.String())
			// « AlreadyExists » ne peut plus arriver après le delete, mais on
			// tolère tout message de succès partiel.
			if !strings.Contains(msg, "AlreadyExists") {
				*errs = append(*errs, fmt.Sprintf("secret %s/%s : %s", s.Namespace, s.Name, msg))
			}
		}
	}
	return nil
}

// restoreBase recharge un dump dans sa base.
//
// La base cible est recréée : pg_dump a été pris avec --clean --if-exists, donc
// le dump supprime puis recrée les objets. On ne fait PAS DROP DATABASE : une
// base absente est créée si besoin, sinon son contenu est remplacé objet par
// objet — approche moins brutale, qui laisse la base en place si la
// restauration échoue au milieu.
func restoreBase(ctx context.Context, pod, base, dumpPath string) error {
	f, err := os.Open(dumpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// La base doit exister pour recevoir le dump.
	if strings.TrimSpace(query(ctx, pod, "postgres",
		"SELECT 1 FROM pg_database WHERE datname='"+base+"'")) != "1" {
		if err := execSQL(ctx, pod, "postgres", "CREATE DATABASE "+quoteIdent(base)); err != nil {
			return fmt.Errorf("création de la base : %w", err)
		}
	}

	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres", "-n", "ceffio-data", pod,
		"--", "psql", "-U", "postgres", "-d", base, "-v", "ON_ERROR_STOP=1", "-q")
	cmd.Stdin = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rechargement : %w : %s", err, oneLine(stderr.String()))
	}
	return nil
}

func execSQL(ctx context.Context, pod, db, sql string) error {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres", "-n", "ceffio-data", pod,
		"--", "psql", "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-q")
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w : %s", err, oneLine(string(out)))
	}
	return nil
}

// quoteIdent protège un nom d'identifiant SQL (les noms de bases sont fixes
// dans ce programme, mais la fonction est réutilisable sans piège).
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// restoreVolume réinjecte un tar dans le pod correspondant.
//
// Deux problèmes réels rencontrés en test, et leur solution :
//
//  1. Le tar a été pris en root, l'extraction se fait avec l'utilisateur du
//     conteneur → `--no-same-owner` évite qu'il tente de restaurer la propriété.
//  2. Extraire directement dans le point de montage fait échouer tar sur « . »
//     (utime/mode interdits sur le répertoire racine du volume monté) et tar
//     sort en code 2 — alors que les fichiers, eux, sont bien écrits.
//
// Solution : extraire dans un sous-répertoire temporaire DU MÊME volume, puis
// copier le contenu à sa place. On reste dans le volume (donc pas de question de
// place), et le point de montage n'est jamais touché directement.
func restoreVolume(ctx context.Context, v Volume, pod, tarPath string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	const staging = ".ceffio-restore"
	script := "set -e; " +
		"rm -rf " + v.Path + "/" + staging + "; " +
		"mkdir -p " + v.Path + "/" + staging + "; " +
		"tar xzf - --no-same-owner -C " + v.Path + "/" + staging + "; " +
		"cp -R " + v.Path + "/" + staging + "/. " + v.Path + "/; " +
		"rm -rf " + v.Path + "/" + staging

	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-n", v.Namespace, pod, "--", "sh", "-c", script)
	cmd.Stdin = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("extraction : %w : %s", err, oneLine(stderr.String()))
	}
	return nil
}
