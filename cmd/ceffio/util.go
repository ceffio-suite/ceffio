package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

func notImplemented(command string) error {
	return fmt.Errorf("commande %q : pas encore implémentée (roadmap Phase 0+)", command)
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// namedTask est une étape de déploiement nommée (pour les logs d'erreur).
type namedTask struct {
	name string
	run  func(context.Context) error
}

// runParallel exécute des étapes indépendantes EN PARALLÈLE et retourne la
// première erreur rencontrée (en annulant les sœurs encore en vol).
//
// À n'utiliser que pour des étapes réellement indépendantes : une phase qui
// écrit dans une autre app (occ dans Nextcloud, kcadm dans Keycloak) doit
// rester séquentielle après elle.
//
// Un signal de progression est émis au lancement, puis chaque étape annonce sa
// fin avec sa durée — indispensable pour diagnostiquer un run long.
func runParallel(ctx context.Context, tasks ...namedTask) error {
	if len(tasks) == 0 {
		return nil
	}
	if len(tasks) == 1 {
		return tasks[0].run(ctx)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	for _, t := range tasks {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("   ├─ %s : démarré\n", t.name)
			start := time.Now()
			if err := t.run(ctx); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", t.name, err)
					cancel() // arrête les tâches sœurs encore en vol
				}
				mu.Unlock()
				fmt.Fprintf(os.Stderr, "   └─ %s : ÉCHEC (%s)\n", t.name, time.Since(start).Round(time.Second))
				return
			}
			fmt.Printf("   └─ %s : OK (%s)\n", t.name, time.Since(start).Round(time.Second))
		}()
	}
	wg.Wait()
	return firstErr
}
