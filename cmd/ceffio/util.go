package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

func notImplemented(command string) error {
	return fmt.Errorf("command %q: not implemented yet (roadmap Phase 0+)", command)
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// namedTask is a named deployment step (for error logs).
type namedTask struct {
	name string
	run  func(context.Context) error
}

// runParallel executes independent steps IN PARALLEL and returns the first
// error encountered (canceling the sisters still in flight).
//
// Use only for genuinely independent steps: a phase that writes into another
// app (occ in Nextcloud, kcadm in Keycloak) must stay sequential after it.
//
// A progress signal is emitted at launch, then each step announces its end
// with its duration — essential for diagnosing a long run.
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
			fmt.Printf("   ├─ %s : started\n", t.name)
			start := time.Now()
			if err := t.run(ctx); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", t.name, err)
					cancel() // stops the sister tasks still in flight
				}
				mu.Unlock()
				fmt.Fprintf(os.Stderr, "   └─ %s : FAILED (%s)\n", t.name, time.Since(start).Round(time.Second))
				return
			}
			fmt.Printf("   └─ %s : OK (%s)\n", t.name, time.Since(start).Round(time.Second))
		}()
	}
	wg.Wait()
	return firstErr
}
