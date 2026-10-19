// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
)

func notImplemented(command string) error {
	return fmt.Errorf("command %q: not implemented yet (roadmap Phase 0+)", command)
}

// joinOuNone renders a list for the install summary, or "none" when empty.
//
// It replaces yesNo, whose only three callers printed "Mail: no" from flags
// that had no effect on the sequence — the summary now lists the modules the
// registry will actually deploy.
func joinOuNone(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}

// ecrireResumeModules prints what the installation will actually deploy.
//
// WHY THE SUMMARY READS THE REGISTRY AND NOT FLAGS: three lines used to print
// "Mail: no" / "Office: yes" / "Monitoring: yes" from options that never
// reached the sequence — mail and office are Core modules, always laid down,
// and no supervision exists. An operator reading "Mail: no" while Stalwart is
// being installed was misled by the very output meant to inform them.
//
// Reading the registry means a module added tomorrow appears here without
// touching this file, the same reason the optional flags' help is generated
// from module.All(). Kept as its own function so the summary can be asserted
// without running a deployment.
func ecrireResumeModules(out io.Writer, core, optionnels []string) {
	fmt.Fprintf(out, "Core:       %s\n", joinOuNone(core))
	if len(optionnels) == 0 {
		fmt.Fprintln(out, "Optional:   none")
		return
	}
	fmt.Fprintf(out, "Optional:   %s\n", strings.Join(optionnels, ", "))
}

// coresDuRegistre returns the IDs of the always-installed modules, in registry
// order.
func coresDuRegistre() []string {
	var cores []string
	for _, m := range module.All() {
		if m.Info().Kind == module.Core {
			cores = append(cores, m.Info().ID)
		}
	}
	return cores
}

// idsDesModules extracts the IDs of a module list, keeping its order.
func idsDesModules(ms []module.Module) []string {
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.Info().ID)
	}
	return ids
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
