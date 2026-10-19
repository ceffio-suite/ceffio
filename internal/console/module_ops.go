// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// Asynchronous install/uninstall operations, one at a time per module.
//
// WHY ASYNCHRONOUS — the measured constraint: installing live
// transcription takes several minutes (the container image and the speech
// models weigh ~9 GB, and AppAPI waits for the ExApp to come up). A
// synchronous HTTP request of that length is cut by the ingress proxy long
// before the operation ends — the browser sees a truncated response while
// the work continues server-side — and the operator is then left unable to
// tell whether the operation succeeded. So the POST answers 202 Accepted
// immediately and the progress is exposed through the operation journal,
// which the page polls.
//
// Everything runs through the Kubernetes API (client-go, remotecommand):
// the console image is built FROM scratch — no shell, no kubectl inside.

// journalLines caps the in-memory journal of one operation.
//
// WHY 200 lines: an install writes one line per step plus the raw occ
// output; 200 lines keep the whole meaningful tail in memory for a page
// poll, without an operation's verbose middle pushing the beginning — the
// part that names what failed — out of reach. Older lines are dropped.
const journalLines = 200

// action is the verb of an operation.
type action string

const (
	actionInstall   action = "install"
	actionUninstall action = "uninstall"
)

// operationView is the JSON shape of the last operation of a module.
type operationView struct {
	Action    string   `json:"action"`
	Running   bool     `json:"running"`
	StartedAt string   `json:"startedAt"`
	Done      bool     `json:"done"` // finished: Success or Error is final
	Success   bool     `json:"success"`
	Error     string   `json:"error,omitempty"`
	Journal   []string `json:"journal"`
}

// operation is the server-side state of ONE running or finished operation:
// the journal (last journalLines lines), the outcome, and the busy flag the
// per-module lock is taken from.
type operation struct {
	action    action
	running   bool
	startedAt time.Time
	success   bool
	errText   string
	journal   []string
}

func (o *operation) view() operationView {
	v := operationView{
		Action:    string(o.action),
		Running:   o.running,
		StartedAt: o.startedAt.Format(time.RFC3339),
		Done:      !o.running,
		Success:   o.success,
		Error:     o.errText,
	}
	v.Journal = append([]string(nil), o.journal...)
	return v
}

// opsManager holds one lock and one operation slot per module ID.
//
// WHY a manager and not a sync.Mutex field on Server: the mutex map must be
// usable before Server is fully built (tests) and the busy check plus the
// operation start must happen atomically — two concurrent POSTs must not
// both see "free".
type opsManager struct {
	mu  sync.Mutex
	ops map[string]*operation
}

func newOpsManager() *opsManager {
	return &opsManager{ops: map[string]*operation{}}
}

// current returns a SNAPSHOT of the operation slot of id (taken under the
// manager lock), safe to read without holding it.
func (g *opsManager) current(id string) (*operation, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	op, ok := g.ops[id]
	if !ok {
		return nil, false
	}
	cp := *op
	cp.journal = append([]string(nil), op.journal...)
	return &cp, true
}

// tryStart marks the module busy and returns the fresh operation slot.
// ok=false means an operation is ALREADY running for this module: the
// caller answers 409 — one operation at a time, because two concurrent
// installs of the same module would interleave their Kubernetes writes and
// leave a state neither of them can describe.
func (g *opsManager) tryStart(id string, a action) (*operation, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if op, ok := g.ops[id]; ok && op.running {
		return nil, false
	}
	op := &operation{action: a, running: true, startedAt: time.Now()}
	g.ops[id] = op
	return op, true
}

// append writes to the journal under the manager lock, keeping only the
// last journalLines lines.
func (g *opsManager) append(id string, p []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	op, ok := g.ops[id]
	if !ok {
		return
	}
	op.journal = append(op.journal, string(p))
	if len(op.journal) > journalLines {
		op.journal = op.journal[len(op.journal)-journalLines:]
	}
}

// finish records the outcome and releases the module.
func (g *opsManager) finish(id string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	op, ok := g.ops[id]
	if !ok {
		return
	}
	op.running = false
	if err != nil {
		op.errText = err.Error()
	} else {
		op.success = true
	}
}

// journalWriter routes everything a module writes to env.Out into the
// operation journal of its module.
type journalWriter struct {
	id  string
	ops *opsManager
}

// Write stores each non-empty write as one journal line.
//
// WHY one line per write and not a byte-splitting parser: modules write
// complete progress lines with fmt.Fprintf; keeping the write boundary
// preserves exactly what the module intended to report. A trailing newline
// is stripped so the journal holds clean lines for JSON.
func (w journalWriter) Write(p []byte) (int, error) {
	line := bytes.TrimRight(p, "\n")
	if len(line) > 0 {
		w.ops.append(w.id, line)
	}
	return len(p), nil
}

// runOperation launches the install/uninstall goroutine for a module whose
// slot was JUST taken by opsManager.tryStart (the handler does the busy
// check and the acceptance decision; this only starts the work).
//
// WHY a detached context: r.Context() is canceled when the HTTP request
// ends — which is immediate for a 202. Using it would kill the operation
// the instant it was accepted.
func (s *Server) runOperation(id string, m module.Module, a action) {
	env := module.Env{
		Domain: s.Domain,
		Kube:   s.kube,
		Out:    journalWriter{id: id, ops: s.ops},
	}
	go func() {
		// The operation outlives every request: a canceled parent would
		// abort it arbitrarily; timeouts belong to the Kubernetes client.
		ctx := context.Background()
		var err error
		if a == actionInstall {
			err = m.Install(ctx, env)
		} else {
			err = m.Uninstall(ctx, env)
		}
		s.ops.finish(id, err)
	}()
}
