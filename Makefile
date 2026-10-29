# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © MANDEM
.PHONY: build test vet lint clean test-clean test-demo pin-digests

build:
	go build -o bin/ceffio ./cmd/ceffio

# test runs the ordinary suite AND the module proof.
#
# WHY test-demo COMES FIRST AND IS PART OF IT: the proof of the module system's
# promise lives behind a build tag, so `go test ./...` never compiles it.
# Leaving it out of the default target means the one test that checks a feature
# can be added without touching the console is the one nobody runs — which is
# how a proof stops proving anything.
# pin-digests pins every container image of the version registry by digest.
#
# IT WRITES internal/version/version.go, and it writes NOTHING when one image
# cannot be resolved: a half-pinned registry looks done and is not.
pin-digests:
	go run ./cmd/pin-digests

test: test-demo
	go test ./...

# test-demo compiles the demo module and runs what depends on it.
#
# The tag is passed to a SUBSET of packages on purpose: it would otherwise apply
# to the whole tree, linking the demo module into the CLI and the console tests
# that have no use for it.
test-demo:
	go test -race -tags demo ./internal/modules/... ./internal/console/... ./cmd/...

vet:
	go vet ./...

lint: vet

clean:
	rm -rf bin/

# Full reproduction from scratch (run after each phase).
test-clean:
	bash scripts/clean-test.sh