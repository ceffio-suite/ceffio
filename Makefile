# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © MANDEM
.PHONY: build test vet lint clean test-clean

build:
	go build -o bin/ceffio ./cmd/ceffio

test:
	go test ./...

vet:
	go vet ./...

lint: vet

clean:
	rm -rf bin/

# Full reproduction from scratch (run after each phase).
test-clean:
	bash scripts/clean-test.sh
