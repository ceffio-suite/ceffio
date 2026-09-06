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

# Reproduction intégrale à zéro (à lancer après chaque phase).
test-clean:
	bash scripts/clean-test.sh
