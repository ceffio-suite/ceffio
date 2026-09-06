.PHONY: build test vet lint clean

build:
	go build -o bin/ceffio ./cmd/ceffio

test:
	go test ./...

vet:
	go vet ./...

lint: vet

clean:
	rm -rf bin/
