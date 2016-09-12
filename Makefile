all: test build

test:
	go test ./...

build:
	go build -o bin/go-auditx cmd/go-auditx.go

run:
	go run cmd/go-auditx.go

ci: test
