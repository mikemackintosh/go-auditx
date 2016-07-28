all: test build

test:

build:
	go build -o bin/go-auditx cmd/go-auditx.go

run:
	go run cmd/go-auditx.go
