all: test build

test:
	go test ./...

build:
	go build -o bin/go-auditx *.go

run:
	go run main.go

ci: test
