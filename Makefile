all: test build

test:
	go test -v ./...

build:
	go build -o bin/go-auditx *.go

run:
	go run main.go bytes.go

ci: test
