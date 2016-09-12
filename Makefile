all: test build

test:
	go test ./...

build:
	go build -o bin/go-auditx main.go

run:
	go run main.go

ci: test
