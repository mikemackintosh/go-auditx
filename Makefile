all: test build

test:
	go test -v ./...

build:
	go build -o bin/go-auditx *.go

run: build
	sudo ./bin/go-auditx -d

ci: test
