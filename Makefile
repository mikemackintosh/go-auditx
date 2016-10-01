all: test build

test:
	go test -cover -v ./...

coverage:
	go test -covermode=count -coverprofile=coverage.out
	go test -covermode=count -coverprofile=coverage.out ./lib/bsm/...
	go tool cover -html=coverage.out

build:
	go build -o bin/go-auditx *.go

run: build
	sudo ./bin/go-auditx -d

ci: test
