.PHONY=default build dev-deps deps vet sec unused static release install test format
HOSTNAME=supabase.com
NAMESPACE=com
NAME=gotrue
BINARY=terraform-provider-${NAME}
VERSION?=`git describe --tags`
OS_ARCH=darwin_arm64
FLAGS?=-ldflags "-X github.com/supabase-community/terraform-provider-gotrue/gotrue.Version=${VERSION}"

default: install

dev-deps: ## Install developer dependencies
	@go install github.com/gobuffalo/pop/soda@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install honnef.co/go/tools/cmd/staticcheck@latest

deps: ## Install dependencies.
	@go mod download
	@go mod verify

vet: # Vet the code
	go vet ./...

sec: dev-deps # Check for security vulnerabilities
	gosec -quiet ./...
	gosec -quiet -tests -exclude=G104 ./...

unused: dev-deps # Look for unused code
	@echo "Unused code:"
	staticcheck -checks U1000 ./...

	@echo

	@echo "Code used only in _test.go (do move it in those files):"
	staticcheck -checks U1000 -tests=false ./...

static: dev-deps
	staticcheck ./...

build: deps
	CGO_ENABLED=0 go build $(FLAGS) -o ${BINARY}

release:
	goreleaser release --rm-dist --snapshot --skip-publish  --skip-sign

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

test:
	CGO_ENABLED=0 go test ./...

format:
	gofmt -s -w .
