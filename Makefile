# Change these variables as necessary.
MAIN_PACKAGE_PATH := $(shell pwd)
OS_INFO := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH_INFO := $(shell uname -m | sed 's/x86_64/amd64/')
TMP_DIR := ./tmp
GO_EXECUTABLE := go

## tidy: format code and tidy modfile
.PHONY: tidy
tidy:
	${GO_EXECUTABLE} fmt ./...
	${GO_EXECUTABLE} mod tidy -v

## lint: run linter
.PHONY: lint
lint: tidy
	golangci-lint fmt
	golangci-lint run --fix > /dev/null 2>&1 || true
	golangci-lint run

## audit: run quality control checks
.PHONY: audit
audit: tidy
	${GO_EXECUTABLE} mod verify
	${GO_EXECUTABLE} vet ./...
	${GO_EXECUTABLE} run honnef.co/go/tools/cmd/staticcheck@latest -checks=all,-ST1000,-U1000 ./...
	${GO_EXECUTABLE} run golang.org/x/vuln/cmd/govulncheck@latest ./...
	./scripts/go_test.sh -buildvcs -vet=all ./...

## test: run all tests
.PHONY: test
test: tidy
	./scripts/go_test.sh -v -buildvcs -vet=all ./...
	./scripts/go_test.sh -v -buildvcs -vet=all -race ./...

## test/cover: run all tests and display coverage
.PHONY: test/cover
test/cover: tidy
	mkdir -p ${TMP_DIR}
	./scripts/go_test.sh -v -buildvcs -vet=all -coverprofile=${TMP_DIR}/coverage.out ./...
	${GO_EXECUTABLE} tool cover -html=${TMP_DIR}/coverage.out

## test: run integration tests
.PHONY: test/integration
test/integration: tidy
	./scripts/integration_test.sh -v

# release: build the binary and create a release
.PHONY: release
release:
	goreleaser release --clean

# new_version: create a new version
.PHONY: new_version
new_version:
	./scripts/new_version.sh $(VERSION)

.PHONY: docker
docker:
	cd testing && docker compose up -d --build --force-recreate --remove-orphans
