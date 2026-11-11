GO_IMAGE ?= golang:1.27-bookworm
DOCKER_GO = docker run --rm -v "$(CURDIR):/src" -w /src

.PHONY: test race vet fmt integration up down

test:
	$(DOCKER_GO) $(GO_IMAGE) go test ./...

race:
	$(DOCKER_GO) -e CGO_ENABLED=1 $(GO_IMAGE) go test -race ./...

vet:
	$(DOCKER_GO) $(GO_IMAGE) go vet ./...

fmt:
	$(DOCKER_GO) $(GO_IMAGE) sh -c 'gofmt -w *.go tests/stub/*.go'

integration:
	sh tests/integration.sh

up:
	docker compose up -d

down:
	docker compose down --remove-orphans
