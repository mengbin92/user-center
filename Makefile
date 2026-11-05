SHELL := /bin/bash
MODULE := github.com/mengbin92/user-center
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO ?= go

.PHONY: help
help:
	@echo "api        regenerate protobuf, gRPC, HTTP and OpenAPI"
	@echo "config     regenerate config protobuf"
	@echo "wire       regenerate Wire injectors"
	@echo "build      build backend binaries"
	@echo "test       run Go tests"
	@echo "web        install and build the SPA"
	@echo "dev        run migrations, bootstrap root (if needed) and start"
	@echo "migrate    apply database migrations"
	@echo "docker     build the container image (linux/amd64)"

.PHONY: api
api:
	buf generate --template buf.gen.yaml
	@test -s openapi.yaml

.PHONY: config
config:
	buf generate --template buf.gen.config.yaml --path internal/conf

.PHONY: wire
wire:
	wire ./cmd/user-center

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=1 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/user-center ./cmd/user-center
	CGO_ENABLED=1 $(GO) build -trimpath -ldflags "-s -w" -o bin/migrate ./cmd/migrate
	CGO_ENABLED=1 $(GO) build -trimpath -ldflags "-s -w" -o bin/admin-rescue ./cmd/admin-rescue

.PHONY: test
test:
	$(GO) test ./...

.PHONY: test-race
test-race:
	$(GO) test -race ./...

.PHONY: web
web:
	cd web && npm ci && npm run build

.PHONY: retention
retention:
	$(GO) run ./cmd/retention -config $${CONF_PATH:-configs/config.yaml}

.PHONY: import-legacy
import-legacy:
	$(GO) run ./cmd/import-legacy -config $${CONF_PATH:-configs/config.yaml} -file $${FILE:?set FILE=/path/to/snapshot.json} $${APPLY:+ -apply}

.PHONY: migrate
migrate:
	$(GO) run ./cmd/migrate -config $${CONF_PATH:-configs/config.yaml}

.PHONY: dev
dev:
	$(GO) run ./cmd/migrate -config configs/config.dev.yaml
	@if [ -n "$$USER_CENTER_BOOTSTRAP_PASSWORD" ]; then \
		$(GO) run ./cmd/admin-rescue -config configs/config.dev.yaml -action bootstrap \
			-username $${USER_CENTER_BOOTSTRAP_USERNAME:-root} \
			-password "$$USER_CENTER_BOOTSTRAP_PASSWORD" \
			-email $${USER_CENTER_BOOTSTRAP_EMAIL:-root@example.com}; \
	fi
	$(GO) run ./cmd/user-center -config configs/config.dev.yaml

.PHONY: docker
docker:
	docker buildx build --platform linux/amd64 --load -t user-center:latest .

.PHONY: clean
clean:
	rm -rf bin artifacts
