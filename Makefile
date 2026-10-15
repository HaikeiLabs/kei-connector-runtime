COMPOSE ?= docker compose
DEV_COMPOSE = $(COMPOSE) -f compose.dev.yaml
OPENWEBUI_COMPOSE = $(DEV_COMPOSE) --profile openwebui
# Works from either the repository checkout or a worktree under .worktrees.
# kei-console starts the policy catalog and exposes the runtime/CLI proxy routes.
CONTROL_PLANE_DIR ?= $(if $(wildcard ../kei-console/Makefile),../kei-console,../../kei-console)
CONTROL_PLANE_TARGET ?= dev
KEI_CLI ?= kei
KEI_CLI_API_URL ?= http://localhost:8082
KEI_RUNTIME_CONTROL_PLANE_URL ?= http://host.docker.internal:8082
KEI_INSTALLATION_NAME ?= local-openwebui
RUNTIME_ENV_FILE ?= .runtime.env

.PHONY: dev dev-down dev-logs dev-config dev-ministack dev-ministack-down dev-control-plane dev-control-plane-down dev-control-plane-logs dev-provision-runtime dev-runtime-token dev-openwebui dev-openwebui-down dev-openwebui-logs dev-local test

# Start the connector runtime. OpenWebUI is an optional client added in a
# later development profile; the default target is the runtime itself.
dev:
	@set -a; [ ! -f "$(RUNTIME_ENV_FILE)" ] || . "$(RUNTIME_ENV_FILE)"; set +a; $(DEV_COMPOSE) up -d --build

dev-ministack:
	$(DEV_COMPOSE) up -d ministack

dev-ministack-down:
	$(DEV_COMPOSE) rm -sf ministack

dev-down:
	$(DEV_COMPOSE) down

dev-logs:
	$(DEV_COMPOSE) logs -f

dev-config:
	@set -a; [ ! -f "$(RUNTIME_ENV_FILE)" ] || . "$(RUNTIME_ENV_FILE)"; set +a; $(DEV_COMPOSE) config

# Start the local policy-catalog control plane from its sibling repository.
dev-control-plane:
	$(MAKE) -C "$(CONTROL_PLANE_DIR)" $(CONTROL_PLANE_TARGET)

dev-control-plane-down:
	$(MAKE) -C "$(CONTROL_PLANE_DIR)" dev-down

dev-control-plane-logs:
	$(MAKE) -C "$(CONTROL_PLANE_DIR)" dev-logs

# Create a platform-neutral local runtime installation, mint its credential,
# and write the environment needed by the local Compose stack.
dev-provision-runtime:
	@command -v "$(KEI_CLI)" >/dev/null || (echo "$(KEI_CLI) is not on PATH" >&2; exit 1)
	@set -eu; \
		installation_id="$(KEI_INSTALLATION_ID)"; \
		installation_tmp="$$(mktemp)"; \
		token_tmp="$$(mktemp)"; \
		trap 'rm -f "$$installation_tmp" "$$token_tmp"' EXIT; \
		if [ -z "$$installation_id" ]; then \
			if [ -n "$(KEI_AGENT_ID)" ]; then \
				"$(KEI_CLI)" bot init --api-url "$(KEI_CLI_API_URL)" --platform cli --name "$(KEI_INSTALLATION_NAME)" --agent "$(KEI_AGENT_ID)" > "$$installation_tmp"; \
			else \
				"$(KEI_CLI)" bot init --api-url "$(KEI_CLI_API_URL)" --platform cli --name "$(KEI_INSTALLATION_NAME)" > "$$installation_tmp"; \
			fi; \
			installation_id="$$(sed -n 's/.*"installation_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$$installation_tmp")"; \
		fi; \
		test -n "$$installation_id" || { echo "could not determine installation ID" >&2; exit 1; }; \
		"$(KEI_CLI)" bot credential --api-url "$(KEI_CLI_API_URL)" --installation "$$installation_id" > "$$token_tmp"; \
		token="$$(tr -d '\r\n' < "$$token_tmp")"; \
		test -n "$$token"; \
		umask 077; \
		{ printf 'export KEI_RUNTIME_CONTROL_PLANE_URL="%s"\n' "$(KEI_RUNTIME_CONTROL_PLANE_URL)"; printf 'export KEI_RUNTIME_INSTALLATION_ID="%s"\n' "$$installation_id"; printf 'export KEI_RUNTIME_TOKEN="%s"\n' "$$token"; } > "$(RUNTIME_ENV_FILE)"; \
		echo "Provisioned installation $$installation_id and wrote runtime environment to $(RUNTIME_ENV_FILE)."

# Retrieve a one-time runtime credential for an installation created through
# the Kei console/CLI flow, without printing the token to the terminal.
dev-runtime-token:
	@test -n "$(KEI_INSTALLATION_ID)" || (echo "KEI_INSTALLATION_ID is required" >&2; exit 1)
	@command -v "$(KEI_CLI)" >/dev/null || (echo "$(KEI_CLI) is not on PATH" >&2; exit 1)
	@set -eu; \
		tmp="$$(mktemp)"; \
		trap 'rm -f "$$tmp"' EXIT; \
		"$(KEI_CLI)" bot credential --api-url "$(KEI_CLI_API_URL)" --installation "$(KEI_INSTALLATION_ID)" > "$$tmp"; \
		token="$$(tr -d '\r\n' < "$$tmp")"; \
		test -n "$$token"; \
		umask 077; \
		{ printf 'export KEI_RUNTIME_CONTROL_PLANE_URL="%s"\n' "$(KEI_RUNTIME_CONTROL_PLANE_URL)"; printf 'export KEI_RUNTIME_INSTALLATION_ID="%s"\n' "$(KEI_INSTALLATION_ID)"; printf 'export KEI_RUNTIME_TOKEN="%s"\n' "$$token"; } > "$(RUNTIME_ENV_FILE)"; \
		echo "Wrote runtime environment to $(RUNTIME_ENV_FILE); source it before make dev-openwebui."

dev-openwebui:
	@set -a; [ ! -f "$(RUNTIME_ENV_FILE)" ] || . "$(RUNTIME_ENV_FILE)"; set +a; $(OPENWEBUI_COMPOSE) up -d --build

# Start the control plane, runtime, and OpenWebUI together. Provisioning is
# intentionally separate because it requires an authenticated CLI session and
# may encounter an existing local installation.
dev-local: dev-control-plane
	@set -eu; \
		test -f "$(RUNTIME_ENV_FILE)" || { echo "$(RUNTIME_ENV_FILE) is required; run make dev-provision-runtime first" >&2; exit 1; }; \
		set -a; . "$(RUNTIME_ENV_FILE)"; set +a; \
		test -n "$${KEI_RUNTIME_INSTALLATION_ID:-}" || { echo "KEI_RUNTIME_INSTALLATION_ID is missing; run make dev-provision-runtime or make dev-runtime-token KEI_INSTALLATION_ID=..." >&2; exit 1; }; \
		$(MAKE) dev-openwebui; \
		attempt=0; until curl -fsS "http://localhost:$${KEI_PROXY_PORT:-8085}/healthz" >/dev/null; do \
			attempt=$$((attempt + 1)); test "$$attempt" -lt 30 || { echo "connector runtime did not become healthy" >&2; exit 1; }; sleep 1; \
		done; \
		"$(KEI_CLI)" bot bind --api-url "$(KEI_CLI_API_URL)" --installation "$${KEI_RUNTIME_INSTALLATION_ID}" || { echo "runtime started but binding failed; inspect the installation with kei bot status" >&2; exit 1; }; \
		echo "Local control plane, connector runtime, and OpenWebUI are running."

dev-openwebui-down:
	$(OPENWEBUI_COMPOSE) down

dev-openwebui-logs:
	$(OPENWEBUI_COMPOSE) logs -f

test:
	go test ./...

# Build the e2e kei-proxy: the private upstream allowance (ADR-036 §10) is
# compiled in only with the e2e tag. Release binaries stay untagged
# (.goreleaser.yaml, Dockerfile without GO_TAGS).
IMAGE ?= kei-connector-runtime
VERSION ?= dev

build-e2e:
	go build -tags e2e -o bin/kei-proxy-e2e ./cmd/kei-proxy

image-e2e:
	docker build --build-arg GO_TAGS=e2e -t $(IMAGE):$(VERSION)-e2e .
