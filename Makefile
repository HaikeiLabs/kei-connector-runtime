COMPOSE ?= docker compose
DEV_COMPOSE = $(COMPOSE) -f compose.dev.yaml
OPENWEBUI_COMPOSE = $(DEV_COMPOSE) --profile openwebui
# Works from either the repository checkout or a worktree under .worktrees.
# kei-console starts the policy catalog and exposes the runtime/CLI proxy routes.
CONTROL_PLANE_DIR ?= $(if $(wildcard ../kei-console/Makefile),../kei-console,../../kei-console)
CONTROL_PLANE_TARGET ?= dev
KEI_CLI ?= kei
KEI_CLI_API_URL ?= http://localhost:3000
KEI_RUNTIME_CONTROL_PLANE_URL ?= http://host.docker.internal:8082
KEI_INSTALLATION_NAME ?= local-openwebui
RUNTIME_ENV_FILE ?= .runtime.env

.PHONY: dev dev-down dev-logs dev-config dev-control-plane dev-control-plane-down dev-control-plane-logs dev-provision-runtime dev-runtime-token dev-openwebui dev-openwebui-down dev-openwebui-logs test

# Start the connector runtime. OpenWebUI is an optional client added in a
# later development profile; the default target is the runtime itself.
dev:
	$(DEV_COMPOSE) up --build

dev-down:
	$(DEV_COMPOSE) down

dev-logs:
	$(DEV_COMPOSE) logs -f

dev-config:
	$(DEV_COMPOSE) config

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
	@test -n "$(KEI_AGENT_ID)" || (echo "KEI_AGENT_ID is required" >&2; exit 1)
	@command -v "$(KEI_CLI)" >/dev/null || (echo "$(KEI_CLI) is not on PATH" >&2; exit 1)
	@set -eu; \
		installation_id="$(KEI_INSTALLATION_ID)"; \
		installation_tmp="$$(mktemp)"; \
		token_tmp="$$(mktemp)"; \
		trap 'rm -f "$$installation_tmp" "$$token_tmp"' EXIT; \
		if [ -z "$$installation_id" ]; then \
			"$(KEI_CLI)" bot init --api-url "$(KEI_CLI_API_URL)" --platform cli --name "$(KEI_INSTALLATION_NAME)" --agent "$(KEI_AGENT_ID)" > "$$installation_tmp"; \
			installation_id="$$(sed -n 's/.*"installation_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$$installation_tmp")"; \
		fi; \
		test -n "$$installation_id" || { echo "could not determine installation ID" >&2; exit 1; }; \
		"$(KEI_CLI)" bot credential --api-url "$(KEI_CLI_API_URL)" --installation "$$installation_id" > "$$token_tmp"; \
		token="$$(tr -d '\r\n' < "$$token_tmp")"; \
		test -n "$$token"; \
		umask 077; \
		{ printf 'export KEI_RUNTIME_CONTROL_PLANE_URL="%s"\n' "$(KEI_RUNTIME_CONTROL_PLANE_URL)"; printf 'export KEI_RUNTIME_TOKEN="%s"\n' "$$token"; printf 'export KEI_PROXY_INVOKING_SUBJECT="%s"\n' "$(KEI_SUBJECT)"; } > "$(RUNTIME_ENV_FILE)"; \
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
		{ printf 'export KEI_RUNTIME_CONTROL_PLANE_URL="%s"\n' "$(KEI_RUNTIME_CONTROL_PLANE_URL)"; printf 'export KEI_RUNTIME_TOKEN="%s"\n' "$$token"; } > "$(RUNTIME_ENV_FILE)"; \
		echo "Wrote runtime environment to $(RUNTIME_ENV_FILE); source it before make dev-openwebui."

dev-openwebui:
	$(OPENWEBUI_COMPOSE) up --build

dev-openwebui-down:
	$(OPENWEBUI_COMPOSE) down

dev-openwebui-logs:
	$(OPENWEBUI_COMPOSE) logs -f

test:
	go test ./...
