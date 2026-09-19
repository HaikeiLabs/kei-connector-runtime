COMPOSE ?= docker compose
DEV_COMPOSE = $(COMPOSE) -f compose.dev.yaml
OPENWEBUI_COMPOSE = $(DEV_COMPOSE) --profile openwebui
# Works from either the repository checkout or a worktree under .worktrees.
CONTROL_PLANE_DIR ?= $(if $(wildcard ../kei-policy-catalog/Makefile),../kei-policy-catalog,../../kei-policy-catalog)
CONTROL_PLANE_TARGET ?= dev

.PHONY: dev dev-down dev-logs dev-config dev-control-plane dev-control-plane-down dev-control-plane-logs dev-openwebui dev-openwebui-down dev-openwebui-logs test

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

dev-openwebui:
	$(OPENWEBUI_COMPOSE) up --build

dev-openwebui-down:
	$(OPENWEBUI_COMPOSE) down

dev-openwebui-logs:
	$(OPENWEBUI_COMPOSE) logs -f

test:
	go test ./...
