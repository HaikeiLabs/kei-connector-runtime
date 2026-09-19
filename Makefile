COMPOSE ?= docker compose
DEV_COMPOSE = $(COMPOSE) -f compose.dev.yaml
OPENWEBUI_COMPOSE = $(DEV_COMPOSE) --profile openwebui

.PHONY: dev dev-down dev-logs dev-config dev-openwebui dev-openwebui-down dev-openwebui-logs test

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

dev-openwebui:
	$(OPENWEBUI_COMPOSE) up --build

dev-openwebui-down:
	$(OPENWEBUI_COMPOSE) down

dev-openwebui-logs:
	$(OPENWEBUI_COMPOSE) logs -f

test:
	go test ./...
