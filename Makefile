COMPOSE ?= docker compose
DEV_COMPOSE = $(COMPOSE) -f compose.dev.yaml

.PHONY: dev dev-down dev-logs dev-config test

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

test:
	go test ./...
