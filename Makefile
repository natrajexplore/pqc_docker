# PQC WireScope - developer entry points.
# Run `make help` for the list. Every target is a thin wrapper so Claude Code and
# humans use the exact same commands.

SHELL := /bin/bash
.DEFAULT_GOAL := help

PROFILES ?= ipsec ipsec-auth tls ssh macsec
PROFILE_FLAGS := $(foreach p,$(PROFILES),--profile $(p))
COMPOSE := docker compose $(PROFILE_FLAGS)

MGMT_NET    := pqcw_mgmt
MGMT_SUBNET := 172.29.0.0/24
CAPTURE_VOL := pqcw_captures
UPSTREAM    := vendor/juliogomez-pqc

.PHONY: help bootstrap secrets preflight network build up down ps logs ui \
        test test-backend test-frontend test-ui lint smoke clean nuke

help: ## Show this help
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z_-]+:.*##/{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}' $(MAKEFILE_LIST)

bootstrap: ## Fetch the upstream juliogomez/pqc repo (submodule) and generate lab secrets
	./scripts/bootstrap.sh

secrets: ## (Re)generate lab-only PSK/PPK into .env (never committed)
	./scripts/gen-lab-secrets.sh

preflight: ## Check Docker, Compose, kernel XFRM/MACsec support, free subnets
	./scripts/preflight.sh

network: ## Create the shared mgmt network + capture volume (idempotent)
	@docker network inspect $(MGMT_NET) >/dev/null 2>&1 || \
	  docker network create --driver bridge --subnet $(MGMT_SUBNET) $(MGMT_NET)
	@docker volume inspect $(CAPTURE_VOL) >/dev/null 2>&1 || docker volume create $(CAPTURE_VOL)

build: network ## Build all images (first run compiles strongSwan x2, hostap, OpenSSH)
	@test -f $(UPSTREAM)/learn/docker/Dockerfile || { echo "Run 'make bootstrap' first"; exit 1; }
	$(COMPOSE) build

up: network ## Start mgmt + selected protocol stacks (PROFILES="ipsec tls ...")
	@test -f .env || { echo "No .env - run 'make bootstrap' (or 'make secrets')"; exit 1; }
	$(COMPOSE) up -d --build
	@echo; echo "UI: http://127.0.0.1:$${PQCW_UI_PORT:-8080}"

down: ## Stop and remove containers (keeps images, PKI volumes and captures)
	$(COMPOSE) down

ps: ## Show container status
	$(COMPOSE) ps

logs: ## Tail backend + agent logs
	$(COMPOSE) logs -f --tail=100 backend cap-ipsec cap-ipsec-auth cap-tls cap-ssh cap-macsec

ui: ## Run the frontend dev server against a running backend (hot reload)
	cd frontend && npm install && npm run dev

test: test-backend test-frontend ## Run all unit tests

test-backend: ## Backend unit tests (no Docker needed)
	cd backend && python -m pytest -q

test-frontend: ## Frontend typecheck + build
	cd frontend && npm install && npm run typecheck && npm run build

test-ui: ## Headless-Chromium UI test against the running lab (needs mgmt + tls up)
	./scripts/ui-test.sh

lint: ## Lint Python + shell + TS
	cd backend && ruff check app tests
	shellcheck scripts/*.sh stacks/*/*.sh
	cd frontend && npm run lint

smoke: ## End-to-end: run every scenario through the API and assert verdicts
	./scripts/smoke.sh

clean: ## Remove captures (pcaps) but keep images and PKI
	docker volume rm $(CAPTURE_VOL) || true

nuke: down ## Remove containers, PKI volumes, captures and the mgmt network
	-docker volume rm pqcw_ipsec_pki pqcw_tls_pki pqcw_ssh_keys pqcw_macsec_pki $(CAPTURE_VOL)
	-docker network rm $(MGMT_NET)
