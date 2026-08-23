.PHONY: up down rebuild restart logs status test lint format clean build push

build:     ## Build the app image and push to quay.io/sigaint/corvus
	scripts/build.sh

push:      ## Alias for build (build + push)
	scripts/build.sh

up:        ## Build and start all containers (dev mode)
	scripts/up.sh

down:      ## Stop all containers
	scripts/down.sh

rebuild:   ## Rebuild and restart all containers
	scripts/rebuild.sh

restart:   ## Restart all containers (no rebuild)
	scripts/restart.sh

logs:      ## Tail container logs
	scripts/logs.sh

status:    ## Show container status
	scripts/status.sh

test:      ## Run unit tests (mocked DB — no Postgres needed)
	pytest

test-live: ## Run live integration tests (requires running stack)
	pytest -m live

lint:      ## Run pylint on application code
	tox -e lint

format:    ## Format code with ruff
	ruff format app tests scripts
	ruff check --fix app tests scripts

typecheck:  ## Run mypy type checking
	mypy app

clean:     ## Remove cache and build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .tox build
