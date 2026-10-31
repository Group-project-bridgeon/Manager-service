.PHONY: help run build test lint tidy clean migrate-up migrate-down migrate-status postman

# Default binary output
BINARY_NAME=server
BIN_DIR=bin

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

run: ## Run server locally
	go run ./cmd/server

build: ## Build server binary
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/server

test: ## Run unit tests with race detection and coverage
	go test -v -race -cover ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

tidy: ## Clean up unused Go module dependencies
	go mod tidy

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out

migrate-up: ## Apply all pending database migrations
	go run ./cmd/migrate up

migrate-down: ## Rollback the most recent database migration
	go run ./cmd/migrate down

migrate-status: ## Check the status of database migrations
	go run ./cmd/migrate status

postman: ## Generate Postman collection and environment files with fresh RS256 JWT tokens
	go run ./cmd/postman
