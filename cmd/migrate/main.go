// Package main provides the CLI migration runner for the database schema using golang-migrate.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/group-project-bridgeon/manager-service/internal/config"
)

const migrationsDir = "migrations"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "migration runner error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: go run ./cmd/migrate [up|down|status|version|reset|force <version>]")
	}

	command := os.Args[1]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	dir := os.Getenv("MIGRATIONS_DIR")
	if dir == "" {
		dir = migrationsDir
	}

	m, err := migrate.New("file://"+dir, cfg.DSN())
	if err != nil {
		return fmt.Errorf("failed to initialize migrate: %w", err)
	}
	defer func() {
		sourceErr, dbErr := m.Close()
		if sourceErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close migration source: %v\n", sourceErr)
		}
		if dbErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close database connection: %v\n", dbErr)
		}
	}()

	switch command {
	case "up":
		if err := m.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				fmt.Println("no change: schema is already up to date")
				return nil
			}
			return fmt.Errorf("migration up failed: %w", err)
		}
		version, dirty, _ := m.Version()
		fmt.Printf("migrations applied successfully (current version: %d, dirty: %t)\n", version, dirty)

	case "down":
		// Roll back 1 migration step by default (matches goose behavior), or N steps if specified
		steps := 1
		if len(os.Args) > 2 {
			parsed, parseErr := strconv.Atoi(os.Args[2])
			if parseErr != nil {
				return fmt.Errorf("invalid step count: %w", parseErr)
			}
			steps = parsed
		}
		if err := m.Steps(-steps); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				fmt.Println("no change: nothing to rollback")
				return nil
			}
			return fmt.Errorf("migration down failed: %w", err)
		}
		version, dirty, _ := m.Version()
		fmt.Printf("migration rolled back %d step(s) (current version: %d, dirty: %t)\n", steps, version, dirty)

	case "reset":
		if err := m.Down(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				fmt.Println("no change: database is already empty")
				return nil
			}
			return fmt.Errorf("migration reset failed: %w", err)
		}
		fmt.Println("all migrations rolled back successfully")

	case "status", "version":
		version, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				fmt.Println("database version: 0 (no migrations applied)")
				return nil
			}
			return fmt.Errorf("failed to get migration version: %w", err)
		}
		fmt.Printf("database version: %d, dirty: %t\n", version, dirty)

	case "force":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: go run ./cmd/migrate force <version>")
		}
		targetVersion, err := strconv.Atoi(os.Args[2])
		if err != nil {
			return fmt.Errorf("invalid version for force: %w", err)
		}
		if err := m.Force(targetVersion); err != nil {
			return fmt.Errorf("failed to force version: %w", err)
		}
		fmt.Printf("forced database version to %d\n", targetVersion)

	default:
		return fmt.Errorf("unknown migration command: %s (supported: up, down, status, version, reset, force)", command)
	}

	return nil
}
