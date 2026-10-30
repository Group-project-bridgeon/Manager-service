// Package main provides the CLI migration runner for the database schema using Goose.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

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
		return fmt.Errorf("usage: go run ./cmd/migrate [up|down|status|version|reset]")
	}

	command := os.Args[1]
	var args []string
	if len(os.Args) > 2 {
		args = os.Args[2:]
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return fmt.Errorf("failed to parse DSN: %w", err)
	}

	db := stdlib.OpenDB(*poolConfig.ConnConfig)
	defer func() {
		_ = db.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.RunContext(ctx, command, db, migrationsDir, args...); err != nil {
		return fmt.Errorf("migration %s failed: %w", command, err)
	}

	return nil
}
