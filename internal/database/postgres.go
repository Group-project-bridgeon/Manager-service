// Package database manages PostgreSQL connection pooling, health checks, and lifecycle.
package database

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/group-project-bridgeon/manager-service/internal/config"
)

// NewPool initializes and returns a verified PostgreSQL connection pool.
func NewPool(ctx context.Context, cfg *config.Config, log *slog.Logger) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("parsing database connection string: %w", err)
	}

	// Apply production connection pool tuning
	poolConfig.MaxConns = cfg.DBMaxConns
	poolConfig.MinConns = cfg.DBMinConns
	poolConfig.MaxConnLifetime = cfg.DBMaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.DBMaxConnIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("initializing pgx connection pool: %w", err)
	}

	// Verify that the database is reachable
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database at %s:%d: %w", cfg.DBHost, cfg.DBPort, err)
	}

	log.Info("connected to postgresql",
		slog.String("host", cfg.DBHost),
		slog.Int("port", cfg.DBPort),
		slog.String("database", cfg.DBName),
		slog.Int("max_conns", int(cfg.DBMaxConns)),
		slog.Int("min_conns", int(cfg.DBMinConns)),
	)

	return pool, nil
}
