// Package main is the entrypoint and composition root for the ERP management server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/group-project-bridgeon/manager-service/internal/api"
	"github.com/group-project-bridgeon/manager-service/internal/config"
	"github.com/group-project-bridgeon/manager-service/internal/logger"
	"github.com/group-project-bridgeon/manager-service/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "startup error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Load and validate configuration (fail-fast)
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// 2. Initialize structured logging
	log := logger.New(cfg.AppEnv, cfg.LogLevel, os.Stdout)
	log.Info("starting ERP management server",
		slog.String("env", cfg.AppEnv),
		slog.Int("port", cfg.Port),
		slog.String("log_level", cfg.LogLevel),
	)

	// 3. Assemble API router
	router := api.NewRouter(api.RouterConfig{
		AppEnv:  cfg.AppEnv,
		Logger:  log,
		Checker: nil, // Phase 2: Wire Postgres health checker here
	})

	// 4. Wrap in production HTTP server
	srv := server.New(cfg, router)

	// 5. Channel to catch server runtime errors
	serverErr := make(chan error, 1)
	go func() {
		log.Info("server listening", slog.Int("port", srv.Port()))
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// 6. Trap OS termination signals (SIGINT, SIGTERM)
	shutdownSig := make(chan os.Signal, 1)
	signal.Notify(shutdownSig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdownSig:
		log.Info("shutdown signal received", slog.String("signal", sig.String()))
	}

	// 7. Initiate graceful shutdown with configured deadline
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	log.Info("draining in-flight requests...", slog.Duration("timeout", cfg.ShutdownTimeout))
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	log.Info("server gracefully stopped")
	return nil
}
