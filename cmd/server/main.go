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
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/api"
	"github.com/group-project-bridgeon/manager-service/internal/auth"
	"github.com/group-project-bridgeon/manager-service/internal/config"
	"github.com/group-project-bridgeon/manager-service/internal/database"
	"github.com/group-project-bridgeon/manager-service/internal/logger"
	rbacRepo "github.com/group-project-bridgeon/manager-service/internal/rbac/repository"
	rbacService "github.com/group-project-bridgeon/manager-service/internal/rbac/service"
	"github.com/group-project-bridgeon/manager-service/internal/server"
	workflowRepo "github.com/group-project-bridgeon/manager-service/internal/workflow/repository"
	workflowService "github.com/group-project-bridgeon/manager-service/internal/workflow/service"
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
	slog.SetDefault(log)
	log.Info("starting ERP management server",
		slog.String("env", cfg.AppEnv),
		slog.Int("port", cfg.Port),
		slog.String("log_level", cfg.LogLevel),
	)

	// 3. Initialize PostgreSQL connection pool
	dbCtx, dbCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dbCancel()

	dbPool, err := database.NewPool(dbCtx, cfg, log)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer dbPool.Close()

	// 4. Wire RBAC business module: repositories -> service
	roleRepo := rbacRepo.NewPostgresRoleRepository(dbPool)
	userRoleRepo := rbacRepo.NewPostgresUserRoleRepository(dbPool)
	roleSvc := rbacService.New(roleRepo, userRoleRepo)

	// 5. Wire Workflow business module: repository -> service (using userRoleRepo as policy authorizer)
	wfRepo := workflowRepo.NewPostgresWorkflowRepository(dbPool)
	wfSvc := workflowService.New(wfRepo, userRoleRepo)

	// 6. Initialize JWT token verifier
	authVerifier := auth.NewVerifier(cfg.JWTPublicKey, cfg.JWTIssuer, cfg.JWTAudience)

	// 7. Assemble API router with dependencies
	router := api.NewRouter(api.RouterConfig{
		AppEnv:          cfg.AppEnv,
		Logger:          log,
		Checker:         database.NewHealthChecker(dbPool),
		AuthVerifier:    authVerifier,
		RoleService:     roleSvc,
		WorkflowService: wfSvc,
	})

	// 7. Wrap in production HTTP server
	srv := server.New(cfg, router)

	// 8. Channel to catch server runtime errors
	serverErr := make(chan error, 1)
	go func() {
		log.Info("server listening", slog.Int("port", srv.Port()))
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// 9. Trap OS termination signals (SIGINT, SIGTERM)
	shutdownSig := make(chan os.Signal, 1)
	signal.Notify(shutdownSig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdownSig:
		log.Info("shutdown signal received", slog.String("signal", sig.String()))
	}

	// 10. Initiate graceful shutdown with configured deadline
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	log.Info("draining in-flight requests...", slog.Duration("timeout", cfg.ShutdownTimeout))
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	log.Info("server gracefully stopped")
	return nil
}
