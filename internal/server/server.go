// Package server provides an HTTP server wrapper with production timeouts and graceful shutdown.
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/config"
)

// Server wraps http.Server to manage application lifecycle.
type Server struct {
	httpServer *http.Server
	port       int
}

// New creates and configures a production-ready http.Server.
func New(cfg *config.Config, handler http.Handler) *Server {
	addr := fmt.Sprintf(":%d", cfg.Port)

	return &Server{
		port: cfg.Port,
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 2 * time.Second, // Protect against Slowloris attacks
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		},
	}
}

// Start begins listening on the configured address.
// It returns http.ErrServerClosed on clean shutdown.
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server without interrupting active connections,
// bounded by the provided context timeout.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Port returns the configured server port.
func (s *Server) Port() int {
	return s.port
}
