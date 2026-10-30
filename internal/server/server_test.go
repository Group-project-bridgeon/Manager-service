package server_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/config"
	"github.com/group-project-bridgeon/manager-service/internal/server"
)

func TestServerLifecycle(t *testing.T) {
	cfg := &config.Config{
		Port:            9988,
		ReadTimeout:     1 * time.Second,
		WriteTimeout:    1 * time.Second,
		IdleTimeout:     1 * time.Second,
		ShutdownTimeout: 1 * time.Second,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := server.New(cfg, handler)

	if srv.Port() != 9988 {
		t.Fatalf("expected port 9988, got %d", srv.Port())
	}

	serverErr := make(chan error, 1)
	go func() {
		err := srv.Start()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Allow server small window to bind socket
	time.Sleep(50 * time.Millisecond)

	// Trigger graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("expected clean shutdown, got: %v", err)
	}

	// Wait for server goroutine to exit
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("unexpected server start error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server took too long to exit after shutdown")
	}
}
