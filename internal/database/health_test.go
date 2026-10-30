package database_test

import (
	"context"
	"errors"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/database"
)

type mockPinger struct {
	err error
}

func (m *mockPinger) Ping(ctx context.Context) error {
	return m.err
}

func TestHealthChecker(t *testing.T) {
	ctx := context.Background()

	t.Run("nil pinger returns nil", func(t *testing.T) {
		h := database.NewHealthChecker(nil)
		if err := h.Check(ctx); err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
	})

	t.Run("successful ping returns nil", func(t *testing.T) {
		h := database.NewHealthChecker(&mockPinger{err: nil})
		if err := h.Check(ctx); err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
	})

	t.Run("failed ping returns error", func(t *testing.T) {
		expectedErr := errors.New("connection reset by peer")
		h := database.NewHealthChecker(&mockPinger{err: expectedErr})
		if err := h.Check(ctx); !errors.Is(err, expectedErr) {
			t.Fatalf("expected error %v, got %v", expectedErr, err)
		}
	})
}
