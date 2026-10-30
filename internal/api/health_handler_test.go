package api_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/api"
	"github.com/group-project-bridgeon/manager-service/internal/logger"
)

type mockReadinessChecker struct {
	err error
}

func (m *mockReadinessChecker) Check(ctx context.Context) error {
	return m.err
}

func TestHealthEndpoints(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New("development", "debug", &buf)

	t.Run("healthz liveness returns 200 ok", func(t *testing.T) {
		r := api.NewRouter(api.RouterConfig{
			AppEnv:  "development",
			Logger:  log,
			Checker: nil,
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		expectedBody := `{"status":"ok"}`
		if w.Body.String() != expectedBody {
			t.Errorf("expected %s, got %s", expectedBody, w.Body.String())
		}
	})

	t.Run("readyz readiness returns 200 when checker passes", func(t *testing.T) {
		r := api.NewRouter(api.RouterConfig{
			AppEnv:  "development",
			Logger:  log,
			Checker: &mockReadinessChecker{err: nil},
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		expectedBody := `{"status":"ready"}`
		if w.Body.String() != expectedBody {
			t.Errorf("expected %s, got %s", expectedBody, w.Body.String())
		}
	})

	t.Run("readyz readiness returns 503 when checker fails", func(t *testing.T) {
		r := api.NewRouter(api.RouterConfig{
			AppEnv:  "development",
			Logger:  log,
			Checker: &mockReadinessChecker{err: errors.New("db unreachable")},
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", w.Code)
		}
	})
}
