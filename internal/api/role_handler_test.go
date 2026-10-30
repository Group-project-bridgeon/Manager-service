package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/api"
	"github.com/group-project-bridgeon/manager-service/internal/logger"
	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
	"github.com/group-project-bridgeon/manager-service/internal/rbac/service"
)

type mockRoleRepoForAPI struct {
	roles map[string]domain.Role
}

func newMockRoleRepoForAPI() *mockRoleRepoForAPI {
	return &mockRoleRepoForAPI{roles: make(map[string]domain.Role)}
}

func (m *mockRoleRepoForAPI) List(ctx context.Context) ([]domain.Role, error) {
	result := make([]domain.Role, 0, len(m.roles))
	for _, r := range m.roles {
		result = append(result, r)
	}
	return result, nil
}

func (m *mockRoleRepoForAPI) GetByID(ctx context.Context, id string) (*domain.Role, error) {
	r, exists := m.roles[id]
	if !exists {
		return nil, domain.ErrRoleNotFound
	}
	return &r, nil
}

func (m *mockRoleRepoForAPI) Create(ctx context.Context, role domain.Role) error {
	if _, exists := m.roles[role.ID]; exists {
		return domain.ErrRoleAlreadyExists
	}
	m.roles[role.ID] = role
	return nil
}

func setupTestRouter() (*service.Service, http.Handler) {
	var buf bytes.Buffer
	log := logger.New("development", "debug", &buf)
	repo := newMockRoleRepoForAPI()
	svc := service.New(repo)

	r := api.NewRouter(api.RouterConfig{
		AppEnv:      "development",
		Logger:      log,
		RoleService: svc,
	})
	return svc, r
}

func TestRoleEndpoints(t *testing.T) {
	svc, router := setupTestRouter()

	t.Run("create role returns 201 created", func(t *testing.T) {
		body := []byte(`{"id":"finance_viewer","name":"Finance Viewer","description":"Read-only access to ledger"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
		}

		var resp api.Response
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode JSON: %v", err)
		}
		if !resp.Success {
			t.Errorf("expected success true")
		}
	})

	t.Run("duplicate role returns 409 conflict", func(t *testing.T) {
		body := []byte(`{"id":"finance_viewer","name":"Finance Viewer","description":"Duplicate"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict, got %d", w.Code)
		}
	})

	t.Run("get existing role returns 200 ok", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/finance_viewer", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("get non-existent role returns 404 not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/non_existent_role", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})

	t.Run("list roles returns array", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	_ = svc
}
