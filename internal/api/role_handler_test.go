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

type mockUserRoleRepoForAPI struct {
	userRoles map[string]map[string]domain.UserRole
}

func newMockUserRoleRepoForAPI() *mockUserRoleRepoForAPI {
	return &mockUserRoleRepoForAPI{userRoles: make(map[string]map[string]domain.UserRole)}
}

func (m *mockUserRoleRepoForAPI) Assign(ctx context.Context, ur domain.UserRole) error {
	if _, ok := m.userRoles[ur.UserID]; !ok {
		m.userRoles[ur.UserID] = make(map[string]domain.UserRole)
	}
	if _, exists := m.userRoles[ur.UserID][ur.RoleID]; exists {
		return domain.ErrUserRoleAlreadyAssigned
	}
	m.userRoles[ur.UserID][ur.RoleID] = ur
	return nil
}

func (m *mockUserRoleRepoForAPI) Revoke(ctx context.Context, userID, roleID string) error {
	if roles, ok := m.userRoles[userID]; ok {
		if _, exists := roles[roleID]; exists {
			delete(roles, roleID)
			return nil
		}
	}
	return domain.ErrUserRoleNotFound
}

func (m *mockUserRoleRepoForAPI) GetRolesByUserID(ctx context.Context, userID string) ([]domain.Role, error) {
	rolesMap, ok := m.userRoles[userID]
	if !ok {
		return []domain.Role{}, nil
	}
	result := make([]domain.Role, 0, len(rolesMap))
	for roleID := range rolesMap {
		result = append(result, domain.Role{ID: roleID, Name: roleID})
	}
	return result, nil
}

func (m *mockUserRoleRepoForAPI) CheckPermission(ctx context.Context, userID, serviceName, resource, action string) (bool, []string, error) {
	rolesMap, ok := m.userRoles[userID]
	if !ok {
		return false, nil, nil
	}
	var roles []string
	for r := range rolesMap {
		roles = append(roles, r)
		if r == "admin" || (r == "manager" && serviceName == "purchasing" && action == "approve") {
			return true, roles, nil
		}
	}
	return false, roles, nil
}

func setupTestRouter() (*service.Service, http.Handler) {
	var buf bytes.Buffer
	log := logger.New("development", "debug", &buf)
	roleRepo := newMockRoleRepoForAPI()
	userRoleRepo := newMockUserRoleRepoForAPI()
	svc := service.New(roleRepo, userRoleRepo)

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

func TestUserRoleEndpoints(t *testing.T) {
	svc, router := setupTestRouter()

	// Seed manager role
	_, _ = svc.CreateRole(context.Background(), "manager", "Manager", "Approver")

	t.Run("assign role to user returns 201", func(t *testing.T) {
		body := []byte(`{"role_id":"manager","assigned_by":"admin"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/user_99/roles", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("list user roles returns roles", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/user_99/roles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("check authz returns true for permitted action", func(t *testing.T) {
		body := []byte(`{"user_id":"user_99","service":"purchasing","resource":"bill","action":"approve"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/authz/check", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp api.Response
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		dataMap := resp.Data.(map[string]any)
		if dataMap["allowed"] != true {
			t.Errorf("expected allowed true, got: %v", dataMap["allowed"])
		}
	})

	t.Run("revoke role returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/user_99/roles/manager", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}
