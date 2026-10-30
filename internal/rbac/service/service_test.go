package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
	"github.com/group-project-bridgeon/manager-service/internal/rbac/service"
)

type mockRoleRepo struct {
	roles map[string]domain.Role
}

func newMockRoleRepo() *mockRoleRepo {
	return &mockRoleRepo{roles: make(map[string]domain.Role)}
}

func (m *mockRoleRepo) List(ctx context.Context) ([]domain.Role, error) {
	result := make([]domain.Role, 0, len(m.roles))
	for _, r := range m.roles {
		result = append(result, r)
	}
	return result, nil
}

func (m *mockRoleRepo) GetByID(ctx context.Context, id string) (*domain.Role, error) {
	r, exists := m.roles[id]
	if !exists {
		return nil, domain.ErrRoleNotFound
	}
	return &r, nil
}

func (m *mockRoleRepo) Create(ctx context.Context, role domain.Role) error {
	if _, exists := m.roles[role.ID]; exists {
		return domain.ErrRoleAlreadyExists
	}
	m.roles[role.ID] = role
	return nil
}

type mockUserRoleRepo struct {
	userRoles map[string]map[string]domain.UserRole // userID -> roleID -> UserRole
}

func newMockUserRoleRepo() *mockUserRoleRepo {
	return &mockUserRoleRepo{userRoles: make(map[string]map[string]domain.UserRole)}
}

func (m *mockUserRoleRepo) Assign(ctx context.Context, ur domain.UserRole) error {
	if _, ok := m.userRoles[ur.UserID]; !ok {
		m.userRoles[ur.UserID] = make(map[string]domain.UserRole)
	}
	if _, exists := m.userRoles[ur.UserID][ur.RoleID]; exists {
		return domain.ErrUserRoleAlreadyAssigned
	}
	m.userRoles[ur.UserID][ur.RoleID] = ur
	return nil
}

func (m *mockUserRoleRepo) Revoke(ctx context.Context, userID, roleID string) error {
	if roles, ok := m.userRoles[userID]; ok {
		if _, exists := roles[roleID]; exists {
			delete(roles, roleID)
			return nil
		}
	}
	return domain.ErrUserRoleNotFound
}

func (m *mockUserRoleRepo) GetRolesByUserID(ctx context.Context, userID string) ([]domain.Role, error) {
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

func (m *mockUserRoleRepo) CheckPermission(ctx context.Context, userID, serviceName, resource, action string) (bool, []string, error) {
	rolesMap, ok := m.userRoles[userID]
	if !ok {
		return false, nil, nil
	}
	var roles []string
	for r := range rolesMap {
		roles = append(roles, r)
		if r == "admin" {
			return true, roles, nil
		}
		if r == "manager" && serviceName == "purchasing" && action == "approve" {
			return true, roles, nil
		}
	}
	return false, roles, nil
}

func TestUserService(t *testing.T) {
	ctx := context.Background()
	roleRepo := newMockRoleRepo()
	userRoleRepo := newMockUserRoleRepo()
	svc := service.New(roleRepo, userRoleRepo)

	// Seed manager role
	_, _ = svc.CreateRole(ctx, "manager", "Manager", "Approves things")

	t.Run("assign and get user roles", func(t *testing.T) {
		_, err := svc.AssignRole(ctx, "usr_1", "manager", "admin_0")
		if err != nil {
			t.Fatalf("unexpected assign error: %v", err)
		}

		roles, err := svc.GetUserRoles(ctx, "usr_1")
		if err != nil {
			t.Fatalf("unexpected get error: %v", err)
		}
		if len(roles) != 1 || roles[0].ID != "manager" {
			t.Errorf("expected 1 manager role, got: %+v", roles)
		}
	})

	t.Run("assign to non-existent role fails", func(t *testing.T) {
		_, err := svc.AssignRole(ctx, "usr_1", "non_existent_role", "admin_0")
		if !errors.Is(err, domain.ErrRoleNotFound) {
			t.Errorf("expected ErrRoleNotFound, got: %v", err)
		}
	})

	t.Run("prevent duplicate assignment", func(t *testing.T) {
		_, err := svc.AssignRole(ctx, "usr_1", "manager", "admin_0")
		if !errors.Is(err, domain.ErrUserRoleAlreadyAssigned) {
			t.Errorf("expected ErrUserRoleAlreadyAssigned, got: %v", err)
		}
	})

	t.Run("authorize permitted action", func(t *testing.T) {
		res, err := svc.Authorize(ctx, domain.AuthzCheckRequest{
			UserID:   "usr_1",
			Service:  "purchasing",
			Resource: "bill",
			Action:   "approve",
		})
		if err != nil {
			t.Fatalf("unexpected authorize error: %v", err)
		}
		if !res.Allowed {
			t.Errorf("expected allowed true for manager approving purchasing bill")
		}
	})

	t.Run("authorize denied action", func(t *testing.T) {
		res, err := svc.Authorize(ctx, domain.AuthzCheckRequest{
			UserID:   "usr_1",
			Service:  "inventory",
			Resource: "stock",
			Action:   "adjust",
		})
		if err != nil {
			t.Fatalf("unexpected authorize error: %v", err)
		}
		if res.Allowed {
			t.Errorf("expected allowed false for manager adjusting inventory stock")
		}
	})

	t.Run("revoke user role", func(t *testing.T) {
		err := svc.RevokeRole(ctx, "usr_1", "manager")
		if err != nil {
			t.Fatalf("unexpected revoke error: %v", err)
		}

		roles, _ := svc.GetUserRoles(ctx, "usr_1")
		if len(roles) != 0 {
			t.Errorf("expected 0 roles after revocation, got: %d", len(roles))
		}
	})
}
