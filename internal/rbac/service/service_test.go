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

func TestServiceCreateRole(t *testing.T) {
	ctx := context.Background()
	repo := newMockRoleRepo()
	svc := service.New(repo)

	t.Run("successfully create new role", func(t *testing.T) {
		role, err := svc.CreateRole(ctx, "auditor", "Auditor", "Audits financial journals")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if role.ID != "auditor" {
			t.Errorf("expected role ID 'auditor', got: %s", role.ID)
		}

		// Verify role can be retrieved
		found, err := svc.GetRoleByID(ctx, "auditor")
		if err != nil {
			t.Fatalf("failed to retrieve role: %v", err)
		}
		if found.Name != "Auditor" {
			t.Errorf("expected name 'Auditor', got: %s", found.Name)
		}
	})

	t.Run("prevent duplicate role creation", func(t *testing.T) {
		_, err := svc.CreateRole(ctx, "auditor", "Auditor Duplicate", "Desc")
		if !errors.Is(err, domain.ErrRoleAlreadyExists) {
			t.Errorf("expected ErrRoleAlreadyExists, got: %v", err)
		}
	})

	t.Run("invalid role id fails validation", func(t *testing.T) {
		_, err := svc.CreateRole(ctx, "", "Invalid", "Desc")
		if !errors.Is(err, domain.ErrInvalidRoleID) {
			t.Errorf("expected ErrInvalidRoleID, got: %v", err)
		}
	})
}

func TestServiceListRoles(t *testing.T) {
	ctx := context.Background()
	repo := newMockRoleRepo()
	svc := service.New(repo)

	_, _ = svc.CreateRole(ctx, "role_a", "Role A", "Desc A")
	_, _ = svc.CreateRole(ctx, "role_b", "Role B", "Desc B")

	roles, err := svc.ListRoles(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got: %d", len(roles))
	}
}
