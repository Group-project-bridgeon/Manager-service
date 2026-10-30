package domain_test

import (
	"errors"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
)

func TestNewRole(t *testing.T) {
	t.Run("valid role creation", func(t *testing.T) {
		role, err := domain.NewRole("CUSTOM_MANAGER", "Custom Manager", "Handles specific branch approvals")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if role.ID != "custom_manager" {
			t.Errorf("expected role ID normalized to lowercase 'custom_manager', got: %s", role.ID)
		}
		if role.Name != "Custom Manager" {
			t.Errorf("expected role name 'Custom Manager', got: %s", role.Name)
		}
		if role.CreatedAt.IsZero() || role.UpdatedAt.IsZero() {
			t.Errorf("expected timestamps to be initialized")
		}
	})

	t.Run("empty id returns ErrInvalidRoleID", func(t *testing.T) {
		_, err := domain.NewRole("  ", "Manager", "Desc")
		if !errors.Is(err, domain.ErrInvalidRoleID) {
			t.Errorf("expected ErrInvalidRoleID, got: %v", err)
		}
	})

	t.Run("empty name returns ErrInvalidRoleName", func(t *testing.T) {
		_, err := domain.NewRole("manager", "   ", "Desc")
		if !errors.Is(err, domain.ErrInvalidRoleName) {
			t.Errorf("expected ErrInvalidRoleName, got: %v", err)
		}
	})
}
