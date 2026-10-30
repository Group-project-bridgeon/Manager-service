package domain_test

import (
	"errors"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
)

func TestNewUserRole(t *testing.T) {
	t.Run("valid user role creation", func(t *testing.T) {
		ur, err := domain.NewUserRole("usr_100", "MANAGER", "admin_01")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ur.UserID != "usr_100" {
			t.Errorf("expected user ID 'usr_100', got: %s", ur.UserID)
		}
		if ur.RoleID != "manager" {
			t.Errorf("expected role ID lowercase 'manager', got: %s", ur.RoleID)
		}
		if ur.AssignedBy != "admin_01" {
			t.Errorf("expected assigned_by 'admin_01', got: %s", ur.AssignedBy)
		}
	})

	t.Run("empty user id returns ErrInvalidUserID", func(t *testing.T) {
		_, err := domain.NewUserRole("   ", "manager", "admin")
		if !errors.Is(err, domain.ErrInvalidUserID) {
			t.Errorf("expected ErrInvalidUserID, got: %v", err)
		}
	})

	t.Run("empty role id returns ErrInvalidRoleID", func(t *testing.T) {
		_, err := domain.NewUserRole("usr_100", "   ", "admin")
		if !errors.Is(err, domain.ErrInvalidRoleID) {
			t.Errorf("expected ErrInvalidRoleID, got: %v", err)
		}
	})
}
