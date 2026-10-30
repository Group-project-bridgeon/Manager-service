// Package service implements business use cases for Role-Based Access Control.
package service

import (
	"context"
	"errors"
	"strings"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
)

// RoleRepository defines the data persistence contract for roles.
type RoleRepository interface {
	List(ctx context.Context) ([]domain.Role, error)
	GetByID(ctx context.Context, id string) (*domain.Role, error)
	Create(ctx context.Context, role domain.Role) error
}

// UserRoleRepository defines the data persistence contract for user-role assignments and authorization queries.
type UserRoleRepository interface {
	Assign(ctx context.Context, ur domain.UserRole) error
	Revoke(ctx context.Context, userID, roleID string) error
	GetRolesByUserID(ctx context.Context, userID string) ([]domain.Role, error)
	CheckPermission(ctx context.Context, userID, serviceName, resource, action string) (bool, []string, error)
}

// Service coordinates RBAC operations and enforces business invariants.
type Service struct {
	roleRepo     RoleRepository
	userRoleRepo UserRoleRepository
}

// New constructs an RBAC Service with the required repositories.
func New(roleRepo RoleRepository, userRoleRepo UserRoleRepository) *Service {
	return &Service{
		roleRepo:     roleRepo,
		userRoleRepo: userRoleRepo,
	}
}

// ListRoles retrieves all configured roles.
func (s *Service) ListRoles(ctx context.Context) ([]domain.Role, error) {
	return s.roleRepo.List(ctx)
}

// GetRoleByID fetches a single role by its identifier.
func (s *Service) GetRoleByID(ctx context.Context, id string) (*domain.Role, error) {
	id = strings.TrimSpace(strings.ToLower(id))
	if id == "" {
		return nil, domain.ErrInvalidRoleID
	}
	return s.roleRepo.GetByID(ctx, id)
}

// CreateRole validates business rules and registers a new role.
func (s *Service) CreateRole(ctx context.Context, id, name, description string) (domain.Role, error) {
	role, err := domain.NewRole(id, name, description)
	if err != nil {
		return domain.Role{}, err
	}

	existing, err := s.roleRepo.GetByID(ctx, role.ID)
	if err == nil && existing != nil {
		return domain.Role{}, domain.ErrRoleAlreadyExists
	}
	if err != nil && !errors.Is(err, domain.ErrRoleNotFound) {
		return domain.Role{}, err
	}

	if err := s.roleRepo.Create(ctx, role); err != nil {
		return domain.Role{}, err
	}

	return role, nil
}

// AssignRole grants a role to a user after verifying that the role exists.
func (s *Service) AssignRole(ctx context.Context, userID, roleID, assignedBy string) (domain.UserRole, error) {
	ur, err := domain.NewUserRole(userID, roleID, assignedBy)
	if err != nil {
		return domain.UserRole{}, err
	}

	// Verify the role actually exists
	_, err = s.roleRepo.GetByID(ctx, ur.RoleID)
	if err != nil {
		return domain.UserRole{}, err
	}

	if err := s.userRoleRepo.Assign(ctx, ur); err != nil {
		return domain.UserRole{}, err
	}

	return ur, nil
}

// RevokeRole removes a role from a user.
func (s *Service) RevokeRole(ctx context.Context, userID, roleID string) error {
	userID = strings.TrimSpace(userID)
	roleID = strings.TrimSpace(strings.ToLower(roleID))

	if userID == "" {
		return domain.ErrInvalidUserID
	}
	if roleID == "" {
		return domain.ErrInvalidRoleID
	}

	return s.userRoleRepo.Revoke(ctx, userID, roleID)
}

// GetUserRoles retrieves all roles granted to a given user.
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]domain.Role, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, domain.ErrInvalidUserID
	}
	return s.userRoleRepo.GetRolesByUserID(ctx, userID)
}

// Authorize checks whether a user has permission to perform an action on a service resource.
func (s *Service) Authorize(ctx context.Context, req domain.AuthzCheckRequest) (domain.AuthzCheckResult, error) {
	userID := strings.TrimSpace(req.UserID)
	if userID == "" {
		return domain.AuthzCheckResult{Allowed: false}, domain.ErrInvalidUserID
	}

	allowed, roles, err := s.userRoleRepo.CheckPermission(ctx, userID, req.Service, req.Resource, req.Action)
	if err != nil {
		return domain.AuthzCheckResult{Allowed: false}, err
	}

	return domain.AuthzCheckResult{
		Allowed: allowed,
		Roles:   roles,
	}, nil
}
