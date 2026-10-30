// Package service implements business use cases for Role-Based Access Control.
package service

import (
	"context"
	"errors"
	"strings"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
)

// RoleRepository defines the data persistence contract required by the Service.
// Clean Architecture: Defined here (where consumed), implemented by internal/rbac/repository.
type RoleRepository interface {
	List(ctx context.Context) ([]domain.Role, error)
	GetByID(ctx context.Context, id string) (*domain.Role, error)
	Create(ctx context.Context, role domain.Role) error
}

// Service coordinates RBAC operations and enforces business invariants.
type Service struct {
	repo RoleRepository
}

// New constructs an RBAC Service with the required repository.
func New(repo RoleRepository) *Service {
	return &Service{repo: repo}
}

// ListRoles retrieves all configured roles.
func (s *Service) ListRoles(ctx context.Context) ([]domain.Role, error) {
	return s.repo.List(ctx)
}

// GetRoleByID fetches a single role by its identifier.
func (s *Service) GetRoleByID(ctx context.Context, id string) (*domain.Role, error) {
	id = strings.TrimSpace(strings.ToLower(id))
	if id == "" {
		return nil, domain.ErrInvalidRoleID
	}
	return s.repo.GetByID(ctx, id)
}

// CreateRole validates business rules and registers a new role.
func (s *Service) CreateRole(ctx context.Context, id, name, description string) (domain.Role, error) {
	role, err := domain.NewRole(id, name, description)
	if err != nil {
		return domain.Role{}, err
	}

	// Check if role already exists
	existing, err := s.repo.GetByID(ctx, role.ID)
	if err == nil && existing != nil {
		return domain.Role{}, domain.ErrRoleAlreadyExists
	}
	if err != nil && !errors.Is(err, domain.ErrRoleNotFound) {
		return domain.Role{}, err
	}

	if err := s.repo.Create(ctx, role); err != nil {
		return domain.Role{}, err
	}

	return role, nil
}
