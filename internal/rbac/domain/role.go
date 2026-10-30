// Package domain contains pure business entities, value objects, and domain errors for RBAC.
package domain

import (
	"errors"
	"strings"
	"time"
)

var (
	// ErrRoleNotFound indicates that the requested role does not exist.
	ErrRoleNotFound = errors.New("role not found")
	// ErrRoleAlreadyExists indicates that a role with this identifier already exists.
	ErrRoleAlreadyExists = errors.New("role already exists")
	// ErrInvalidRoleID indicates that the role identifier violates naming rules.
	ErrInvalidRoleID = errors.New("role id must be lowercase alphanumeric and not empty")
	// ErrInvalidRoleName indicates that the human-readable role name is missing.
	ErrInvalidRoleName = errors.New("role name cannot be empty")
)

// Role represents a business role within the ERP system.
type Role struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewRole validates and creates a new domain Role.
func NewRole(id, name, description string) (Role, error) {
	id = strings.TrimSpace(strings.ToLower(id))
	name = strings.TrimSpace(name)

	if id == "" {
		return Role{}, ErrInvalidRoleID
	}
	if name == "" {
		return Role{}, ErrInvalidRoleName
	}

	now := time.Now().UTC()
	return Role{
		ID:          id,
		Name:        name,
		Description: strings.TrimSpace(description),
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}
