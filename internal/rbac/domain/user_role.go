package domain

import (
	"errors"
	"strings"
	"time"
)

var (
	// ErrInvalidUserID indicates that the user identifier is missing.
	ErrInvalidUserID = errors.New("user id cannot be empty")
	// ErrUserRoleAlreadyAssigned indicates that the role is already granted to this user.
	ErrUserRoleAlreadyAssigned = errors.New("user already has this role")
	// ErrUserRoleNotFound indicates that the role is not granted to this user.
	ErrUserRoleNotFound = errors.New("user role assignment not found")
)

// UserRole represents the assignment of a Role to a User.
type UserRole struct {
	UserID     string
	RoleID     string
	AssignedBy string
	CreatedAt  time.Time
}

// NewUserRole validates and creates a domain UserRole.
func NewUserRole(userID, roleID, assignedBy string) (UserRole, error) {
	userID = strings.TrimSpace(userID)
	roleID = strings.TrimSpace(strings.ToLower(roleID))

	if userID == "" {
		return UserRole{}, ErrInvalidUserID
	}
	if roleID == "" {
		return UserRole{}, ErrInvalidRoleID
	}

	return UserRole{
		UserID:     userID,
		RoleID:     roleID,
		AssignedBy: strings.TrimSpace(assignedBy),
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// AuthzCheckRequest represents an authorization query from any ERP service.
type AuthzCheckRequest struct {
	UserID   string
	Service  string
	Resource string
	Action   string
}

// AuthzCheckResult represents the authorization decision.
type AuthzCheckResult struct {
	Allowed bool
	Roles   []string
}
