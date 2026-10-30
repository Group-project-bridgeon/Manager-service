package api

import (
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
)

// AssignRoleRequest defines the payload for granting a role to a user.
type AssignRoleRequest struct {
	RoleID     string `json:"role_id" binding:"required"`
	AssignedBy string `json:"assigned_by"`
}

// UserRoleResponse represents the JSON output for a role assignment.
type UserRoleResponse struct {
	UserID     string    `json:"user_id"`
	RoleID     string    `json:"role_id"`
	AssignedBy string    `json:"assigned_by"`
	CreatedAt  time.Time `json:"created_at"`
}

func toUserRoleResponse(ur domain.UserRole) UserRoleResponse {
	return UserRoleResponse{
		UserID:     ur.UserID,
		RoleID:     ur.RoleID,
		AssignedBy: ur.AssignedBy,
		CreatedAt:  ur.CreatedAt,
	}
}

// AuthzCheckRequestDTO defines the payload sent by other ERP services to check authorization.
type AuthzCheckRequestDTO struct {
	UserID   string `json:"user_id" binding:"required"`
	Service  string `json:"service" binding:"required"`
	Resource string `json:"resource" binding:"required"`
	Action   string `json:"action" binding:"required"`
}

// AuthzCheckResponseDTO defines the authorization decision returned.
type AuthzCheckResponseDTO struct {
	Allowed bool     `json:"allowed"`
	Roles   []string `json:"roles"`
}
