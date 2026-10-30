package api

import (
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
)

// CreateRoleRequest defines the payload for registering a new role.
type CreateRoleRequest struct {
	ID          string `json:"id" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

// RoleResponse defines the JSON projection returned to clients.
type RoleResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toRoleResponse(r domain.Role) RoleResponse {
	return RoleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func toRoleResponses(roles []domain.Role) []RoleResponse {
	dtos := make([]RoleResponse, 0, len(roles))
	for _, r := range roles {
		dtos = append(dtos, toRoleResponse(r))
	}
	return dtos
}
