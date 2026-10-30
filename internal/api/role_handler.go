package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
	"github.com/group-project-bridgeon/manager-service/internal/rbac/service"
)

// RoleHandler handles HTTP requests for roles.
type RoleHandler struct {
	service *service.Service
}

// NewRoleHandler constructs a RoleHandler.
func NewRoleHandler(service *service.Service) *RoleHandler {
	return &RoleHandler{service: service}
}

// List handles GET /api/v1/roles.
func (h *RoleHandler) List(c *gin.Context) {
	roles, err := h.service.ListRoles(c.Request.Context())
	if err != nil {
		RespondInternalError(c)
		return
	}
	JSON(c, http.StatusOK, toRoleResponses(roles))
}

// GetByID handles GET /api/v1/roles/:id.
func (h *RoleHandler) GetByID(c *gin.Context) {
	id := c.Param("id")
	role, err := h.service.GetRoleByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrRoleNotFound) {
			Error(c, http.StatusNotFound, "ROLE_NOT_FOUND", "The requested role does not exist", nil)
			return
		}
		if errors.Is(err, domain.ErrInvalidRoleID) {
			Error(c, http.StatusBadRequest, "INVALID_ROLE_ID", err.Error(), nil)
			return
		}
		RespondInternalError(c)
		return
	}
	JSON(c, http.StatusOK, toRoleResponse(*role))
}

// Create handles POST /api/v1/roles.
func (h *RoleHandler) Create(c *gin.Context) {
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid role payload", []ErrorDetail{
			{Field: "body", Message: err.Error()},
		})
		return
	}

	role, err := h.service.CreateRole(c.Request.Context(), req.ID, req.Name, req.Description)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRoleAlreadyExists):
			Error(c, http.StatusConflict, "ROLE_ALREADY_EXISTS", "A role with this ID already exists", nil)
		case errors.Is(err, domain.ErrInvalidRoleID), errors.Is(err, domain.ErrInvalidRoleName):
			Error(c, http.StatusBadRequest, "INVALID_INPUT", err.Error(), nil)
		default:
			RespondInternalError(c)
		}
		return
	}

	JSON(c, http.StatusCreated, toRoleResponse(role))
}
