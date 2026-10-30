package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
	"github.com/group-project-bridgeon/manager-service/internal/rbac/service"
)

// UserRoleHandler handles user role management and authorization checks.
type UserRoleHandler struct {
	service *service.Service
}

// NewUserRoleHandler constructs a UserRoleHandler.
func NewUserRoleHandler(service *service.Service) *UserRoleHandler {
	return &UserRoleHandler{service: service}
}

// Assign handles POST /api/v1/users/:id/roles.
func (h *UserRoleHandler) Assign(c *gin.Context) {
	userID := c.Param("id")
	var req AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid assignment payload", []ErrorDetail{
			{Field: "body", Message: err.Error()},
		})
		return
	}

	ur, err := h.service.AssignRole(c.Request.Context(), userID, req.RoleID, req.AssignedBy)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRoleNotFound):
			Error(c, http.StatusNotFound, "ROLE_NOT_FOUND", "The specified role does not exist", nil)
		case errors.Is(err, domain.ErrUserRoleAlreadyAssigned):
			Error(c, http.StatusConflict, "ROLE_ALREADY_ASSIGNED", "User already has this role", nil)
		case errors.Is(err, domain.ErrInvalidUserID), errors.Is(err, domain.ErrInvalidRoleID):
			Error(c, http.StatusBadRequest, "INVALID_INPUT", err.Error(), nil)
		default:
			RespondInternalError(c)
		}
		return
	}

	JSON(c, http.StatusCreated, toUserRoleResponse(ur))
}

// ListUserRoles handles GET /api/v1/users/:id/roles.
func (h *UserRoleHandler) ListUserRoles(c *gin.Context) {
	userID := c.Param("id")
	roles, err := h.service.GetUserRoles(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidUserID) {
			Error(c, http.StatusBadRequest, "INVALID_USER_ID", err.Error(), nil)
			return
		}
		RespondInternalError(c)
		return
	}

	JSON(c, http.StatusOK, toRoleResponses(roles))
}

// Revoke handles DELETE /api/v1/users/:id/roles/:role_id.
func (h *UserRoleHandler) Revoke(c *gin.Context) {
	userID := c.Param("id")
	roleID := c.Param("role_id")

	err := h.service.RevokeRole(c.Request.Context(), userID, roleID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserRoleNotFound):
			Error(c, http.StatusNotFound, "ASSIGNMENT_NOT_FOUND", "User does not have this role", nil)
		case errors.Is(err, domain.ErrInvalidUserID), errors.Is(err, domain.ErrInvalidRoleID):
			Error(c, http.StatusBadRequest, "INVALID_INPUT", err.Error(), nil)
		default:
			RespondInternalError(c)
		}
		return
	}

	JSON(c, http.StatusOK, gin.H{"revoked": true})
}

// CheckAuthz handles POST /api/v1/authz/check.
func (h *UserRoleHandler) CheckAuthz(c *gin.Context) {
	var req AuthzCheckRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid authorization request", []ErrorDetail{
			{Field: "body", Message: err.Error()},
		})
		return
	}

	decision, err := h.service.Authorize(c.Request.Context(), domain.AuthzCheckRequest{
		UserID:   req.UserID,
		Service:  req.Service,
		Resource: req.Resource,
		Action:   req.Action,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidUserID) {
			Error(c, http.StatusBadRequest, "INVALID_USER_ID", err.Error(), nil)
			return
		}
		RespondInternalError(c)
		return
	}

	JSON(c, http.StatusOK, AuthzCheckResponseDTO{
		Allowed: decision.Allowed,
		Roles:   decision.Roles,
	})
}
