package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
	"github.com/group-project-bridgeon/manager-service/internal/workflow/service"
)

// WorkflowHandler handles approval workflow endpoints.
type WorkflowHandler struct {
	service *service.Service
}

// NewWorkflowHandler constructs a WorkflowHandler.
func NewWorkflowHandler(service *service.Service) *WorkflowHandler {
	return &WorkflowHandler{service: service}
}

// Submit handles POST /api/v1/approvals/submit.
func (h *WorkflowHandler) Submit(c *gin.Context) {
	var req SubmitApprovalRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid submission payload", []ErrorDetail{
			{Field: "body", Message: err.Error()},
		})
		return
	}

	approval, err := h.service.Submit(c.Request.Context(), req.Service, req.ResourceID, req.RequesterID, req.Amount)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidAmount), errors.Is(err, domain.ErrInvalidResourceID), errors.Is(err, domain.ErrInvalidRequesterID):
			Error(c, http.StatusBadRequest, "INVALID_INPUT", err.Error(), nil)
		default:
			RespondInternalError(c)
		}
		return
	}

	JSON(c, http.StatusCreated, toApprovalResponse(*approval))
}

// Approve handles POST /api/v1/approvals/:id/approve.
func (h *WorkflowHandler) Approve(c *gin.Context) {
	requestID := c.Param("id")
	var req ActionRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid action payload", []ErrorDetail{
			{Field: "body", Message: err.Error()},
		})
		return
	}

	appr, err := h.service.Approve(c.Request.Context(), requestID, req.ActorID, req.Notes)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRequestNotFound):
			Error(c, http.StatusNotFound, "REQUEST_NOT_FOUND", "Approval request not found", nil)
		case errors.Is(err, domain.ErrSelfApprovalNotAllowed):
			Error(c, http.StatusForbidden, "SELF_APPROVAL_FORBIDDEN", "Requester cannot approve their own bill", nil)
		case errors.Is(err, domain.ErrInsufficientRole):
			Error(c, http.StatusForbidden, "INSUFFICIENT_ROLE", "Actor lacks manager approval authority", nil)
		case errors.Is(err, domain.ErrRequestAlreadyDecided):
			Error(c, http.StatusConflict, "REQUEST_ALREADY_DECIDED", "Request is already decided", nil)
		case errors.Is(err, domain.ErrRequestExpired):
			Error(c, http.StatusGone, "REQUEST_EXPIRED", "Approval request has expired", nil)
		default:
			RespondInternalError(c)
		}
		return
	}

	JSON(c, http.StatusOK, toApprovalResponse(*appr))
}

// Reject handles POST /api/v1/approvals/:id/reject.
func (h *WorkflowHandler) Reject(c *gin.Context) {
	requestID := c.Param("id")
	var req ActionRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid action payload", []ErrorDetail{
			{Field: "body", Message: err.Error()},
		})
		return
	}

	appr, err := h.service.Reject(c.Request.Context(), requestID, req.ActorID, req.Notes)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRequestNotFound):
			Error(c, http.StatusNotFound, "REQUEST_NOT_FOUND", "Approval request not found", nil)
		case errors.Is(err, domain.ErrRequestAlreadyDecided):
			Error(c, http.StatusConflict, "REQUEST_ALREADY_DECIDED", "Request is already decided", nil)
		default:
			RespondInternalError(c)
		}
		return
	}

	JSON(c, http.StatusOK, toApprovalResponse(*appr))
}

// GetStatus handles GET /api/v1/approvals/status?service=purchasing&resource_id=bill_100.
func (h *WorkflowHandler) GetStatus(c *gin.Context) {
	serviceName := c.Query("service")
	resourceID := c.Query("resource_id")

	if serviceName == "" || resourceID == "" {
		Error(c, http.StatusBadRequest, "INVALID_QUERY", "service and resource_id query parameters are required", nil)
		return
	}

	appr, err := h.service.GetStatus(c.Request.Context(), serviceName, resourceID)
	if err != nil {
		if errors.Is(err, domain.ErrRequestNotFound) {
			Error(c, http.StatusNotFound, "REQUEST_NOT_FOUND", "No approval record found for resource", nil)
			return
		}
		RespondInternalError(c)
		return
	}

	JSON(c, http.StatusOK, toApprovalResponse(*appr))
}

// GetHistory handles GET /api/v1/approvals/:id.
func (h *WorkflowHandler) GetHistory(c *gin.Context) {
	requestID := c.Param("id")

	appr, actions, err := h.service.GetHistory(c.Request.Context(), requestID)
	if err != nil {
		if errors.Is(err, domain.ErrRequestNotFound) {
			Error(c, http.StatusNotFound, "REQUEST_NOT_FOUND", "Approval request not found", nil)
			return
		}
		RespondInternalError(c)
		return
	}

	JSON(c, http.StatusOK, ApprovalHistoryResponseDTO{
		Request: toApprovalResponse(*appr),
		Actions: toActionResponses(actions),
	})
}
