package api

import (
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
)

// SubmitApprovalRequestDTO represents the payload to submit a resource for approval.
type SubmitApprovalRequestDTO struct {
	Service     string  `json:"service" binding:"required"`
	ResourceID  string  `json:"resource_id" binding:"required"`
	RequesterID string  `json:"requester_id" binding:"required"`
	Amount      float64 `json:"amount" binding:"required,gt=0"`
}

// ActionRequestDTO represents the payload for approving or rejecting a request.
type ActionRequestDTO struct {
	ActorID string `json:"actor_id" binding:"required"`
	Notes   string `json:"notes"`
}

// ApprovalRequestResponseDTO represents the JSON projection of an approval request.
type ApprovalRequestResponseDTO struct {
	ID             string     `json:"id"`
	Service        string     `json:"service"`
	ResourceID     string     `json:"resource_id"`
	Amount         float64    `json:"amount"`
	RequesterID    string     `json:"requester_id"`
	Status         string     `json:"status"`
	CurrentLevel   int        `json:"current_level"`
	RequiredLevels int        `json:"required_levels"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ApprovalActionResponseDTO represents a single audit decision.
type ApprovalActionResponseDTO struct {
	ID        string    `json:"id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	Level     int       `json:"level"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
}

// ApprovalHistoryResponseDTO includes the request and its complete audit history.
type ApprovalHistoryResponseDTO struct {
	Request ApprovalRequestResponseDTO  `json:"request"`
	Actions []ApprovalActionResponseDTO `json:"actions"`
}

func toApprovalResponse(r domain.ApprovalRequest) ApprovalRequestResponseDTO {
	return ApprovalRequestResponseDTO{
		ID:             r.ID,
		Service:        r.Service,
		ResourceID:     r.ResourceID,
		Amount:         r.Amount,
		RequesterID:    r.RequesterID,
		Status:         string(r.Status),
		CurrentLevel:   r.CurrentLevel,
		RequiredLevels: r.RequiredLevels,
		ExpiresAt:      r.ExpiresAt,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
}

func toActionResponses(actions []domain.ApprovalAction) []ApprovalActionResponseDTO {
	dtos := make([]ApprovalActionResponseDTO, 0, len(actions))
	for _, a := range actions {
		dtos = append(dtos, ApprovalActionResponseDTO{
			ID:        a.ID,
			ActorID:   a.ActorID,
			Action:    a.Action,
			Level:     a.Level,
			Notes:     a.Notes,
			CreatedAt: a.CreatedAt,
		})
	}
	return dtos
}
