// Package domain provides pure business entities and rules for approval workflows.
package domain

import (
	"errors"
	"strings"
	"time"
)

// Status represents the lifecycle state of an approval request.
type Status string

const (
	// StatusPending indicates the request is awaiting further approvals.
	StatusPending Status = "pending"
	// StatusApproved indicates all required approval levels have been granted.
	StatusApproved Status = "approved"
	// StatusRejected indicates an approver rejected the request.
	StatusRejected Status = "rejected"
	// StatusExpired indicates the request exceeded its validity window.
	StatusExpired Status = "expired"
)

var (
	// ErrRequestNotFound indicates the request does not exist.
	ErrRequestNotFound = errors.New("approval request not found")
	// ErrRequestAlreadyDecided indicates the request is already approved or rejected.
	ErrRequestAlreadyDecided = errors.New("approval request has already been decided")
	// ErrRequestExpired indicates the request has passed its expiration time.
	ErrRequestExpired = errors.New("approval request has expired")
	// ErrSelfApprovalNotAllowed indicates the requester is forbidden from approving their own request.
	ErrSelfApprovalNotAllowed = errors.New("requester cannot approve their own request")
	// ErrInsufficientRole indicates the actor lacks the authority required for this approval.
	ErrInsufficientRole = errors.New("actor does not possess the required approval role")
	// ErrInvalidAmount indicates that the amount is negative or invalid.
	ErrInvalidAmount = errors.New("approval amount must be positive")
	// ErrInvalidResourceID indicates the resource identifier is missing.
	ErrInvalidResourceID = errors.New("resource id cannot be empty")
	// ErrInvalidRequesterID indicates the requester identifier is missing.
	ErrInvalidRequesterID = errors.New("requester id cannot be empty")
	// ErrDuplicateApproval indicates the actor has already approved a previous level of this request.
	ErrDuplicateApproval = errors.New("actor has already approved a previous level for this request")
	// ErrDuplicateSubmission indicates an active approval request already exists for this resource.
	ErrDuplicateSubmission = errors.New("an active approval request already exists for this resource")
	// ErrConcurrentUpdate indicates that a concurrent transaction modified the request before this decision was committed.
	ErrConcurrentUpdate = errors.New("request was modified concurrently by another transaction")
)

// ApprovalPolicy defines threshold rules for when approvals are required.
type ApprovalPolicy struct {
	ID                string
	Service           string
	ResourceType      string
	MinAmount         float64
	MaxAmount         *float64 // nil means infinity / no upper bound
	RequiredRole      string
	RequiredLevels    int
	AllowSelfApproval bool
}

// ApprovalRequest represents an active or completed approval workflow.
type ApprovalRequest struct {
	ID             string
	Service        string
	ResourceID     string
	Amount         float64
	RequesterID    string
	Status         Status
	CurrentLevel   int
	RequiredLevels int
	ExpiresAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ApprovalAction records an immutable audit decision on a request.
type ApprovalAction struct {
	ID        string
	RequestID string
	ActorID   string
	Action    string // "approve" or "reject"
	Level     int
	Notes     string
	CreatedAt time.Time
}

// CanApprove evaluates whether an actor can approve the request based on business rules.
func (r *ApprovalRequest) CanApprove(actorID string, allowSelfApproval bool) error {
	if r.Status != StatusPending {
		return ErrRequestAlreadyDecided
	}

	if r.ExpiresAt != nil && time.Now().UTC().After(*r.ExpiresAt) {
		return ErrRequestExpired
	}

	if !allowSelfApproval && strings.EqualFold(r.RequesterID, actorID) {
		return ErrSelfApprovalNotAllowed
	}

	return nil
}
