// Package service implements the core approval workflow engine use cases.
package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
)

// WorkflowRepository defines persistence requirements for approvals.
type WorkflowRepository interface {
	CreateRequest(ctx context.Context, req domain.ApprovalRequest) error
	GetRequestByID(ctx context.Context, id string) (*domain.ApprovalRequest, error)
	GetRequestByResource(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error)
	GetActiveRequestByResource(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error)
	UpdateRequest(ctx context.Context, req domain.ApprovalRequest) error
	RecordAction(ctx context.Context, action domain.ApprovalAction) error
	ApplyDecisionTx(ctx context.Context, req domain.ApprovalRequest, action domain.ApprovalAction, expectedLevel int, expectedStatus domain.Status) error
	GetMatchingPolicy(ctx context.Context, serviceName, resourceType string, amount float64) (*domain.ApprovalPolicy, error)
	ListActionsByRequestID(ctx context.Context, requestID string) ([]domain.ApprovalAction, error)
}

// Authorizer evaluates role-based authority against workflow approval policies.
type Authorizer interface {
	CheckPermission(ctx context.Context, userID, serviceName, resource, action string) (bool, []string, error)
}

// Service coordinates approval workflows.
type Service struct {
	repo       WorkflowRepository
	authorizer Authorizer
}

// New constructs an approval workflow Service with optional policy authorizer.
func New(repo WorkflowRepository, authorizer ...Authorizer) *Service {
	s := &Service{
		repo: repo,
	}
	if len(authorizer) > 0 && authorizer[0] != nil {
		s.authorizer = authorizer[0]
	}
	return s
}

// Submit registers a new resource for approval.
func (s *Service) Submit(ctx context.Context, serviceName, resourceID, requesterID string, amount float64) (*domain.ApprovalRequest, error) {
	serviceName = strings.TrimSpace(serviceName)
	resourceID = strings.TrimSpace(resourceID)
	requesterID = strings.TrimSpace(requesterID)

	if serviceName == "" {
		return nil, fmt.Errorf("service cannot be empty")
	}
	if resourceID == "" {
		return nil, domain.ErrInvalidResourceID
	}
	if requesterID == "" {
		return nil, domain.ErrInvalidRequesterID
	}
	if amount <= 0 {
		return nil, domain.ErrInvalidAmount
	}

	// Prevent duplicate submissions: reject if an active (pending or approved) request already exists for this resource
	activeReq, err := s.repo.GetActiveRequestByResource(ctx, serviceName, resourceID)
	if err == nil && activeReq != nil {
		if activeReq.Status == domain.StatusPending {
			return nil, domain.ErrDuplicateSubmission
		}
		if activeReq.Status == domain.StatusApproved {
			return nil, domain.ErrRequestAlreadyDecided
		}
	}

	// Dynamic Thresholds: Default to 1 level for < 50k, 2 levels for >= 50k
	requiredLevels := 1
	if amount >= 50000 {
		requiredLevels = 2
	}

	// Check if a custom policy exists in DB
	if policy, err := s.repo.GetMatchingPolicy(ctx, serviceName, "bill", amount); err == nil && policy != nil {
		requiredLevels = policy.RequiredLevels
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour) // 3-day approval window

	req := domain.ApprovalRequest{
		ID:             newUUID(),
		Service:        serviceName,
		ResourceID:     resourceID,
		Amount:         amount,
		RequesterID:    requesterID,
		Status:         domain.StatusPending,
		CurrentLevel:   0,
		RequiredLevels: requiredLevels,
		ExpiresAt:      &expiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.CreateRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("creating approval request: %w", err)
	}

	return &req, nil
}

// Approve grants an approval level on a pending request.
func (s *Service) Approve(ctx context.Context, requestID, actorID, notes string) (*domain.ApprovalRequest, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return nil, domain.ErrInvalidRequesterID
	}

	req, getErr := s.repo.GetRequestByID(ctx, requestID)
	if getErr != nil {
		return nil, getErr
	}

	allowSelfApproval := false
	var requiredRole string
	if policy, pErr := s.repo.GetMatchingPolicy(ctx, req.Service, "bill", req.Amount); pErr == nil && policy != nil {
		allowSelfApproval = policy.AllowSelfApproval
		requiredRole = policy.RequiredRole
	}

	// 1. Check self-approval and lifecycle constraints
	if checkErr := req.CanApprove(actorID, allowSelfApproval); checkErr != nil {
		return nil, checkErr
	}

	// 2. Enforce approval-policy role authorization if policy specifies a required role
	if requiredRole != "" && s.authorizer != nil {
		allowed, roles, authErr := s.authorizer.CheckPermission(ctx, actorID, req.Service, "bill", "approve")
		if authErr != nil {
			return nil, fmt.Errorf("verifying approval role authority: %w", authErr)
		}
		hasRole := false
		for _, r := range roles {
			if r == requiredRole || r == "admin" {
				hasRole = true
				break
			}
		}
		if !hasRole && !allowed {
			return nil, domain.ErrInsufficientRole
		}
	}

	// 3. Enforce four-eyes principle (no duplicate approvals by same actor in multi-level requests)
	actions, err := s.repo.ListActionsByRequestID(ctx, requestID)
	if err == nil {
		for _, a := range actions {
			if a.Action == "approve" && strings.EqualFold(a.ActorID, actorID) {
				return nil, domain.ErrDuplicateApproval
			}
		}
	}

	expectedLevel := req.CurrentLevel
	expectedStatus := req.Status

	req.CurrentLevel++
	if req.CurrentLevel >= req.RequiredLevels {
		req.Status = domain.StatusApproved
	}
	req.UpdatedAt = time.Now().UTC()

	action := domain.ApprovalAction{
		ID:        newUUID(),
		RequestID: req.ID,
		ActorID:   actorID,
		Action:    "approve",
		Level:     req.CurrentLevel,
		Notes:     strings.TrimSpace(notes),
		CreatedAt: time.Now().UTC(),
	}

	if err := s.repo.ApplyDecisionTx(ctx, *req, action, expectedLevel, expectedStatus); err != nil {
		return nil, err
	}

	return req, nil
}

// Reject terminates a request with a rejected decision.
func (s *Service) Reject(ctx context.Context, requestID, actorID, notes string) (*domain.ApprovalRequest, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return nil, domain.ErrInvalidRequesterID
	}

	req, err := s.repo.GetRequestByID(ctx, requestID)
	if err != nil {
		return nil, err
	}

	if req.Status != domain.StatusPending {
		return nil, domain.ErrRequestAlreadyDecided
	}

	expectedLevel := req.CurrentLevel
	expectedStatus := req.Status

	req.Status = domain.StatusRejected
	req.UpdatedAt = time.Now().UTC()

	action := domain.ApprovalAction{
		ID:        newUUID(),
		RequestID: req.ID,
		ActorID:   actorID,
		Action:    "reject",
		Level:     req.CurrentLevel + 1,
		Notes:     strings.TrimSpace(notes),
		CreatedAt: time.Now().UTC(),
	}

	if err := s.repo.ApplyDecisionTx(ctx, *req, action, expectedLevel, expectedStatus); err != nil {
		return nil, err
	}

	return req, nil
}

// GetStatus returns the current approval state for an ERP resource.
func (s *Service) GetStatus(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error) {
	return s.repo.GetRequestByResource(ctx, serviceName, resourceID)
}

// GetHistory retrieves the approval request and its full audit trail.
func (s *Service) GetHistory(ctx context.Context, requestID string) (*domain.ApprovalRequest, []domain.ApprovalAction, error) {
	req, err := s.repo.GetRequestByID(ctx, requestID)
	if err != nil {
		return nil, nil, err
	}

	actions, err := s.repo.ListActionsByRequestID(ctx, requestID)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving audit actions: %w", err)
	}

	return req, actions, nil
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
