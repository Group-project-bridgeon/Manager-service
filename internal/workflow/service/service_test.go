package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
	"github.com/group-project-bridgeon/manager-service/internal/workflow/service"
)

type mockWorkflowRepo struct {
	requests map[string]domain.ApprovalRequest
	actions  map[string][]domain.ApprovalAction
}

func newMockWorkflowRepo() *mockWorkflowRepo {
	return &mockWorkflowRepo{
		requests: make(map[string]domain.ApprovalRequest),
		actions:  make(map[string][]domain.ApprovalAction),
	}
}

func (m *mockWorkflowRepo) CreateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	m.requests[req.ID] = req
	return nil
}

func (m *mockWorkflowRepo) GetRequestByID(ctx context.Context, id string) (*domain.ApprovalRequest, error) {
	req, exists := m.requests[id]
	if !exists {
		return nil, domain.ErrRequestNotFound
	}
	return &req, nil
}

func (m *mockWorkflowRepo) GetRequestByResource(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error) {
	for _, req := range m.requests {
		if req.Service == serviceName && req.ResourceID == resourceID {
			return &req, nil
		}
	}
	return nil, domain.ErrRequestNotFound
}

func (m *mockWorkflowRepo) GetActiveRequestByResource(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error) {
	for _, req := range m.requests {
		if req.Service == serviceName && req.ResourceID == resourceID && (req.Status == domain.StatusPending || req.Status == domain.StatusApproved) {
			return &req, nil
		}
	}
	return nil, nil
}

func (m *mockWorkflowRepo) UpdateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	m.requests[req.ID] = req
	return nil
}

func (m *mockWorkflowRepo) RecordAction(ctx context.Context, action domain.ApprovalAction) error {
	m.actions[action.RequestID] = append(m.actions[action.RequestID], action)
	return nil
}

func (m *mockWorkflowRepo) ApplyDecisionTx(ctx context.Context, req domain.ApprovalRequest, action domain.ApprovalAction, expectedLevel int, expectedStatus domain.Status) error {
	existing, exists := m.requests[req.ID]
	if !exists {
		return domain.ErrRequestNotFound
	}
	if existing.CurrentLevel != expectedLevel || existing.Status != expectedStatus {
		return domain.ErrConcurrentUpdate
	}
	m.requests[req.ID] = req
	m.actions[action.RequestID] = append(m.actions[action.RequestID], action)
	return nil
}

func (m *mockWorkflowRepo) GetMatchingPolicy(ctx context.Context, serviceName, resourceType string, amount float64) (*domain.ApprovalPolicy, error) {
	return nil, nil // Fallback to default thresholds
}

func (m *mockWorkflowRepo) ListActionsByRequestID(ctx context.Context, requestID string) ([]domain.ApprovalAction, error) {
	return m.actions[requestID], nil
}

func TestWorkflowThresholds(t *testing.T) {
	ctx := context.Background()
	repo := newMockWorkflowRepo()
	svc := service.New(repo)

	t.Run("under 50k requires 1 level", func(t *testing.T) {
		req, err := svc.Submit(ctx, "purchasing", "bill_01", "purchaser_bob", 25000.00)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.RequiredLevels != 1 {
			t.Errorf("expected 1 required level for 25k, got: %d", req.RequiredLevels)
		}

		// Approve
		appr, err := svc.Approve(ctx, req.ID, "mgr_1", "Looks good")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if appr.Status != domain.StatusApproved {
			t.Errorf("expected approved status after 1 approval, got: %s", appr.Status)
		}
	})

	t.Run("50k and above requires 2 levels", func(t *testing.T) {
		req, err := svc.Submit(ctx, "purchasing", "bill_02", "purchaser_bob", 75000.00)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.RequiredLevels != 2 {
			t.Errorf("expected 2 required levels for 75k, got: %d", req.RequiredLevels)
		}

		// Level 1 Approval
		l1, err := svc.Approve(ctx, req.ID, "mgr_1", "First manager approval")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if l1.Status != domain.StatusPending {
			t.Errorf("expected status pending after level 1 approval, got: %s", l1.Status)
		}

		// Level 2 Approval
		l2, err := svc.Approve(ctx, req.ID, "mgr_2", "Second level approval")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if l2.Status != domain.StatusApproved {
			t.Errorf("expected status approved after level 2 approval, got: %s", l2.Status)
		}

		// Verify history audit log
		_, actions, err := svc.GetHistory(ctx, req.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(actions) != 2 {
			t.Errorf("expected 2 audit actions, got: %d", len(actions))
		}
	})

	t.Run("self approval forbidden", func(t *testing.T) {
		req, err := svc.Submit(ctx, "purchasing", "bill_03", "purchaser_bob", 10000.00)
		if err != nil {
			t.Fatalf("unexpected submit error: %v", err)
		}

		_, err = svc.Approve(ctx, req.ID, "purchaser_bob", "Attempt self-approve")
		if !errors.Is(err, domain.ErrSelfApprovalNotAllowed) {
			t.Errorf("expected ErrSelfApprovalNotAllowed, got: %v", err)
		}
	})

	t.Run("rejection marks request rejected", func(t *testing.T) {
		req, _ := svc.Submit(ctx, "purchasing", "bill_04", "purchaser_bob", 10000.00)
		rej, err := svc.Reject(ctx, req.ID, "mgr_1", "Budget exceeded")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rej.Status != domain.StatusRejected {
			t.Errorf("expected status rejected, got: %s", rej.Status)
		}

		// Cannot approve already rejected request
		_, err = svc.Approve(ctx, req.ID, "mgr_2", "Cannot approve")
		if !errors.Is(err, domain.ErrRequestAlreadyDecided) {
			t.Errorf("expected ErrRequestAlreadyDecided, got: %v", err)
		}
	})
}
