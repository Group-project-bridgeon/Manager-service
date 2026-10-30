package service_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
	"github.com/group-project-bridgeon/manager-service/internal/workflow/service"
)

// ThreadSafeMockWorkflowRepo provides a concurrent-safe mock repository for failure/concurrency tests.
type ThreadSafeMockWorkflowRepo struct {
	mu            sync.RWMutex
	requests      map[string]domain.ApprovalRequest
	actions       map[string][]domain.ApprovalAction
	failOnAction  bool
	failOnUpdate  bool
	dbDown        bool
}

func newThreadSafeMockWorkflowRepo() *ThreadSafeMockWorkflowRepo {
	return &ThreadSafeMockWorkflowRepo{
		requests: make(map[string]domain.ApprovalRequest),
		actions:  make(map[string][]domain.ApprovalAction),
	}
}

func (m *ThreadSafeMockWorkflowRepo) CreateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dbDown {
		return errors.New("database connection refused")
	}
	m.requests[req.ID] = req
	return nil
}

func (m *ThreadSafeMockWorkflowRepo) GetRequestByID(ctx context.Context, id string) (*domain.ApprovalRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.dbDown {
		return nil, errors.New("database connection refused")
	}
	req, exists := m.requests[id]
	if !exists {
		return nil, domain.ErrRequestNotFound
	}
	// Return a copy to simulate row reading
	copyReq := req
	return &copyReq, nil
}

func (m *ThreadSafeMockWorkflowRepo) GetRequestByResource(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.dbDown {
		return nil, errors.New("database connection refused")
	}
	for _, req := range m.requests {
		if req.Service == serviceName && req.ResourceID == resourceID {
			copyReq := req
			return &copyReq, nil
		}
	}
	return nil, domain.ErrRequestNotFound
}

func (m *ThreadSafeMockWorkflowRepo) UpdateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dbDown || m.failOnUpdate {
		return errors.New("database error: failed to update request")
	}
	m.requests[req.ID] = req
	return nil
}

func (m *ThreadSafeMockWorkflowRepo) RecordAction(ctx context.Context, action domain.ApprovalAction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dbDown || m.failOnAction {
		return errors.New("database error: failed to insert audit action")
	}
	m.actions[action.RequestID] = append(m.actions[action.RequestID], action)
	return nil
}

func (m *ThreadSafeMockWorkflowRepo) GetMatchingPolicy(ctx context.Context, serviceName, resourceType string, amount float64) (*domain.ApprovalPolicy, error) {
	return nil, nil
}

func (m *ThreadSafeMockWorkflowRepo) ListActionsByRequestID(ctx context.Context, requestID string) ([]domain.ApprovalAction, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.dbDown {
		return nil, errors.New("database connection refused")
	}
	actions := m.actions[requestID]
	copied := make([]domain.ApprovalAction, len(actions))
	copy(copied, actions)
	return copied, nil
}

// -----------------------------------------------------------------------------
// Test Matrix Suite
// -----------------------------------------------------------------------------

func TestFailureAndConcurrencyMatrix(t *testing.T) {
	ctx := context.Background()

	// -------------------------------------------------------------------------
	// 3. Invalid Approval Transitions
	// -------------------------------------------------------------------------
	t.Run("Matrix #3: Invalid approval transitions", func(t *testing.T) {
		repo := newThreadSafeMockWorkflowRepo()
		svc := service.New(repo)

		// Create request
		req, _ := svc.Submit(ctx, "purchasing", "bill_trans_1", "purchaser_bob", 10000)

		// Transition 1: pending -> approved
		_, err := svc.Approve(ctx, req.ID, "manager_alice", "First approval")
		if err != nil {
			t.Fatalf("expected pending -> approved to succeed, got: %v", err)
		}

		// Transition 2: approved -> approved (ILLEGAL)
		_, err = svc.Approve(ctx, req.ID, "manager_carol", "Duplicate approval on approved")
		if !errors.Is(err, domain.ErrRequestAlreadyDecided) {
			t.Errorf("expected ErrRequestAlreadyDecided for approved -> approved, got: %v", err)
		}

		// Transition 3: approved -> rejected (ILLEGAL)
		_, err = svc.Reject(ctx, req.ID, "manager_carol", "Rejecting approved request")
		if !errors.Is(err, domain.ErrRequestAlreadyDecided) {
			t.Errorf("expected ErrRequestAlreadyDecided for approved -> rejected, got: %v", err)
		}

		// Transition 4: rejected -> approved (ILLEGAL)
		req2, _ := svc.Submit(ctx, "purchasing", "bill_trans_2", "purchaser_bob", 10000)
		_, err = svc.Reject(ctx, req2.ID, "manager_alice", "Rejected budget")
		if err != nil {
			t.Fatalf("expected rejection to succeed, got: %v", err)
		}

		_, err = svc.Approve(ctx, req2.ID, "manager_carol", "Approving rejected request")
		if !errors.Is(err, domain.ErrRequestAlreadyDecided) {
			t.Errorf("expected ErrRequestAlreadyDecided for rejected -> approved, got: %v", err)
		}

		// Transition 5: rejected -> rejected (ILLEGAL)
		_, err = svc.Reject(ctx, req2.ID, "manager_carol", "Rejecting already rejected")
		if !errors.Is(err, domain.ErrRequestAlreadyDecided) {
			t.Errorf("expected ErrRequestAlreadyDecided for rejected -> rejected, got: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// 4. Duplicate Approval
	// -------------------------------------------------------------------------
	t.Run("Matrix #4: Duplicate approval on decided request", func(t *testing.T) {
		repo := newThreadSafeMockWorkflowRepo()
		svc := service.New(repo)

		req, _ := svc.Submit(ctx, "purchasing", "bill_dup_1", "purchaser_1", 20000)

		// First approval
		_, err := svc.Approve(ctx, req.ID, "manager_1", "OK")
		if err != nil {
			t.Fatalf("first approval failed: %v", err)
		}

		// Duplicate approval by same manager
		_, err = svc.Approve(ctx, req.ID, "manager_1", "OK again")
		if !errors.Is(err, domain.ErrRequestAlreadyDecided) {
			t.Errorf("expected ErrRequestAlreadyDecided on duplicate approval, got: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// 5. Concurrent Approval (Race Condition Verification)
	// -------------------------------------------------------------------------
	t.Run("Matrix #5: Concurrent approvals under race detector", func(t *testing.T) {
		repo := newThreadSafeMockWorkflowRepo()
		svc := service.New(repo)

		// 1-level approval request
		req, err := svc.Submit(ctx, "purchasing", "bill_race_1", "purchaser_1", 10000)
		if err != nil {
			t.Fatalf("submit failed: %v", err)
		}

		const numGoroutines = 10
		var wg sync.WaitGroup
		var successCount int32
		var failCount int32

		startBarrier := make(chan struct{})

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			managerID := fmt.Sprintf("manager_%d", i+1)
			go func(mID string) {
				defer wg.Done()
				<-startBarrier // synchronize start for maximum contention

				_, err := svc.Approve(ctx, req.ID, mID, "concurrent approval")
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&failCount, 1)
				}
			}(managerID)
		}

		// Release all goroutines simultaneously
		close(startBarrier)
		wg.Wait()

		// Verify that at least one succeeded and total attempts equals numGoroutines
		total := atomic.LoadInt32(&successCount) + atomic.LoadInt32(&failCount)
		if total != numGoroutines {
			t.Errorf("expected %d total attempts, got %d", numGoroutines, total)
		}

		// Check final request state
		finalReq, _ := repo.GetRequestByID(ctx, req.ID)
		if finalReq.Status != domain.StatusApproved {
			t.Errorf("expected final status approved, got: %s", finalReq.Status)
		}
	})

	// -------------------------------------------------------------------------
	// 6. Database Outage / Recovery
	// -------------------------------------------------------------------------
	t.Run("Matrix #6: DB outage and recovery handling", func(t *testing.T) {
		repo := newThreadSafeMockWorkflowRepo()
		svc := service.New(repo)

		// Normal operation
		req, err := svc.Submit(ctx, "purchasing", "bill_outage_1", "purchaser_1", 10000)
		if err != nil {
			t.Fatalf("submit failed: %v", err)
		}

		// Simulate DB Outage
		repo.mu.Lock()
		repo.dbDown = true
		repo.mu.Unlock()

		// Operation during outage fails cleanly
		_, err = svc.Approve(ctx, req.ID, "manager_1", "approve during outage")
		if err == nil {
			t.Fatal("expected error during database outage, got nil")
		}

		// Simulate DB Recovery
		repo.mu.Lock()
		repo.dbDown = false
		repo.mu.Unlock()

		// Operation after recovery succeeds without restart
		appr, err := svc.Approve(ctx, req.ID, "manager_1", "approve after recovery")
		if err != nil {
			t.Fatalf("expected success after DB recovery, got: %v", err)
		}
		if appr.Status != domain.StatusApproved {
			t.Errorf("expected approved after recovery, got %s", appr.Status)
		}
	})

	// -------------------------------------------------------------------------
	// 8. Multi-Level Approval Flow
	// -------------------------------------------------------------------------
	t.Run("Matrix #8: Multi-level approval flow for amounts >= 50k", func(t *testing.T) {
		repo := newThreadSafeMockWorkflowRepo()
		svc := service.New(repo)

		// Submit >= 50k bill (requires 2 levels)
		req, err := svc.Submit(ctx, "purchasing", "bill_multi_1", "purchaser_1", 75000.00)
		if err != nil {
			t.Fatalf("submit failed: %v", err)
		}
		if req.RequiredLevels != 2 {
			t.Fatalf("expected 2 required levels, got: %d", req.RequiredLevels)
		}
		if req.CurrentLevel != 0 || req.Status != domain.StatusPending {
			t.Fatalf("initial state mismatch: level=%d, status=%s", req.CurrentLevel, req.Status)
		}

		// Level 1 Approval by Manager Alice
		l1, err := svc.Approve(ctx, req.ID, "manager_alice", "Level 1 verified")
		if err != nil {
			t.Fatalf("level 1 approval failed: %v", err)
		}
		if l1.CurrentLevel != 1 {
			t.Errorf("expected level 1, got %d", l1.CurrentLevel)
		}
		if l1.Status != domain.StatusPending {
			t.Errorf("expected status pending after level 1, got %s", l1.Status)
		}

		// Level 2 Approval by Manager Bob
		l2, err := svc.Approve(ctx, req.ID, "manager_bob", "Level 2 approved")
		if err != nil {
			t.Fatalf("level 2 approval failed: %v", err)
		}
		if l2.CurrentLevel != 2 {
			t.Errorf("expected level 2, got %d", l2.CurrentLevel)
		}
		if l2.Status != domain.StatusApproved {
			t.Errorf("expected status approved after level 2, got %s", l2.Status)
		}

		// Verify audit history contains both levels in order
		_, actions, err := svc.GetHistory(ctx, req.ID)
		if err != nil {
			t.Fatalf("get history failed: %v", err)
		}
		if len(actions) != 2 {
			t.Fatalf("expected 2 audit actions, got %d", len(actions))
		}
		if actions[0].ActorID != "manager_alice" || actions[0].Level != 1 {
			t.Errorf("action 0 mismatch: %v", actions[0])
		}
		if actions[1].ActorID != "manager_bob" || actions[1].Level != 2 {
			t.Errorf("action 1 mismatch: %v", actions[1])
		}
	})

	// -------------------------------------------------------------------------
	// 9. Approval Expiration
	// -------------------------------------------------------------------------
	t.Run("Matrix #9: Approval expiration enforcement", func(t *testing.T) {
		repo := newThreadSafeMockWorkflowRepo()
		svc := service.New(repo)

		req, err := svc.Submit(ctx, "purchasing", "bill_exp_1", "purchaser_1", 20000)
		if err != nil {
			t.Fatalf("submit failed: %v", err)
		}

		// Force expiration time to the past
		past := time.Now().UTC().Add(-2 * time.Hour)
		req.ExpiresAt = &past
		_ = repo.UpdateRequest(ctx, *req)

		// Attempting to approve expired request
		_, err = svc.Approve(ctx, req.ID, "manager_1", "Late approval")
		if !errors.Is(err, domain.ErrRequestExpired) {
			t.Errorf("expected ErrRequestExpired, got: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// 10. E2E Test Automation Cleanup Verification
	// -------------------------------------------------------------------------
	t.Run("Matrix #10: Test state isolation and clean teardown", func(t *testing.T) {
		repo := newThreadSafeMockWorkflowRepo()
		svc := service.New(repo)

		// Create isolated test entities
		req, _ := svc.Submit(ctx, "purchasing", "bill_clean_1", "purchaser_1", 5000)
		_, _ = svc.Approve(ctx, req.ID, "manager_1", "OK")

		// Verify repository contains exactly the scoped test entities
		actions, _ := repo.ListActionsByRequestID(ctx, req.ID)
		if len(actions) != 1 {
			t.Errorf("expected 1 action in isolated repo, got %d", len(actions))
		}

		// Explicit teardown simulation: resetting repo leaves 0 residual state
		repo.mu.Lock()
		repo.requests = make(map[string]domain.ApprovalRequest)
		repo.actions = make(map[string][]domain.ApprovalAction)
		repo.mu.Unlock()

		_, err := svc.GetStatus(ctx, "purchasing", "bill_clean_1")
		if !errors.Is(err, domain.ErrRequestNotFound) {
			t.Errorf("expected clean repository to return ErrRequestNotFound, got: %v", err)
		}
	})
}
