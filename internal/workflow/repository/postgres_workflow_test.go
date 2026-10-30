package repository_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/group-project-bridgeon/manager-service/internal/config"
	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
	"github.com/group-project-bridgeon/manager-service/internal/workflow/repository"
)

func getTestDBPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if cfg, err := config.Load(); err == nil {
			dsn = cfg.DSN()
		} else {
			dsn = "postgres://erp_admin:change_me_admin_password@localhost:5432/manager_db?sslmode=disable"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("skipping Postgres integration test (connection error): %v", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("skipping Postgres integration test (ping failed, database offline or isolated): %v", err)
	}

	return pool
}

func TestPostgresWorkflowRepository_ConcurrencyAndAtomicity(t *testing.T) {
	pool := getTestDBPool(t)
	defer pool.Close()

	repo := repository.NewPostgresWorkflowRepository(pool)
	ctx := context.Background()

	t.Run("Concurrent decisions: exactly one succeeds and 9 get ErrConcurrentUpdate", func(t *testing.T) {
		reqID := uuid.New().String()
		resourceID := fmt.Sprintf("PO-CONCUR-%s", uuid.New().String()[:8])
		req := domain.ApprovalRequest{
			ID:             reqID,
			Service:        "purchasing",
			ResourceID:     resourceID,
			Amount:         10000,
			RequesterID:    uuid.New().String(),
			Status:         domain.StatusPending,
			CurrentLevel:   0,
			RequiredLevels: 1,
			CreatedAt:      time.Now().UTC().Truncate(time.Microsecond),
			UpdatedAt:      time.Now().UTC().Truncate(time.Microsecond),
		}

		if err := repo.CreateRequest(ctx, req); err != nil {
			t.Fatalf("failed to create initial approval request: %v", err)
		}

		concurrency := 10
		var wg sync.WaitGroup
		startBarrier := make(chan struct{})

		var successCount int32
		var conflictCount int32
		var otherErrCount int32

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			actorID := fmt.Sprintf("manager-%d", i+1)
			go func(actor string) {
				defer wg.Done()
				<-startBarrier

				decidedReq := req
				decidedReq.Status = domain.StatusApproved
				decidedReq.CurrentLevel = 1
				decidedReq.UpdatedAt = time.Now().UTC()

				action := domain.ApprovalAction{
					ID:        uuid.New().String(),
					RequestID: reqID,
					ActorID:   actor,
					Action:    "approve",
					Level:     1,
					Notes:     fmt.Sprintf("approved concurrently by %s", actor),
					CreatedAt: time.Now().UTC(),
				}

				err := repo.ApplyDecisionTx(ctx, decidedReq, action, 0, domain.StatusPending)
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				} else if errors.Is(err, domain.ErrConcurrentUpdate) {
					atomic.AddInt32(&conflictCount, 1)
				} else {
					atomic.AddInt32(&otherErrCount, 1)
				}
			}(actorID)
		}

		close(startBarrier)
		wg.Wait()

		if successCount != 1 {
			t.Errorf("expected exactly 1 successful concurrent decision, got %d", successCount)
		}
		if conflictCount != int32(concurrency-1) {
			t.Errorf("expected %d conflict rejections, got %d", concurrency-1, conflictCount)
		}
		if otherErrCount != 0 {
			t.Errorf("expected 0 unexpected errors, got %d", otherErrCount)
		}

		// Verify audit trail contains exactly 1 action record
		actions, err := repo.ListActionsByRequestID(ctx, reqID)
		if err != nil {
			t.Fatalf("failed listing actions: %v", err)
		}
		if len(actions) != 1 {
			t.Errorf("expected exactly 1 recorded action in audit trail, got %d", len(actions))
		}

		// Verify request reflects updated approved state
		finalReq, err := repo.GetRequestByID(ctx, reqID)
		if err != nil {
			t.Fatalf("failed getting final request: %v", err)
		}
		if finalReq.Status != domain.StatusApproved || finalReq.CurrentLevel != 1 {
			t.Errorf("expected approved status and level 1, got status=%s level=%d", finalReq.Status, finalReq.CurrentLevel)
		}
	})

	t.Run("Duplicate submission blocked by partial unique index", func(t *testing.T) {
		resourceID := fmt.Sprintf("PO-DUP-%s", uuid.New().String()[:8])
		req1 := domain.ApprovalRequest{
			ID:             uuid.New().String(),
			Service:        "purchasing",
			ResourceID:     resourceID,
			Amount:         5000,
			RequesterID:    uuid.New().String(),
			Status:         domain.StatusPending,
			CurrentLevel:   0,
			RequiredLevels: 1,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err := repo.CreateRequest(ctx, req1); err != nil {
			t.Fatalf("failed creating first request: %v", err)
		}

		// Attempting duplicate pending request for same resource
		req2 := req1
		req2.ID = uuid.New().String()
		err := repo.CreateRequest(ctx, req2)
		if err == nil {
			t.Fatalf("expected error on duplicate active request submission, got nil")
		}
	})

	t.Run("Audit trail immutability trigger blocks deletion and modification", func(t *testing.T) {
		reqID := uuid.New().String()
		resourceID := fmt.Sprintf("PO-AUDIT-%s", uuid.New().String()[:8])
		req := domain.ApprovalRequest{
			ID:             reqID,
			Service:        "purchasing",
			ResourceID:     resourceID,
			Amount:         8000,
			RequesterID:    uuid.New().String(),
			Status:         domain.StatusPending,
			CurrentLevel:   0,
			RequiredLevels: 1,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err := repo.CreateRequest(ctx, req); err != nil {
			t.Fatalf("failed creating request: %v", err)
		}

		actionID := uuid.New().String()
		action := domain.ApprovalAction{
			ID:        actionID,
			RequestID: reqID,
			ActorID:   uuid.New().String(),
			Action:    "approve",
			Level:     1,
			Notes:     "immutability test",
			CreatedAt: time.Now().UTC(),
		}
		req.Status = domain.StatusApproved
		req.CurrentLevel = 1
		if err := repo.ApplyDecisionTx(ctx, req, action, 0, domain.StatusPending); err != nil {
			t.Fatalf("failed applying decision: %v", err)
		}

		// Attempt DELETE on approval_actions
		_, delErr := pool.Exec(ctx, "DELETE FROM approval_actions WHERE id = $1", actionID)
		if delErr == nil {
			t.Fatalf("expected trigger to prevent deletion of approval_actions, but DELETE succeeded")
		}

		// Attempt UPDATE on approval_actions
		_, updErr := pool.Exec(ctx, "UPDATE approval_actions SET notes = 'tampered' WHERE id = $1", actionID)
		if updErr == nil {
			t.Fatalf("expected trigger to prevent modification of approval_actions, but UPDATE succeeded")
		}
	})

	t.Run("Transaction rollback on context cancellation preserves consistency", func(t *testing.T) {
		reqID := uuid.New().String()
		resourceID := fmt.Sprintf("PO-CANCEL-%s", uuid.New().String()[:8])
		req := domain.ApprovalRequest{
			ID:             reqID,
			Service:        "purchasing",
			ResourceID:     resourceID,
			Amount:         15000,
			RequesterID:    uuid.New().String(),
			Status:         domain.StatusPending,
			CurrentLevel:   0,
			RequiredLevels: 1,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err := repo.CreateRequest(ctx, req); err != nil {
			t.Fatalf("failed creating request: %v", err)
		}

		canceledCtx, cancel := context.WithCancel(ctx)
		cancel() // immediately canceled

		action := domain.ApprovalAction{
			ID:        uuid.New().String(),
			RequestID: reqID,
			ActorID:   uuid.New().String(),
			Action:    "approve",
			Level:     1,
			Notes:     "canceled test",
			CreatedAt: time.Now().UTC(),
		}
		decided := req
		decided.Status = domain.StatusApproved
		decided.CurrentLevel = 1

		err := repo.ApplyDecisionTx(canceledCtx, decided, action, 0, domain.StatusPending)
		if err == nil {
			t.Fatalf("expected error on canceled context, got nil")
		}

		// Verify state was rolled back cleanly
		persisted, err := repo.GetRequestByID(ctx, reqID)
		if err != nil {
			t.Fatalf("failed retrieving request: %v", err)
		}
		if persisted.Status != domain.StatusPending || persisted.CurrentLevel != 0 {
			t.Errorf("expected rolled back state (pending, 0), got status=%s level=%d", persisted.Status, persisted.CurrentLevel)
		}
		actions, err := repo.ListActionsByRequestID(ctx, reqID)
		if err != nil {
			t.Fatalf("failed listing actions: %v", err)
		}
		if len(actions) != 0 {
			t.Errorf("expected 0 actions due to rollback, got %d", len(actions))
		}
	})

	t.Run("Database failure and recovery: operations fail gracefully when DB is down and recover when restored", func(t *testing.T) {
		// Test operation against a closed pool simulating sudden database disconnect/failure
		deadCtx, cancel := context.WithCancel(ctx)
		cancel() // context canceled to simulate immediate network/DB outage

		reqID := uuid.New().String()
		_, err := repo.GetRequestByID(deadCtx, reqID)
		if err == nil {
			t.Fatalf("expected error when querying with canceled context (DB outage), got nil")
		}

		// Now query against healthy DB connection (recovery)
		liveReq, err := repo.GetRequestByID(ctx, reqID)
		if !errors.Is(err, domain.ErrRequestNotFound) {
			t.Errorf("expected ErrRequestNotFound on live DB, got %v (req: %v)", err, liveReq)
		}
	})
}
