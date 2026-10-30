package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
)

func TestCanApprove(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	past := now.Add(-1 * time.Hour)

	t.Run("valid approval", func(t *testing.T) {
		req := domain.ApprovalRequest{
			RequesterID: "user_a",
			Status:      domain.StatusPending,
			ExpiresAt:   &future,
		}

		err := req.CanApprove("user_b", false)
		if err != nil {
			t.Fatalf("expected valid approval, got: %v", err)
		}
	})

	t.Run("self approval forbidden", func(t *testing.T) {
		req := domain.ApprovalRequest{
			RequesterID: "user_a",
			Status:      domain.StatusPending,
			ExpiresAt:   &future,
		}

		err := req.CanApprove("user_a", false)
		if !errors.Is(err, domain.ErrSelfApprovalNotAllowed) {
			t.Errorf("expected ErrSelfApprovalNotAllowed, got: %v", err)
		}
	})

	t.Run("self approval allowed when policy permits", func(t *testing.T) {
		req := domain.ApprovalRequest{
			RequesterID: "user_a",
			Status:      domain.StatusPending,
			ExpiresAt:   &future,
		}

		err := req.CanApprove("user_a", true)
		if err != nil {
			t.Errorf("expected nil error when allowSelfApproval is true, got: %v", err)
		}
	})

	t.Run("already decided request returns ErrRequestAlreadyDecided", func(t *testing.T) {
		req := domain.ApprovalRequest{
			RequesterID: "user_a",
			Status:      domain.StatusApproved,
			ExpiresAt:   &future,
		}

		err := req.CanApprove("user_b", false)
		if !errors.Is(err, domain.ErrRequestAlreadyDecided) {
			t.Errorf("expected ErrRequestAlreadyDecided, got: %v", err)
		}
	})

	t.Run("expired request returns ErrRequestExpired", func(t *testing.T) {
		req := domain.ApprovalRequest{
			RequesterID: "user_a",
			Status:      domain.StatusPending,
			ExpiresAt:   &past,
		}

		err := req.CanApprove("user_b", false)
		if !errors.Is(err, domain.ErrRequestExpired) {
			t.Errorf("expected ErrRequestExpired, got: %v", err)
		}
	})
}
