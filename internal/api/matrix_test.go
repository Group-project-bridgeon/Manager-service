package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/group-project-bridgeon/manager-service/internal/api"
	"github.com/group-project-bridgeon/manager-service/internal/auth"
	"github.com/group-project-bridgeon/manager-service/internal/logger"
	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
	workflowService "github.com/group-project-bridgeon/manager-service/internal/workflow/service"
)

type toggleReadinessChecker struct {
	err error
}

func (m *toggleReadinessChecker) Check(ctx context.Context) error {
	return m.err
}

func TestAPIFailureAndConcurrencyMatrix(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating test rsa key: %v", err)
	}
	verifier := auth.NewVerifier(&priv.PublicKey, "erp-auth", "erp-api")

	mintToken := func(userID uuid.UUID, permissions []string, ttl time.Duration) string {
		now := time.Now().Truncate(time.Second)
		ver := 1
		claims := auth.CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "erp-auth",
				Audience:  jwt.ClaimStrings{"erp-api"},
				Subject:   userID.String(),
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			},
			UserID:       userID.String(),
			Email:        "user@example.com",
			TokenVersion: &ver,
			Permissions:  permissions,
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		str, _ := tok.SignedString(priv)
		return str
	}

	repo := newMockWfRepo()
	wfSvc := workflowService.New(repo)
	checker := &toggleReadinessChecker{err: nil}

	var buf bytes.Buffer
	log := logger.New("development", "warn", &buf)

	router := api.NewRouter(api.RouterConfig{
		AppEnv:          "development",
		Logger:          log,
		Checker:         checker,
		AuthVerifier:    verifier,
		WorkflowService: wfSvc,
	})

	purchaserID := uuid.New()
	managerID := uuid.New()
	manager2ID := uuid.New()

	purchaserToken := mintToken(purchaserID, []string{api.PermApprovalsSubmit, api.PermApprovalsRead}, 10*time.Minute)
	managerToken := mintToken(managerID, []string{api.PermApprovalsApprove, api.PermApprovalsReject, api.PermApprovalsRead}, 10*time.Minute)
	manager2Token := mintToken(manager2ID, []string{api.PermApprovalsApprove, api.PermApprovalsReject, api.PermApprovalsRead}, 10*time.Minute)
	readOnlyToken := mintToken(managerID, []string{api.PermApprovalsRead}, 10*time.Minute)

	// -------------------------------------------------------------------------
	// 1. Invalid / Expired JWT
	// -------------------------------------------------------------------------
	t.Run("Matrix #1: Expired and invalid tokens rejected with 401", func(t *testing.T) {
		// Expired token
		now := time.Now().Truncate(time.Second)
		expiredToken := createTestTokenWithTimes(t, priv, purchaserID, []string{api.PermApprovalsSubmit}, now.Add(-20*time.Minute), now.Add(-5*time.Minute))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals/status?service=purchasing&resource_id=x", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for expired token, got %d", w.Code)
		}
		var resp api.ErrorResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Error.Code != "TOKEN_EXPIRED" {
			t.Errorf("expected code TOKEN_EXPIRED, got %q", resp.Error.Code)
		}
	})

	// -------------------------------------------------------------------------
	// 2. Permission Denial
	// -------------------------------------------------------------------------
	t.Run("Matrix #2: Caller lacking required permission receives 403 FORBIDDEN", func(t *testing.T) {
		body := []byte(`{"service":"purchasing","resource_id":"b_1","amount":5000}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+readOnlyToken) // has read only, not submit
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
		var resp api.ErrorResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Error.Code != "FORBIDDEN" {
			t.Errorf("expected code FORBIDDEN, got %q", resp.Error.Code)
		}
	})

	// -------------------------------------------------------------------------
	// 3 & 4. Invalid Transitions and Duplicate Approval
	// -------------------------------------------------------------------------
	t.Run("Matrix #3 & #4: Duplicate approval on decided bill returns 409 Conflict", func(t *testing.T) {
		// Submit bill
		submitBody := []byte(`{"service":"purchasing","resource_id":"bill_dup_api","amount":10000}`)
		sReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(submitBody))
		sReq.Header.Set("Content-Type", "application/json")
		sReq.Header.Set("Authorization", "Bearer "+purchaserToken)
		sW := httptest.NewRecorder()
		router.ServeHTTP(sW, sReq)

		var sResp api.Response
		_ = json.Unmarshal(sW.Body.Bytes(), &sResp)
		reqID := sResp.Data.(map[string]any)["id"].(string)

		// First approval succeeds
		aReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqID+"/approve", bytes.NewBufferString(`{"notes":"ok"}`))
		aReq.Header.Set("Content-Type", "application/json")
		aReq.Header.Set("Authorization", "Bearer "+managerToken)
		aW := httptest.NewRecorder()
		router.ServeHTTP(aW, aReq)

		if aW.Code != http.StatusOK {
			t.Fatalf("first approval failed: %d", aW.Code)
		}

		// Second duplicate approval fails with 409
		dupReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqID+"/approve", bytes.NewBufferString(`{"notes":"duplicate"}`))
		dupReq.Header.Set("Content-Type", "application/json")
		dupReq.Header.Set("Authorization", "Bearer "+manager2Token)
		dupW := httptest.NewRecorder()
		router.ServeHTTP(dupW, dupReq)

		if dupW.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict on duplicate approval, got %d", dupW.Code)
		}
		var errResp api.ErrorResponse
		_ = json.Unmarshal(dupW.Body.Bytes(), &errResp)
		if errResp.Error.Code != "REQUEST_ALREADY_DECIDED" {
			t.Errorf("expected code REQUEST_ALREADY_DECIDED, got %q", errResp.Error.Code)
		}
	})

	// -------------------------------------------------------------------------
	// 6. DB Outage / Readiness Probe Failure & Recovery
	// -------------------------------------------------------------------------
	t.Run("Matrix #6: Readiness probe flips 503 during DB outage and 200 upon recovery", func(t *testing.T) {
		// Normal state
		checker.err = nil
		w1 := httptest.NewRecorder()
		router.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if w1.Code != http.StatusOK {
			t.Errorf("expected readyz 200, got %d", w1.Code)
		}

		// Outage state
		checker.err = errors.New("db connection severed")
		w2 := httptest.NewRecorder()
		router.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if w2.Code != http.StatusServiceUnavailable {
			t.Errorf("expected readyz 503 during outage, got %d", w2.Code)
		}

		// Liveness stays 200 during DB outage
		wLive := httptest.NewRecorder()
		router.ServeHTTP(wLive, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if wLive.Code != http.StatusOK {
			t.Errorf("expected healthz 200 during outage, got %d", wLive.Code)
		}

		// Recovery state
		checker.err = nil
		w3 := httptest.NewRecorder()
		router.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if w3.Code != http.StatusOK {
			t.Errorf("expected readyz 200 after recovery, got %d", w3.Code)
		}
	})

	// -------------------------------------------------------------------------
	// 8. Multi-Level Approval API Flow
	// -------------------------------------------------------------------------
	t.Run("Matrix #8: Multi-level approval progresses levels and reflects in status and history", func(t *testing.T) {
		// Submit 80k bill (2 levels required)
		sBody := []byte(`{"service":"purchasing","resource_id":"bill_multi_api","amount":80000}`)
		sReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(sBody))
		sReq.Header.Set("Content-Type", "application/json")
		sReq.Header.Set("Authorization", "Bearer "+purchaserToken)
		sW := httptest.NewRecorder()
		router.ServeHTTP(sW, sReq)

		var sResp api.Response
		_ = json.Unmarshal(sW.Body.Bytes(), &sResp)
		reqID := sResp.Data.(map[string]any)["id"].(string)

		// Level 1 Approval by Manager 1
		l1Req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqID+"/approve", bytes.NewBufferString(`{"notes":"L1 ok"}`))
		l1Req.Header.Set("Content-Type", "application/json")
		l1Req.Header.Set("Authorization", "Bearer "+managerToken)
		l1W := httptest.NewRecorder()
		router.ServeHTTP(l1W, l1Req)

		var l1Resp api.Response
		_ = json.Unmarshal(l1W.Body.Bytes(), &l1Resp)
		if l1Resp.Data.(map[string]any)["status"] != "pending" || l1Resp.Data.(map[string]any)["current_level"].(float64) != 1 {
			t.Fatalf("expected pending status with level 1, got %v", l1Resp.Data)
		}

		// Level 2 Approval by Manager 2
		l2Req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqID+"/approve", bytes.NewBufferString(`{"notes":"L2 ok"}`))
		l2Req.Header.Set("Content-Type", "application/json")
		l2Req.Header.Set("Authorization", "Bearer "+manager2Token)
		l2W := httptest.NewRecorder()
		router.ServeHTTP(l2W, l2Req)

		var l2Resp api.Response
		_ = json.Unmarshal(l2W.Body.Bytes(), &l2Resp)
		if l2Resp.Data.(map[string]any)["status"] != "approved" || l2Resp.Data.(map[string]any)["current_level"].(float64) != 2 {
			t.Fatalf("expected approved status with level 2, got %v", l2Resp.Data)
		}

		// Check history contains both actions
		hReq := httptest.NewRequest(http.MethodGet, "/api/v1/approvals/"+reqID, nil)
		hReq.Header.Set("Authorization", "Bearer "+managerToken)
		hW := httptest.NewRecorder()
		router.ServeHTTP(hW, hReq)

		var hResp api.Response
		_ = json.Unmarshal(hW.Body.Bytes(), &hResp)
		actions := hResp.Data.(map[string]any)["actions"].([]any)
		if len(actions) != 2 {
			t.Errorf("expected 2 audit actions, got %d", len(actions))
		}
	})

	// -------------------------------------------------------------------------
	// 9. Expiration API Handling
	// -------------------------------------------------------------------------
	t.Run("Matrix #9: Expired request returns 410 REQUEST_EXPIRED", func(t *testing.T) {
		past := time.Now().UTC().Add(-10 * time.Hour)
		expiredReq := domain.ApprovalRequest{
			ID:             uuid.New().String(),
			Service:        "purchasing",
			ResourceID:     "bill_expired_api",
			Amount:         10000,
			RequesterID:    purchaserID.String(),
			Status:         domain.StatusPending,
			CurrentLevel:   0,
			RequiredLevels: 1,
			ExpiresAt:      &past,
			CreatedAt:      past.Add(-72 * time.Hour),
			UpdatedAt:      past.Add(-72 * time.Hour),
		}
		_ = repo.CreateRequest(context.Background(), expiredReq)

		aReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+expiredReq.ID+"/approve", bytes.NewBufferString(`{"notes":"too late"}`))
		aReq.Header.Set("Content-Type", "application/json")
		aReq.Header.Set("Authorization", "Bearer "+managerToken)
		aW := httptest.NewRecorder()
		router.ServeHTTP(aW, aReq)

		if aW.Code != http.StatusGone {
			t.Fatalf("expected 410 Gone for expired request, got %d", aW.Code)
		}
		var errResp api.ErrorResponse
		_ = json.Unmarshal(aW.Body.Bytes(), &errResp)
		if errResp.Error.Code != "REQUEST_EXPIRED" {
			t.Errorf("expected error code REQUEST_EXPIRED, got %q", errResp.Error.Code)
		}
	})
}
