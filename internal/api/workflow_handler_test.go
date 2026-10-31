package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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

type mockWfRepo struct {
	requests map[string]domain.ApprovalRequest
	actions  map[string][]domain.ApprovalAction
}

func newMockWfRepo() *mockWfRepo {
	return &mockWfRepo{
		requests: make(map[string]domain.ApprovalRequest),
		actions:  make(map[string][]domain.ApprovalAction),
	}
}

func (m *mockWfRepo) CreateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	m.requests[req.ID] = req
	return nil
}

func (m *mockWfRepo) GetRequestByID(ctx context.Context, id string) (*domain.ApprovalRequest, error) {
	req, ok := m.requests[id]
	if !ok {
		return nil, domain.ErrRequestNotFound
	}
	return &req, nil
}

func (m *mockWfRepo) GetRequestByResource(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error) {
	for _, req := range m.requests {
		if req.Service == serviceName && req.ResourceID == resourceID {
			return &req, nil
		}
	}
	return nil, domain.ErrRequestNotFound
}

func (m *mockWfRepo) GetActiveRequestByResource(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error) {
	for _, req := range m.requests {
		if req.Service == serviceName && req.ResourceID == resourceID && (req.Status == domain.StatusPending || req.Status == domain.StatusApproved) {
			return &req, nil
		}
	}
	return nil, nil
}

func (m *mockWfRepo) UpdateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	m.requests[req.ID] = req
	return nil
}

func (m *mockWfRepo) RecordAction(ctx context.Context, action domain.ApprovalAction) error {
	m.actions[action.RequestID] = append(m.actions[action.RequestID], action)
	return nil
}

func (m *mockWfRepo) ApplyDecisionTx(ctx context.Context, req domain.ApprovalRequest, action domain.ApprovalAction, expectedLevel int, expectedStatus domain.Status) error {
	existing, ok := m.requests[req.ID]
	if !ok {
		return domain.ErrRequestNotFound
	}
	if existing.CurrentLevel != expectedLevel || existing.Status != expectedStatus {
		return domain.ErrConcurrentUpdate
	}
	m.requests[req.ID] = req
	m.actions[req.ID] = append(m.actions[req.ID], action)
	return nil
}

func (m *mockWfRepo) GetMatchingPolicy(ctx context.Context, serviceName, resourceType string, amount float64) (*domain.ApprovalPolicy, error) {
	return nil, nil
}

func (m *mockWfRepo) ListActionsByRequestID(ctx context.Context, requestID string) ([]domain.ApprovalAction, error) {
	return m.actions[requestID], nil
}

type wfTokenIssuer struct {
	priv *rsa.PrivateKey
}

func (ti *wfTokenIssuer) issueToken(userID uuid.UUID, permissions []string) string {
	ver := 1
	now := time.Now().Truncate(time.Second)
	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "erp-auth",
			Audience:  jwt.ClaimStrings{"erp-api"},
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		UserID:       userID.String(),
		Email:        "user@example.com",
		TokenVersion: &ver,
		Permissions:  permissions,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, _ := tok.SignedString(ti.priv)
	return tokenStr
}

func setupWorkflowTestRouter() (*workflowService.Service, http.Handler, *wfTokenIssuer) {
	var buf bytes.Buffer
	log := logger.New("development", "debug", &buf)
	repo := newMockWfRepo()
	wfSvc := workflowService.New(repo)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	verifier := auth.NewVerifier(&priv.PublicKey, "erp-auth", "erp-api")

	r := api.NewRouter(api.RouterConfig{
		AppEnv:          "development",
		Logger:          log,
		AuthVerifier:    verifier,
		WorkflowService: wfSvc,
	})
	return wfSvc, r, &wfTokenIssuer{priv: priv}
}

func TestWorkflowEndpoints(t *testing.T) {
	_, router, issuer := setupWorkflowTestRouter()

	purchaserID := uuid.New()
	managerID := uuid.New()

	purchaserToken := issuer.issueToken(purchaserID, []string{
		api.PermApprovalsSubmit,
		api.PermApprovalsRead,
	})
	managerToken := issuer.issueToken(managerID, []string{
		api.PermApprovalsApprove,
		api.PermApprovalsReject,
		api.PermApprovalsRead,
	})
	// A token having approve permission but belonging to the purchaser (for self-approval tests)
	purchaserWithApproveToken := issuer.issueToken(purchaserID, []string{
		api.PermApprovalsSubmit,
		api.PermApprovalsApprove,
		api.PermApprovalsRead,
	})

	var createdID string

	t.Run("submit without token returns 401 unauthorized", func(t *testing.T) {
		body := []byte(`{"service":"purchasing","resource_id":"bill_101","amount":35000.00}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("submit without submit permission returns 403 forbidden", func(t *testing.T) {
		readOnlyToken := issuer.issueToken(purchaserID, []string{api.PermApprovalsRead})
		body := []byte(`{"service":"purchasing","resource_id":"bill_101","amount":35000.00}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+readOnlyToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("submit bill under 50k takes requester from token and sets 1 required level", func(t *testing.T) {
		body := []byte(`{"service":"purchasing","resource_id":"bill_101","amount":35000.00}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+purchaserToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
		}

		var resp api.Response
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		dataMap := resp.Data.(map[string]any)
		createdID = dataMap["id"].(string)

		// Verify requester_id matches purchaser token identity
		if dataMap["requester_id"] != purchaserID.String() {
			t.Errorf("expected requester_id %q, got %q", purchaserID.String(), dataMap["requester_id"])
		}
		if dataMap["required_levels"].(float64) != 1 {
			t.Errorf("expected 1 required level for 35k, got: %v", dataMap["required_levels"])
		}
	})

	t.Run("client sending requester_id and actor_id in body cannot spoof identity", func(t *testing.T) {
		spoofedID := "spoofed-user-999"
		// Send payload with spoofed requester_id in body
		spoofBody := []byte(`{"service":"purchasing","resource_id":"bill_spoof","requester_id":"` + spoofedID + `","amount":15000.00}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(spoofBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+purchaserToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
		}

		var resp api.Response
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		dataMap := resp.Data.(map[string]any)
		spoofReqID := dataMap["id"].(string)

		// The requester_id MUST be purchaserID, NEVER the spoofedID
		if dataMap["requester_id"] != purchaserID.String() {
			t.Errorf("spoofed requester_id leaked! expected %q, got %q", purchaserID.String(), dataMap["requester_id"])
		}

		// Now attempt to approve with spoofed actor_id in body
		approveSpoofBody := []byte(`{"actor_id":"` + spoofedID + `","notes":"spoofed approver"}`)
		apprReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+spoofReqID+"/approve", bytes.NewBuffer(approveSpoofBody))
		apprReq.Header.Set("Content-Type", "application/json")
		apprReq.Header.Set("Authorization", "Bearer "+managerToken)
		apprW := httptest.NewRecorder()

		router.ServeHTTP(apprW, apprReq)

		if apprW.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", apprW.Code, apprW.Body.String())
		}

		// Check history: actor_id in audit action MUST be managerID, not spoofedID
		histReq := httptest.NewRequest(http.MethodGet, "/api/v1/approvals/"+spoofReqID, nil)
		histReq.Header.Set("Authorization", "Bearer "+managerToken)
		histW := httptest.NewRecorder()
		router.ServeHTTP(histW, histReq)

		var histResp api.Response
		_ = json.Unmarshal(histW.Body.Bytes(), &histResp)
		histMap := histResp.Data.(map[string]any)
		actions := histMap["actions"].([]any)
		firstAction := actions[0].(map[string]any)

		if firstAction["actor_id"] != managerID.String() {
			t.Errorf("spoofed actor_id leaked! expected %q, got %q", managerID.String(), firstAction["actor_id"])
		}
	})

	t.Run("self approval forbidden even if caller has approve permission", func(t *testing.T) {
		body := []byte(`{"notes":"Trying to self approve"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+createdID+"/approve", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		// Using purchaser's token which has approve permission
		req.Header.Set("Authorization", "Bearer "+purchaserWithApproveToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d: %s", w.Code, w.Body.String())
		}

		var errResp api.ErrorResponse
		_ = json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Error.Code != "SELF_APPROVAL_FORBIDDEN" {
			t.Errorf("expected error code SELF_APPROVAL_FORBIDDEN, got %q", errResp.Error.Code)
		}
	})

	t.Run("manager approval succeeds", func(t *testing.T) {
		body := []byte(`{"notes":"Approved bill"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+createdID+"/approve", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+managerToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}

		var resp api.Response
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		dataMap := resp.Data.(map[string]any)
		if dataMap["status"] != "approved" {
			t.Errorf("expected status 'approved', got: %v", dataMap["status"])
		}
	})

	t.Run("status endpoint returns approved status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals/status?service=purchasing&resource_id=bill_101", nil)
		req.Header.Set("Authorization", "Bearer "+purchaserToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp api.Response
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		dataMap := resp.Data.(map[string]any)
		if dataMap["status"] != "approved" {
			t.Errorf("expected status 'approved', got: %v", dataMap["status"])
		}
	})

	t.Run("history endpoint returns audit trail", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals/"+createdID, nil)
		req.Header.Set("Authorization", "Bearer "+managerToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp api.Response
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		dataMap := resp.Data.(map[string]any)
		actions := dataMap["actions"].([]any)
		if len(actions) != 1 {
			t.Errorf("expected 1 audit action, got: %d", len(actions))
		}
	})

	t.Run("reject endpoint terminates request", func(t *testing.T) {
		// Submit another request to reject
		submitBody := []byte(`{"service":"purchasing","resource_id":"bill_rej","amount":10000.00}`)
		sReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(submitBody))
		sReq.Header.Set("Content-Type", "application/json")
		sReq.Header.Set("Authorization", "Bearer "+purchaserToken)
		sW := httptest.NewRecorder()
		router.ServeHTTP(sW, sReq)

		var sResp api.Response
		_ = json.Unmarshal(sW.Body.Bytes(), &sResp)
		rejID := sResp.Data.(map[string]any)["id"].(string)

		// Reject
		rejBody := []byte(`{"notes":"Rejecting invalid budget"}`)
		rReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+rejID+"/reject", bytes.NewBuffer(rejBody))
		rReq.Header.Set("Content-Type", "application/json")
		rReq.Header.Set("Authorization", "Bearer "+managerToken)
		rW := httptest.NewRecorder()
		router.ServeHTTP(rW, rReq)

		if rW.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rW.Code, rW.Body.String())
		}

		var rResp api.Response
		_ = json.Unmarshal(rW.Body.Bytes(), &rResp)
		if rResp.Data.(map[string]any)["status"] != "rejected" {
			t.Errorf("expected status 'rejected', got: %v", rResp.Data.(map[string]any)["status"])
		}
	})
}
