package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/api"
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

func (m *mockWfRepo) UpdateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	m.requests[req.ID] = req
	return nil
}

func (m *mockWfRepo) RecordAction(ctx context.Context, action domain.ApprovalAction) error {
	m.actions[action.RequestID] = append(m.actions[action.RequestID], action)
	return nil
}

func (m *mockWfRepo) GetMatchingPolicy(ctx context.Context, serviceName, resourceType string, amount float64) (*domain.ApprovalPolicy, error) {
	return nil, nil
}

func (m *mockWfRepo) ListActionsByRequestID(ctx context.Context, requestID string) ([]domain.ApprovalAction, error) {
	return m.actions[requestID], nil
}

type mockWfAuthorizer struct{}

func (m *mockWfAuthorizer) CheckPermission(ctx context.Context, userID, serviceName, resource, action string) (bool, []string, error) {
	if userID == "unauthorized_user" {
		return false, []string{"guest"}, nil
	}
	return true, []string{"manager"}, nil
}

func setupWorkflowTestRouter() (*workflowService.Service, http.Handler) {
	var buf bytes.Buffer
	log := logger.New("development", "debug", &buf)
	repo := newMockWfRepo()
	auth := &mockWfAuthorizer{}
	wfSvc := workflowService.New(repo, auth)

	r := api.NewRouter(api.RouterConfig{
		AppEnv:          "development",
		Logger:          log,
		WorkflowService: wfSvc,
	})
	return wfSvc, r
}

func TestWorkflowEndpoints(t *testing.T) {
	_, router := setupWorkflowTestRouter()

	var createdID string

	t.Run("submit bill under 50k returns 201 with 1 required level", func(t *testing.T) {
		body := []byte(`{"service":"purchasing","resource_id":"bill_101","requester_id":"purchaser_1","amount":35000.00}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/submit", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
		}

		var resp api.Response
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		dataMap := resp.Data.(map[string]any)
		createdID = dataMap["id"].(string)

		if dataMap["required_levels"].(float64) != 1 {
			t.Errorf("expected 1 required level for 35k, got: %v", dataMap["required_levels"])
		}
	})

	t.Run("self approval returns 403 forbidden", func(t *testing.T) {
		body := []byte(`{"actor_id":"purchaser_1","notes":"Trying to self approve"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+createdID+"/approve", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("manager approval succeeds", func(t *testing.T) {
		body := []byte(`{"actor_id":"manager_1","notes":"Approved bill"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+createdID+"/approve", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
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
}
