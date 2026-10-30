package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/group-project-bridgeon/manager-service/internal/api"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	api.JSON(c, http.StatusOK, map[string]string{"foo": "bar"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var res api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	if !res.Success {
		t.Errorf("expected success true, got false")
	}
}

func TestError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(api.HeaderRequestID, "test-request-id-123")

	api.Error(c, http.StatusBadRequest, "INVALID_INPUT", "Bad payload", []api.ErrorDetail{
		{Field: "email", Message: "must be valid"},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var res api.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode error JSON: %v", err)
	}

	if res.Success {
		t.Errorf("expected success false, got true")
	}
	if res.Error.Code != "INVALID_INPUT" {
		t.Errorf("expected code INVALID_INPUT, got %s", res.Error.Code)
	}
	if res.Error.RequestID != "test-request-id-123" {
		t.Errorf("expected request_id 'test-request-id-123', got %s", res.Error.RequestID)
	}
	if len(res.Error.Details) != 1 || res.Error.Details[0].Field != "email" {
		t.Errorf("expected details to contain email field error, got %+v", res.Error.Details)
	}
}

func TestRespondInternalError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	api.RespondInternalError(c)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}

	var res api.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode error JSON: %v", err)
	}

	if res.Error.Code != "INTERNAL_ERROR" {
		t.Errorf("expected INTERNAL_ERROR, got %s", res.Error.Code)
	}
}
