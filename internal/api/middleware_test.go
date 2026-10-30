package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/group-project-bridgeon/manager-service/internal/api"
	"github.com/group-project-bridgeon/manager-service/internal/logger"
)

func TestRequestIDMiddleware(t *testing.T) {
	r := gin.New()
	r.Use(api.RequestID())
	r.GET("/test", func(c *gin.Context) {
		reqID, _ := c.Get(api.HeaderRequestID)
		c.String(http.StatusOK, reqID.(string))
	})

	// Case 1: Header generated automatically
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	respHeader := w.Header().Get(api.HeaderRequestID)
	if respHeader == "" {
		t.Fatalf("expected X-Request-ID header to be set in response")
	}
	if w.Body.String() != respHeader {
		t.Errorf("expected body to match header %s, got %s", respHeader, w.Body.String())
	}

	// Case 2: Header passed from client is preserved
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set(api.HeaderRequestID, "custom-id-999")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Header().Get(api.HeaderRequestID) != "custom-id-999" {
		t.Errorf("expected custom-id-999, got %s", w2.Header().Get(api.HeaderRequestID))
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New("development", "error", &buf)

	r := gin.New()
	r.Use(api.RequestID(), api.Recovery(log))
	r.GET("/panic", func(c *gin.Context) {
		panic("database connection suddenly severed")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}

	if !bytes.Contains(buf.Bytes(), []byte("panic recovered")) {
		t.Errorf("expected panic log message, got: %s", buf.String())
	}
}
