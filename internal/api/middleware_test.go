package api_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/group-project-bridgeon/manager-service/internal/api"
	"github.com/group-project-bridgeon/manager-service/internal/auth"
	"github.com/group-project-bridgeon/manager-service/internal/logger"
)

func generateTestRSAKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key pair: %v", err)
	}
	return priv, &priv.PublicKey
}

func createTestTokenWithTimes(t *testing.T, priv *rsa.PrivateKey, userID uuid.UUID, permissions []string, issuedAt, expiresAt time.Time) string {
	t.Helper()
	ver := 1
	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "erp-auth",
			Audience:  jwt.ClaimStrings{"erp-api"},
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		UserID:       userID.String(),
		Email:        "user@example.com",
		TokenVersion: &ver,
		Permissions:  permissions,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenStr
}

func createTestToken(t *testing.T, priv *rsa.PrivateKey, userID uuid.UUID, permissions []string, ttl time.Duration) string {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	return createTestTokenWithTimes(t, priv, userID, permissions, now, now.Add(ttl))
}

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

func TestAuthenticateMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	priv, pub := generateTestRSAKeyPair(t)
	verifier := auth.NewVerifier(pub, "erp-auth", "erp-api")

	userID := uuid.New()
	now := time.Now().Truncate(time.Second)
	validToken := createTestToken(t, priv, userID, []string{"manager.approvals:read"}, 10*time.Minute)
	expiredToken := createTestTokenWithTimes(t, priv, userID, []string{"manager.approvals:read"}, now.Add(-20*time.Minute), now.Add(-5*time.Minute))

	otherPriv, _ := generateTestRSAKeyPair(t)
	wrongKeyToken := createTestToken(t, otherPriv, userID, []string{"manager.approvals:read"}, 10*time.Minute)

	setupRouter := func() *gin.Engine {
		r := gin.New()
		r.Use(api.RequestID())
		r.Use(api.Authenticate(verifier))
		r.GET("/protected", func(c *gin.Context) {
			p := api.MustGetPrincipal(c)
			api.JSON(c, http.StatusOK, gin.H{"user_id": p.UserID.String()})
		})
		return r
	}

	r := setupRouter()

	t.Run("missing authorization header returns 401 with WWW-Authenticate", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		if w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("expected WWW-Authenticate header 'Bearer', got %q", w.Header().Get("WWW-Authenticate"))
		}

		var resp api.ErrorResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}
		if resp.Error.Code != "UNAUTHORIZED" {
			t.Errorf("expected code UNAUTHORIZED, got %q", resp.Error.Code)
		}
	})

	t.Run("malformed header format returns 401 TOKEN_INVALID", func(t *testing.T) {
		cases := []string{
			"Basic dXNlcjpwYXNz",
			"Bearer",
			"Bearer ",
			"tokenwithoutscheme",
		}
		for _, authHeader := range cases {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", authHeader)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("header %q: expected 401, got %d", authHeader, w.Code)
			}
			var resp api.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.Error.Code != "TOKEN_INVALID" {
				t.Errorf("header %q: expected code TOKEN_INVALID, got %q", authHeader, resp.Error.Code)
			}
		}
	})

	t.Run("expired token returns 401 TOKEN_EXPIRED with WWW-Authenticate", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		if w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("expected WWW-Authenticate header 'Bearer', got %q", w.Header().Get("WWW-Authenticate"))
		}

		var resp api.ErrorResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}
		if resp.Error.Code != "TOKEN_EXPIRED" {
			t.Errorf("expected code TOKEN_EXPIRED, got %q", resp.Error.Code)
		}
	})

	t.Run("invalid token signature returns 401 TOKEN_INVALID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+wrongKeyToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		var resp api.ErrorResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}
		if resp.Error.Code != "TOKEN_INVALID" {
			t.Errorf("expected code TOKEN_INVALID, got %q", resp.Error.Code)
		}
	})

	t.Run("valid token with lowercase bearer prefix succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "bearer "+validToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("valid token with uppercase BEARER prefix succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "BEARER "+validToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestRequirePermissionMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	priv, pub := generateTestRSAKeyPair(t)
	verifier := auth.NewVerifier(pub, "erp-auth", "erp-api")

	var logBuf bytes.Buffer
	customLogger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	slog.SetDefault(customLogger)

	userID := uuid.New()
	tokenWithApprove := createTestToken(t, priv, userID, []string{"manager.approvals:approve"}, 10*time.Minute)
	tokenWithRead := createTestToken(t, priv, userID, []string{"manager.approvals:read"}, 10*time.Minute)

	r := gin.New()
	r.Use(api.RequestID())
	v1 := r.Group("/api/v1")
	v1.Use(api.Authenticate(verifier))
	{
		v1.POST("/approve", api.RequirePermission("manager.approvals:approve"), func(c *gin.Context) {
			api.JSON(c, http.StatusOK, "approved")
		})
	}

	t.Run("missing required permission returns 403 FORBIDDEN and logs warning without token", func(t *testing.T) {
		logBuf.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/approve", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenWithRead))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}

		var resp api.ErrorResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse error response: %v", err)
		}
		if resp.Error.Code != "FORBIDDEN" {
			t.Errorf("expected error code FORBIDDEN, got %q", resp.Error.Code)
		}

		// Verify logger captured warning with user_id and required permission, but never the raw token
		logOutput := logBuf.String()
		if !bytes.Contains([]byte(logOutput), []byte("permission denied")) {
			t.Errorf("expected 'permission denied' in log, got: %s", logOutput)
		}
		if !bytes.Contains([]byte(logOutput), []byte(userID.String())) {
			t.Errorf("expected user_id in log, got: %s", logOutput)
		}
		if !bytes.Contains([]byte(logOutput), []byte("manager.approvals:approve")) {
			t.Errorf("expected required permission in log, got: %s", logOutput)
		}
		if bytes.Contains([]byte(logOutput), []byte(tokenWithRead)) {
			t.Errorf("CRITICAL: raw token was found in log output!")
		}
	})

	t.Run("exact matching permission succeeds with 200 OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approve", nil)
		req.Header.Set("Authorization", "Bearer "+tokenWithApprove)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("calling RequirePermission without Authenticate returns 401 UNAUTHORIZED", func(t *testing.T) {
		unprotectedRouter := gin.New()
		unprotectedRouter.Use(api.RequirePermission("manager.approvals:read"))
		unprotectedRouter.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		unprotectedRouter.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}
