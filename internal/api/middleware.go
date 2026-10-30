package api

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/group-project-bridgeon/manager-service/internal/auth"
)

// PrincipalContextKey is the key under which the authenticated Principal is stored in the Gin context.
const PrincipalContextKey = "auth_principal"

type principalContextKey struct{}

// Authenticate middleware validates the RS256 Bearer JWT in the Authorization header.
// It stores the verified Principal in the request context.
func Authenticate(verifier *auth.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Header("WWW-Authenticate", "Bearer")
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authorization header is required", nil)
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
			c.Header("WWW-Authenticate", "Bearer")
			Error(c, http.StatusUnauthorized, "TOKEN_INVALID", "Invalid authorization header format", nil)
			c.Abort()
			return
		}

		tokenStr := strings.TrimSpace(parts[1])
		principal, err := verifier.Verify(tokenStr)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer")
			if errors.Is(err, auth.ErrExpiredToken) {
				Error(c, http.StatusUnauthorized, "TOKEN_EXPIRED", "Token has expired", nil)
			} else {
				Error(c, http.StatusUnauthorized, "TOKEN_INVALID", "Token is invalid", nil)
			}
			c.Abort()
			return
		}

		c.Set(PrincipalContextKey, principal)
		ctx := context.WithValue(c.Request.Context(), principalContextKey{}, principal)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// RequirePermission middleware enforces that the authenticated caller has the exact permission.
// If missing, it logs user_id and required permission at WARN level and returns 403 Forbidden.
func RequirePermission(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := GetPrincipal(c)
		if !ok || principal == nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required", nil)
			c.Abort()
			return
		}

		if !principal.HasPermission(perm) {
			slog.Warn("permission denied",
				slog.String("user_id", principal.UserID.String()),
				slog.String("required_permission", perm),
			)
			Error(c, http.StatusForbidden, "FORBIDDEN", "Forbidden: insufficient permissions", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetPrincipal extracts the authenticated Principal from the Gin context.
func GetPrincipal(c *gin.Context) (*auth.Principal, bool) {
	val, exists := c.Get(PrincipalContextKey)
	if !exists {
		return nil, false
	}
	p, ok := val.(*auth.Principal)
	return p, ok
}

// MustGetPrincipal extracts the authenticated Principal from Gin context or panics if missing.
func MustGetPrincipal(c *gin.Context) *auth.Principal {
	p, ok := GetPrincipal(c)
	if !ok || p == nil {
		panic("MustGetPrincipal called without authenticated principal in context")
	}
	return p
}

// PrincipalFromContext extracts the authenticated Principal from a standard context.Context.
func PrincipalFromContext(ctx context.Context) (*auth.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(*auth.Principal)
	return p, ok
}

// RequestID middleware ensures every request has a unique trace ID.
// If the incoming request has an X-Request-ID header, it is reused; otherwise a UUID v4 is generated.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := c.GetHeader(HeaderRequestID)
		if reqID == "" {
			reqID = newUUID()
		}

		c.Set(HeaderRequestID, reqID)
		c.Writer.Header().Set(HeaderRequestID, reqID)
		c.Next()
	}
}

// StructuredLogger middleware logs HTTP request details using log/slog.
func StructuredLogger(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		reqID, _ := c.Get(HeaderRequestID)
		reqIDStr, _ := reqID.(string)

		fullPath := path
		if rawQuery != "" {
			fullPath = path + "?" + rawQuery
		}

		attrs := []any{
			slog.String("request_id", reqIDStr),
			slog.String("method", c.Request.Method),
			slog.String("path", fullPath),
			slog.Int("status", status),
			slog.Duration("latency", latency),
			slog.String("client_ip", c.ClientIP()),
			slog.String("user_agent", c.Request.UserAgent()),
		}

		msg := fmt.Sprintf("%s %s %d", c.Request.Method, fullPath, status)

		switch {
		case status >= http.StatusInternalServerError:
			log.Error(msg, attrs...)
		case status >= http.StatusBadRequest:
			log.Warn(msg, attrs...)
		default:
			log.Info(msg, attrs...)
		}
	}
}

// Recovery middleware handles panics cleanly by logging the stack trace and returning our standard 500 JSON.
func Recovery(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				reqID, _ := c.Get(HeaderRequestID)
				reqIDStr, _ := reqID.(string)

				stack := string(debug.Stack())
				log.Error("panic recovered",
					slog.String("request_id", reqIDStr),
					slog.Any("error", r),
					slog.String("stack", stack),
				)

				RespondInternalError(c)
				c.Abort()
			}
		}()
		c.Next()
	}
}

// newUUID generates a RFC 4122 compliant UUID v4 using crypto/rand.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	// Set UUID version to 4
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant to RFC 4122
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
