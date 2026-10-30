package api

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
)

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
