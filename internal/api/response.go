// Package api handles HTTP transport, routing, middlewares, and response formatting.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HeaderRequestID is the standard HTTP header key for request tracing.
const HeaderRequestID = "X-Request-ID"

// Response represents the standard API success envelope.
type Response struct {
	Success bool `json:"success"`
	Data    any  `json:"data,omitempty"`
}

// ErrorDetail represents specific field validation errors.
type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ErrorPayload represents the standard error response body.
type ErrorPayload struct {
	Code      string        `json:"code"`
	Message   string        `json:"message"`
	RequestID string        `json:"request_id,omitempty"`
	Details   []ErrorDetail `json:"details,omitempty"`
}

// ErrorResponse represents the top-level error envelope.
type ErrorResponse struct {
	Success bool         `json:"success"`
	Error   ErrorPayload `json:"error"`
}

// JSON writes a standardized success JSON response.
func JSON(c *gin.Context, statusCode int, data any) {
	c.JSON(statusCode, Response{
		Success: true,
		Data:    data,
	})
}

// Error writes a standardized error JSON response, extracting the request ID from Gin context.
func Error(c *gin.Context, statusCode int, code, message string, details []ErrorDetail) {
	reqID, _ := c.Get(HeaderRequestID)
	reqIDStr, _ := reqID.(string)

	c.JSON(statusCode, ErrorResponse{
		Success: false,
		Error: ErrorPayload{
			Code:      code,
			Message:   message,
			RequestID: reqIDStr,
			Details:   details,
		},
	})
}

// RespondInternalError writes a generic 500 internal server error without leaking sensitive internals.
func RespondInternalError(c *gin.Context) {
	Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred. Please try again later.", nil)
}
