package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ReadinessChecker defines the contract for checking underlying subsystem health.
// Clean Architecture: defined where consumed (here), implemented later by infrastructure.
type ReadinessChecker interface {
	Check(ctx context.Context) error
}

// HealthHandler serves liveness and readiness probes.
type HealthHandler struct {
	checker ReadinessChecker
}

// NewHealthHandler constructs a HealthHandler with an optional readiness checker.
func NewHealthHandler(checker ReadinessChecker) *HealthHandler {
	return &HealthHandler{checker: checker}
}

// Liveness handles /healthz. Returns 200 OK if the HTTP server is running.
func (h *HealthHandler) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Readiness handles /readyz. Checks if downstream dependencies (DB) are ready.
func (h *HealthHandler) Readiness(c *gin.Context) {
	if h.checker != nil {
		if err := h.checker.Check(c.Request.Context()); err != nil {
			Error(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Subsystem readiness check failed", nil)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
