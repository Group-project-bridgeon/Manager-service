package api

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

// RouterConfig contains dependencies required to construct the HTTP router.
type RouterConfig struct {
	AppEnv  string
	Logger  *slog.Logger
	Checker ReadinessChecker
}

// NewRouter configures and returns the Gin engine with all routes and middlewares mounted.
func NewRouter(cfg RouterConfig) *gin.Engine {
	if cfg.AppEnv == "production" || cfg.AppEnv == "staging" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// gin.New() gives us a blank engine without Gin's default console logger or recovery
	r := gin.New()

	// Attach production middlewares
	r.Use(RequestID())
	r.Use(StructuredLogger(cfg.Logger))
	r.Use(Recovery(cfg.Logger))

	// Health probes
	health := NewHealthHandler(cfg.Checker)
	r.GET("/healthz", health.Liveness)
	r.GET("/readyz", health.Readiness)

	// Business API routes (v1)
	v1 := r.Group("/api/v1")
	{
		// Future business modules will be registered here, e.g.:
		// partyHandler.RegisterRoutes(v1.Group("/parties"))
		// authHandler.RegisterRoutes(v1.Group("/auth"))
		_ = v1
	}

	return r
}
