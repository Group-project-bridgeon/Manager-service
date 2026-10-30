package api

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/service"
)

// RouterConfig contains dependencies required to construct the HTTP router.
type RouterConfig struct {
	AppEnv      string
	Logger      *slog.Logger
	Checker     ReadinessChecker
	RoleService *service.Service
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
		if cfg.RoleService != nil {
			roleHandler := NewRoleHandler(cfg.RoleService)
			roles := v1.Group("/roles")
			{
				roles.GET("", roleHandler.List)
				roles.GET("/:id", roleHandler.GetByID)
				roles.POST("", roleHandler.Create)
			}
		}
	}

	return r
}
