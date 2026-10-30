package api

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	rbacService "github.com/group-project-bridgeon/manager-service/internal/rbac/service"
	workflowService "github.com/group-project-bridgeon/manager-service/internal/workflow/service"
)

// RouterConfig contains dependencies required to construct the HTTP router.
type RouterConfig struct {
	AppEnv          string
	Logger          *slog.Logger
	Checker         ReadinessChecker
	RoleService     *rbacService.Service
	WorkflowService *workflowService.Service
}

// NewRouter configures and returns the Gin engine with all routes and middlewares mounted.
func NewRouter(cfg RouterConfig) *gin.Engine {
	if cfg.AppEnv == "production" || cfg.AppEnv == "staging" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

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
		// RBAC & Authorization routes
		if cfg.RoleService != nil {
			roleHandler := NewRoleHandler(cfg.RoleService)
			userRoleHandler := NewUserRoleHandler(cfg.RoleService)

			roles := v1.Group("/roles")
			{
				roles.GET("", roleHandler.List)
				roles.GET("/:id", roleHandler.GetByID)
				roles.POST("", roleHandler.Create)
			}

			users := v1.Group("/users")
			{
				users.POST("/:id/roles", userRoleHandler.Assign)
				users.GET("/:id/roles", userRoleHandler.ListUserRoles)
				users.DELETE("/:id/roles/:role_id", userRoleHandler.Revoke)
			}

			authz := v1.Group("/authz")
			{
				authz.POST("/check", userRoleHandler.CheckAuthz)
			}
		}

		// Approval Workflow Engine routes
		if cfg.WorkflowService != nil {
			workflowHandler := NewWorkflowHandler(cfg.WorkflowService)
			approvals := v1.Group("/approvals")
			{
				approvals.POST("/submit", workflowHandler.Submit)
				approvals.GET("/status", workflowHandler.GetStatus)
				approvals.GET("/:id", workflowHandler.GetHistory)
				approvals.POST("/:id/approve", workflowHandler.Approve)
				approvals.POST("/:id/reject", workflowHandler.Reject)
			}
		}
	}

	return r
}
