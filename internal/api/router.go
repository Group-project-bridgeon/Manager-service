package api

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	"github.com/group-project-bridgeon/manager-service/internal/auth"
	rbacService "github.com/group-project-bridgeon/manager-service/internal/rbac/service"
	workflowService "github.com/group-project-bridgeon/manager-service/internal/workflow/service"
)

// RouterConfig contains dependencies required to construct the HTTP router.
type RouterConfig struct {
	AppEnv          string
	Logger          *slog.Logger
	Checker         ReadinessChecker
	AuthVerifier    *auth.Verifier
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

	// Health probes (Public endpoints)
	health := NewHealthHandler(cfg.Checker)
	r.GET("/healthz", health.Liveness)
	r.GET("/health", health.Liveness)
	r.GET("/readyz", health.Readiness)
	r.GET("/ready", health.Readiness)

	// Business API routes (v1) - Protected by JWT Authentication
	v1 := r.Group("/api/v1")
	if cfg.AuthVerifier != nil {
		v1.Use(Authenticate(cfg.AuthVerifier))
	}
	{
		// RBAC & Authorization routes
		if cfg.RoleService != nil {
			roleHandler := NewRoleHandler(cfg.RoleService)
			userRoleHandler := NewUserRoleHandler(cfg.RoleService)

			roles := v1.Group("/roles")
			{
				roles.GET("", RequirePermission(PermRBACManage), roleHandler.List)
				roles.GET("/:id", RequirePermission(PermRBACManage), roleHandler.GetByID)
				roles.POST("", RequirePermission(PermRBACManage), roleHandler.Create)
			}

			users := v1.Group("/users")
			{
				users.POST("/:id/roles", RequirePermission(PermRBACManage), userRoleHandler.Assign)
				users.GET("/:id/roles", RequirePermission(PermRBACManage), userRoleHandler.ListUserRoles)
				users.DELETE("/:id/roles/:role_id", RequirePermission(PermRBACManage), userRoleHandler.Revoke)
			}

			authz := v1.Group("/authz")
			{
				authz.POST("/check", RequirePermission(PermAuthzCheck), userRoleHandler.CheckAuthz)
			}
		}

		// Approval Workflow Engine routes
		if cfg.WorkflowService != nil {
			workflowHandler := NewWorkflowHandler(cfg.WorkflowService)
			approvals := v1.Group("/approvals")
			{
				approvals.POST("/submit", RequirePermission(PermApprovalsSubmit), workflowHandler.Submit)
				approvals.GET("/status", RequirePermission(PermApprovalsRead), workflowHandler.GetStatus)
				approvals.GET("/:id", RequirePermission(PermApprovalsRead), workflowHandler.GetHistory)
				approvals.POST("/:id/approve", RequirePermission(PermApprovalsApprove), workflowHandler.Approve)
				approvals.POST("/:id/reject", RequirePermission(PermApprovalsReject), workflowHandler.Reject)
			}
		}
	}

	return r
}
