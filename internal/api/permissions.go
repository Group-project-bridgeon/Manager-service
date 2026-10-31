package api

// Standard permission strings required by Manager service API endpoints.
// These represent exact GLOBAL grants issued by the Authentication service.
// Each permission follows the "resource:action" format with exactly one colon.
const (
	// PermApprovalsSubmit allows submitting new approval requests.
	PermApprovalsSubmit = "manager.approvals:submit"

	// PermApprovalsRead allows querying approval statuses and histories.
	PermApprovalsRead = "manager.approvals:read"

	// PermApprovalsApprove allows approving pending approval requests.
	PermApprovalsApprove = "manager.approvals:approve"

	// PermApprovalsReject allows rejecting pending approval requests.
	PermApprovalsReject = "manager.approvals:reject"

	// PermRBACManage allows creating roles, listing roles, assigning roles, and revoking roles.
	PermRBACManage = "manager.rbac:manage"

	// PermAuthzCheck allows checking whether a user has a specific permission.
	PermAuthzCheck = "manager.authz:check"
)
