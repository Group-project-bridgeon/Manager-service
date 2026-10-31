DROP TRIGGER IF EXISTS trg_prevent_approval_actions_mutation ON approval_actions;
DROP FUNCTION IF EXISTS prevent_audit_log_mutation();

DROP INDEX IF EXISTS idx_unique_active_approval_per_resource;

ALTER TABLE approval_policies
    DROP CONSTRAINT IF EXISTS chk_approval_policies_amounts,
    DROP CONSTRAINT IF EXISTS chk_approval_policies_required_levels;

ALTER TABLE approval_actions
    DROP CONSTRAINT IF EXISTS chk_approval_actions_action,
    DROP CONSTRAINT IF EXISTS chk_approval_actions_level;

ALTER TABLE approval_requests
    DROP CONSTRAINT IF EXISTS chk_approval_requests_status,
    DROP CONSTRAINT IF EXISTS chk_approval_requests_amount,
    DROP CONSTRAINT IF EXISTS chk_approval_requests_levels;
