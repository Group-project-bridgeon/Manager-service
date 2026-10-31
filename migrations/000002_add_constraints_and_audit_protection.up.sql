-- 1. Check constraints on approval_requests
ALTER TABLE approval_requests
    ADD CONSTRAINT chk_approval_requests_status
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    ADD CONSTRAINT chk_approval_requests_amount
    CHECK (amount > 0),
    ADD CONSTRAINT chk_approval_requests_levels
    CHECK (current_level >= 0 AND required_levels > 0 AND current_level <= required_levels);

-- 2. Check constraints on approval_actions
ALTER TABLE approval_actions
    ADD CONSTRAINT chk_approval_actions_action
    CHECK (action IN ('approve', 'reject')),
    ADD CONSTRAINT chk_approval_actions_level
    CHECK (level > 0);

-- 3. Check constraints on approval_policies
ALTER TABLE approval_policies
    ADD CONSTRAINT chk_approval_policies_amounts
    CHECK (min_amount >= 0 AND (max_amount IS NULL OR max_amount >= min_amount)),
    ADD CONSTRAINT chk_approval_policies_required_levels
    CHECK (required_levels > 0);

-- 4. Partial unique index to enforce single active approval request per resource
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_approval_per_resource
    ON approval_requests (service, resource_id)
    WHERE status IN ('pending', 'approved');

-- 5. Immutability trigger on approval_actions to protect audit history
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'approval_actions records are strictly immutable and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_approval_actions_mutation ON approval_actions;
CREATE TRIGGER trg_prevent_approval_actions_mutation
BEFORE UPDATE OR DELETE ON approval_actions
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_mutation();
