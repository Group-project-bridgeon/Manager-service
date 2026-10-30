// Package repository implements PostgreSQL persistence for approval workflows.
package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/group-project-bridgeon/manager-service/internal/workflow/domain"
)

// PostgresWorkflowRepository implements service.WorkflowRepository.
type PostgresWorkflowRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresWorkflowRepository constructs a PostgresWorkflowRepository.
func NewPostgresWorkflowRepository(pool *pgxpool.Pool) *PostgresWorkflowRepository {
	return &PostgresWorkflowRepository{pool: pool}
}

// CreateRequest inserts a new approval request into PostgreSQL.
func (r *PostgresWorkflowRepository) CreateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	query := `
		INSERT INTO approval_requests (
			id, service, resource_id, amount, requester_id, status, current_level, required_levels, expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.pool.Exec(ctx, query,
		req.ID,
		req.Service,
		req.ResourceID,
		req.Amount,
		req.RequesterID,
		string(req.Status),
		req.CurrentLevel,
		req.RequiredLevels,
		req.ExpiresAt,
		req.CreatedAt,
		req.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting approval request: %w", err)
	}

	return nil
}

// GetRequestByID retrieves an approval request by its ID.
func (r *PostgresWorkflowRepository) GetRequestByID(ctx context.Context, id string) (*domain.ApprovalRequest, error) {
	query := `
		SELECT id, service, resource_id, amount, requester_id, status, current_level, required_levels, expires_at, created_at, updated_at
		FROM approval_requests
		WHERE id = $1
	`

	var req domain.ApprovalRequest
	var statusStr string
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&req.ID,
		&req.Service,
		&req.ResourceID,
		&req.Amount,
		&req.RequesterID,
		&statusStr,
		&req.CurrentLevel,
		&req.RequiredLevels,
		&req.ExpiresAt,
		&req.CreatedAt,
		&req.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrRequestNotFound
		}
		return nil, fmt.Errorf("querying approval request %s: %w", id, err)
	}
	req.Status = domain.Status(statusStr)

	return &req, nil
}

// GetRequestByResource finds the most recent approval request for a service resource.
func (r *PostgresWorkflowRepository) GetRequestByResource(ctx context.Context, serviceName, resourceID string) (*domain.ApprovalRequest, error) {
	query := `
		SELECT id, service, resource_id, amount, requester_id, status, current_level, required_levels, expires_at, created_at, updated_at
		FROM approval_requests
		WHERE service = $1 AND resource_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`

	var req domain.ApprovalRequest
	var statusStr string
	err := r.pool.QueryRow(ctx, query, serviceName, resourceID).Scan(
		&req.ID,
		&req.Service,
		&req.ResourceID,
		&req.Amount,
		&req.RequesterID,
		&statusStr,
		&req.CurrentLevel,
		&req.RequiredLevels,
		&req.ExpiresAt,
		&req.CreatedAt,
		&req.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrRequestNotFound
		}
		return nil, fmt.Errorf("querying request for resource %s: %w", resourceID, err)
	}
	req.Status = domain.Status(statusStr)

	return &req, nil
}

// UpdateRequest updates status, current level, and timestamps.
func (r *PostgresWorkflowRepository) UpdateRequest(ctx context.Context, req domain.ApprovalRequest) error {
	query := `
		UPDATE approval_requests
		SET status = $1, current_level = $2, updated_at = $3
		WHERE id = $4
	`

	_, err := r.pool.Exec(ctx, query, string(req.Status), req.CurrentLevel, req.UpdatedAt, req.ID)
	if err != nil {
		return fmt.Errorf("updating approval request %s: %w", req.ID, err)
	}

	return nil
}

// RecordAction logs an approval or rejection action.
func (r *PostgresWorkflowRepository) RecordAction(ctx context.Context, action domain.ApprovalAction) error {
	query := `
		INSERT INTO approval_actions (id, request_id, actor_id, action, level, notes, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.pool.Exec(ctx, query,
		action.ID,
		action.RequestID,
		action.ActorID,
		action.Action,
		action.Level,
		action.Notes,
		action.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("recording approval action: %w", err)
	}

	return nil
}

// GetMatchingPolicy finds custom threshold policies if defined in the database.
func (r *PostgresWorkflowRepository) GetMatchingPolicy(ctx context.Context, serviceName, resourceType string, amount float64) (*domain.ApprovalPolicy, error) {
	query := `
		SELECT id, service, resource_type, min_amount, max_amount, required_role, required_levels, allow_self_approval
		FROM approval_policies
		WHERE service = $1 AND resource_type = $2 AND min_amount <= $3 AND (max_amount IS NULL OR max_amount > $3)
		ORDER BY min_amount DESC
		LIMIT 1
	`

	var policy domain.ApprovalPolicy
	err := r.pool.QueryRow(ctx, query, serviceName, resourceType, amount).Scan(
		&policy.ID,
		&policy.Service,
		&policy.ResourceType,
		&policy.MinAmount,
		&policy.MaxAmount,
		&policy.RequiredRole,
		&policy.RequiredLevels,
		&policy.AllowSelfApproval,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No custom policy found, use defaults
		}
		return nil, fmt.Errorf("querying matching policy: %w", err)
	}

	return &policy, nil
}

// ListActionsByRequestID retrieves all actions recorded for a request.
func (r *PostgresWorkflowRepository) ListActionsByRequestID(ctx context.Context, requestID string) ([]domain.ApprovalAction, error) {
	query := `
		SELECT id, request_id, actor_id, action, level, notes, created_at
		FROM approval_actions
		WHERE request_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.pool.Query(ctx, query, requestID)
	if err != nil {
		return nil, fmt.Errorf("querying actions: %w", err)
	}
	defer rows.Close()

	var actions []domain.ApprovalAction
	for rows.Next() {
		var a domain.ApprovalAction
		if err := rows.Scan(&a.ID, &a.RequestID, &a.ActorID, &a.Action, &a.Level, &a.Notes, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning action: %w", err)
		}
		actions = append(actions, a)
	}

	return actions, rows.Err()
}
