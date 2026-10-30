package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
)

// PostgresUserRoleRepository implements service.UserRoleRepository using pgxpool.
type PostgresUserRoleRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresUserRoleRepository constructs a PostgresUserRoleRepository.
func NewPostgresUserRoleRepository(pool *pgxpool.Pool) *PostgresUserRoleRepository {
	return &PostgresUserRoleRepository{pool: pool}
}

// Assign inserts a user_role record into PostgreSQL.
func (r *PostgresUserRoleRepository) Assign(ctx context.Context, ur domain.UserRole) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, assigned_by, created_at)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.pool.Exec(ctx, query, ur.UserID, ur.RoleID, ur.AssignedBy, ur.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgErrUniqueViolation {
			return domain.ErrUserRoleAlreadyAssigned
		}
		return fmt.Errorf("assigning role %s to user %s: %w", ur.RoleID, ur.UserID, err)
	}

	return nil
}

// Revoke removes a user_role record from PostgreSQL.
func (r *PostgresUserRoleRepository) Revoke(ctx context.Context, userID, roleID string) error {
	query := `
		DELETE FROM user_roles
		WHERE user_id = $1 AND role_id = $2
	`

	res, err := r.pool.Exec(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("revoking role %s from user %s: %w", roleID, userID, err)
	}

	if res.RowsAffected() == 0 {
		return domain.ErrUserRoleNotFound
	}

	return nil
}

// GetRolesByUserID retrieves all roles granted to the user.
func (r *PostgresUserRoleRepository) GetRolesByUserID(ctx context.Context, userID string) ([]domain.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.id ASC
	`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("querying roles for user %s: %w", userID, err)
	}
	defer rows.Close()

	var roles []domain.Role
	for rows.Next() {
		var role domain.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning role row: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating role rows: %w", err)
	}

	return roles, nil
}

// CheckPermission checks whether any of the user's roles grants the requested permission.
func (r *PostgresUserRoleRepository) CheckPermission(ctx context.Context, userID, serviceName, resource, action string) (bool, []string, error) {
	// 1. Fetch user roles
	rolesQuery := `
		SELECT role_id FROM user_roles WHERE user_id = $1 ORDER BY role_id ASC
	`
	rows, err := r.pool.Query(ctx, rolesQuery, userID)
	if err != nil {
		return false, nil, fmt.Errorf("querying user roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil {
			return false, nil, fmt.Errorf("scanning role id: %w", err)
		}
		roles = append(roles, roleID)
	}

	if len(roles) == 0 {
		return false, nil, nil
	}

	// 2. Admin superuser bypass
	for _, role := range roles {
		if role == "admin" {
			return true, roles, nil
		}
	}

	// 3. Check role_permissions table
	permQuery := `
		SELECT EXISTS (
			SELECT 1
			FROM role_permissions rp
			JOIN permissions p ON rp.permission_id = p.id
			WHERE rp.role_id = ANY($1)
			  AND p.service = $2
			  AND (p.resource = $3 OR p.resource = '*')
			  AND (p.action = $4 OR p.action = '*')
		)
	`

	var hasPerm bool
	if err := r.pool.QueryRow(ctx, permQuery, roles, serviceName, resource, action).Scan(&hasPerm); err != nil {
		return false, nil, fmt.Errorf("evaluating permissions: %w", err)
	}

	return hasPerm, roles, nil
}
