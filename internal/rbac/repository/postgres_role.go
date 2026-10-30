// Package repository provides PostgreSQL implementations of RBAC persistence interfaces.
package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/group-project-bridgeon/manager-service/internal/rbac/domain"
)

const pgErrUniqueViolation = "23505"

// PostgresRoleRepository implements service.RoleRepository using pgxpool.
type PostgresRoleRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRoleRepository constructs a PostgresRoleRepository with the given connection pool.
func NewPostgresRoleRepository(pool *pgxpool.Pool) *PostgresRoleRepository {
	return &PostgresRoleRepository{pool: pool}
}

// List retrieves all roles ordered by identifier.
func (r *PostgresRoleRepository) List(ctx context.Context) ([]domain.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		ORDER BY id ASC
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("querying roles: %w", err)
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

// GetByID retrieves a single role by its identifier.
func (r *PostgresRoleRepository) GetByID(ctx context.Context, id string) (*domain.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE id = $1
	`

	var role domain.Role
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrRoleNotFound
		}
		return nil, fmt.Errorf("querying role by id %s: %w", id, err)
	}

	return &role, nil
}

// Create inserts a new role record into PostgreSQL.
func (r *PostgresRoleRepository) Create(ctx context.Context, role domain.Role) error {
	query := `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.pool.Exec(ctx, query,
		role.ID,
		role.Name,
		role.Description,
		role.CreatedAt,
		role.UpdatedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgErrUniqueViolation {
			return domain.ErrRoleAlreadyExists
		}
		return fmt.Errorf("inserting role %s: %w", role.ID, err)
	}

	return nil
}
