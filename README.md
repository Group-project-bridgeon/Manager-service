# Manager Service

Manager-service is the centralized governance, authorization, and workflow approval engine for the ERP platform. It manages role-based access control (RBAC), enforces multi-level approval hierarchies for organizational resources (such as purchasing bills), and guarantees an immutable audit trail.

---

## 1. System Architecture & Core Invariants

### 1.1 Authentication & Principal Extraction
- **Token Contract**: Manager-service validates RS256 JWTs issued exclusively by the Authentication service.
- **Single Source of Identity**: Identity is extracted solely from the cryptographically verified JWT claims (`user_id` and `sub`). Request bodies **never** supply identity fields (`requester_id`, `actor_id`, and `assigned_by` are stripped from DTOs and ignored if submitted).
- **Exact Global Permissions**: Authorization is enforced at the HTTP gateway via Gin middleware (`RequirePermission`) with exact string matching. No wildcard or prefix grants are allowed.
- **Key Rotation**: Supports zero-downtime key rotation via a multi-key KeyRing. Multiple RSA public keys can be supplied as concatenated PEM blocks or comma-delimited paths in `JWT_PUBLIC_KEY_PATH`.
- **Known Limitation**: `token_version` cannot be validated without an out-of-band synchronous call to the Authentication service; a revoked token remains valid until its 15-minute expiration timestamp (`exp`).

### 1.2 Concurrency, Transactions & Atomicity
- **Transactional State Transitions (`pgx.Tx`)**: Workflow state changes and audit action recordings are executed within a single database transaction via `ApplyDecisionTx`.
- **Optimistic Concurrency Control (OCC)**: State transitions conditionally match `WHERE id = $id AND current_level = $expectedLevel AND status = $expectedStatus`. If a concurrent approver acts simultaneously, exactly one transaction commits; all competing transactions receive `409 CONCURRENT_UPDATE` and roll back cleanly.
- **Four-Eyes Principle**: A manager who approved a prior level of a multi-level request cannot approve subsequent levels (`409 DUPLICATE_APPROVAL`).
- **Self-Approval Prohibition**: The creator/requester of a resource cannot approve their own submission unless an explicit policy with `allow_self_approval = true` matches (`403 SELF_APPROVAL_FORBIDDEN`).
- **Duplicate Submission Prevention**: A database partial unique index on `(service, resource_id) WHERE status IN ('pending', 'approved')` prevents duplicate concurrent submissions. If a previous request is rejected or expired, resubmission is permitted.
- **Immutable Audit Trail**: PostgreSQL trigger `trg_prevent_approval_actions_mutation` raises an exception on any `UPDATE` or `DELETE` against `approval_actions`.

---

## 2. API Contract & Permissions Matrix

### 2.1 Standard Envelopes
All responses adhere to the standard envelope format:

**Success Response (2xx):**
```json
{
  "data": { ... },
  "request_id": "0192e2b3-8c45-789a-bcde-f0123456789a"
}
```

**Error Response (4xx / 5xx):**
```json
{
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "lacking required permission: manager.approvals:approve"
  },
  "request_id": "0192e2b3-8c45-789a-bcde-f0123456789a"
}
```

### 2.2 Endpoints and Permission Matrix

| Method | Endpoint | Required Permission | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | *Public* | Liveness probe (returns 200 OK) |
| `GET` | `/readyz` | *Public* | Readiness probe (verifies DB ping connectivity; returns 503 on outage) |
| `POST` | `/api/v1/approvals/submit` | `manager.approvals:submit` | Submits a resource for approval workflow |
| `GET` | `/api/v1/approvals/status` | `manager.approvals:read` | Queries the current approval status for a resource |
| `GET` | `/api/v1/approvals/:id` | `manager.approvals:read` | Returns the full approval request and its audit history |
| `POST` | `/api/v1/approvals/:id/approve` | `manager.approvals:approve` | Records an approval decision for the current level |
| `POST` | `/api/v1/approvals/:id/reject` | `manager.approvals:reject` | Rejects the approval request |
| `GET` | `/api/v1/roles` | `manager.rbac:manage` | Lists all defined system roles |
| `GET` | `/api/v1/roles/:id` | `manager.rbac:manage` | Retrieves role details and assigned permissions |
| `POST` | `/api/v1/roles` | `manager.rbac:manage` | Creates a new role |
| `POST` | `/api/v1/users/:id/roles` | `manager.rbac:manage` | Assigns a role to a user (`assigned_by` derived from JWT) |
| `GET` | `/api/v1/users/:id/roles` | `manager.rbac:manage` | Lists roles assigned to a user |
| `DELETE`| `/api/v1/users/:id/roles/:role_id` | `manager.rbac:manage` | Revokes a role assignment from a user |
| `POST` | `/api/v1/authz/check` | `manager.authz:check` | Checks whether a user possesses authority for an action |

### 2.3 Required Migration for Authentication Service
The Authentication service database must seed the following permissions into its catalog:
```sql
INSERT INTO permissions (id, service, resource, action, description) VALUES
    ('manager.approvals:submit', 'manager', 'approvals', 'submit', 'Submit resource for manager approval'),
    ('manager.approvals:read', 'manager', 'approvals', 'read', 'View approval request status and history'),
    ('manager.approvals:approve', 'manager', 'approvals', 'approve', 'Approve pending workflow level'),
    ('manager.approvals:reject', 'manager', 'approvals', 'reject', 'Reject pending workflow'),
    ('manager.rbac:manage', 'manager', 'rbac', 'manage', 'Create roles and assign/revoke user roles'),
    ('manager.authz:check', 'manager', 'authz', 'check', 'Evaluate role permissions via authz check')
ON CONFLICT (id) DO NOTHING;
```

---

## 3. Configuration Reference

Configuration is strictly validated at application startup:

| Variable | Description | Default | Validation Rules |
| :--- | :--- | :--- | :--- |
| `APP_ENV` | Application environment | `development` | Must be `development`, `staging`, or `production` |
| `PORT` | HTTP server listening port | `8080` | Integer between 1 and 65535 |
| `LOG_LEVEL` | Slog minimum logging level | `info` | Must be `debug`, `info`, `warn`, or `error` |
| `READ_TIMEOUT` | HTTP server read timeout | `5s` | Must be positive duration |
| `WRITE_TIMEOUT` | HTTP server write timeout | `10s` | Must be positive duration |
| `IDLE_TIMEOUT` | HTTP server idle timeout | `120s` | Must be positive duration |
| `SHUTDOWN_TIMEOUT` | Graceful shutdown timeout | `5s` | Must be positive and `< 10s` |
| `DB_HOST` | PostgreSQL hostname | `localhost` | Non-empty string |
| `DB_PORT` | PostgreSQL port | `5432` | Integer between 1 and 65535 |
| `DB_USER` | PostgreSQL username | `postgres` | Non-empty string |
| `DB_PASSWORD` | PostgreSQL password | `""` | Required in `production` environment |
| `DB_NAME` | PostgreSQL database name | `erp_manager` | Non-empty string |
| `DB_SSLMODE` | PostgreSQL SSL connection mode | `disable` | One of `disable`, `require`, `verify-ca`, `verify-full` |
| `DB_MAX_CONNS` | Pgx connection pool maximum size | `25` | Positive integer `>= DB_MIN_CONNS` |
| `DB_MIN_CONNS` | Pgx connection pool minimum size | `5` | Non-negative integer |
| `DB_MAX_CONN_LIFETIME` | Maximum connection reuse duration | `1h` | Must be positive duration |
| `DB_MAX_CONN_IDLE_TIME` | Maximum idle connection duration | `30m` | Must be positive duration |
| `JWT_PUBLIC_KEY_PATH` | Path(s) to RSA public key PEM file(s) | *None* | Required. RSA key $\ge 2048$ bits. Supports comma-separated paths |
| `JWT_ISSUER` | Expected JWT `iss` claim | `erp-auth` | Non-empty string |
| `JWT_AUDIENCE` | Expected JWT `aud` claim | `erp-api` | Non-empty string |

---

## 4. Development & Testing

### 4.1 Prerequisites
- Go 1.22+
- PostgreSQL 16+
- Docker & Docker Compose
- `golangci-lint`

### 4.2 Makefile Commands
```bash
make test             # Run all unit and integration tests with -race
make lint             # Run golangci-lint
make build            # Compile statically linked binary into bin/server
make migrate-up       # Run pending Goose database migrations
make migrate-down     # Roll back last Goose migration
make migrate-status   # Display applied database migrations
```

### 4.3 Running via Docker Compose
To start Manager-service and PostgreSQL together on the shared `erp-network`:
```bash
docker compose up --build -d
```
The server container awaits the PostgreSQL health check before starting.

### 4.4 Postman Testing
A comprehensive Postman test suite is provided in the [`postman/`](file:///home/yadu/project/Grp/Manager-service/postman) directory:
- [`Manager-Service.postman_collection.json`](file:///home/yadu/project/Grp/Manager-service/postman/Manager-Service.postman_collection.json): Contains 17 requests across 4 folders covering Health checks, Approvals workflow (single & multi-level), RBAC role management, and negative security scenarios (401, 403, 409).
- [`Manager-Service.postman_environment.json`](file:///home/yadu/project/Grp/Manager-service/postman/Manager-Service.postman_environment.json): Environment variables including `baseUrl` and fresh RS256 JWT tokens.

To refresh tokens or regenerate the Postman files:
```bash
make postman
```

**Steps to run in Postman:**
1. Open Postman, click **Import**, and select both files from `postman/`.
2. In the top-right environment selector, choose **Manager Service (Local)**.
3. Start the Manager service (`make run`).
4. Execute requests individually or run the full suite using Postman's **Collection Runner**. Variables (such as `approval_id`) automatically chain across requests!
