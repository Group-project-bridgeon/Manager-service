# Manager-service
decides what each user or role may do in each service, and approves things such as purchase bills before they proceed.
now this is my new service to the erp platform  which is manager service this servie manages all the erp platform 
2. Roles and permissions list

A table of role → permissions for the first version, for example:

Role	Can do
admin	everything, including managing roles
manager	approve bills, view all services
purchaser	create bills, view catalog and parties
inventory_clerk	adjust and receive stock
accountant	view approved bills, create payables

What approval thresholds apply? For example, under ₹50,000 needs one manager, and above that needs two levels.
Can anyone with the manager role approve, or only certain managers?
Can the requester approve their own bill? My default is no.
Can a rejected bill be resubmitted, or does it need a new bill?
Does a pending request expire?

Also define the bill status lifecycle, which Purchasing must follow: draft → pending_approval → approved | rejected, and then what happens after approved (paid, received).

## Authentication & Authorization

Manager-service authenticates incoming requests using RS256 JSON Web Tokens (JWT) issued by the Authentication service. The verified JWT is the single source of truth for caller identity and permissions.

### Environment Configuration

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `JWT_PUBLIC_KEY_PATH` | Path to RSA public key PEM file (min 2048 bits) | - | **Yes** |
| `JWT_ISSUER` | Expected JWT issuer claim (`iss`) | `erp-auth` | No |
| `JWT_AUDIENCE` | Expected JWT audience claim (`aud`) | `erp-api` | No |

### Security Model
- **Algorithm**: RS256 only. All symmetric algorithms (e.g., HS256) and "none" are rejected.
- **Key Requirement**: RSA public key >= 2048 bits loaded from PEM file. Private keys are never mounted or accessed by Manager service.
- **Token Verification**: Signature, `exp`, `iat`, `nbf`, `iss`, and `aud` are strictly validated with 0s clock leeway. Token lifetime (`exp - iat`) must not exceed 15 minutes.
- **Caller Identity**: Extracted strictly from JWT `user_id` (and matching `sub`). Identity fields in request bodies (`requester_id`, `actor_id`) are not accepted.
- **Route Authorization**: Route-level permissions matching exact global grants (`manager.approvals:submit`, `manager.approvals:read`, `manager.approvals:approve`, `manager.approvals:reject`, `manager.rbac:manage`, `manager.authz:check`).
- **Known Limitation**: `token_version` is embedded in the token but not checked against an external revocation cache; revoked tokens remain valid until their maximum 15-minute expiration.
