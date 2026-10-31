// Package auth provides infrastructure for verifying JWTs and extracting typed caller principals.
package auth

import "github.com/google/uuid"

// Principal represents the authenticated caller's identity and permissions.
// It is the sole source of identity for authenticated requests.
type Principal struct {
	UserID      uuid.UUID
	Email       string
	Permissions []string
}

// HasPermission checks if the principal possesses the exact permission.
func (p *Principal) HasPermission(permission string) bool {
	for _, perm := range p.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}
