package database

import "context"

// Pinger abstracts the Ping method of a database connection pool.
type Pinger interface {
	Ping(ctx context.Context) error
}

// HealthChecker implements api.ReadinessChecker to verify database connectivity.
type HealthChecker struct {
	pinger Pinger
}

// NewHealthChecker constructs a HealthChecker wrapping a database pinger.
func NewHealthChecker(pinger Pinger) *HealthChecker {
	return &HealthChecker{pinger: pinger}
}

// Check verifies that PostgreSQL responds to ping.
func (h *HealthChecker) Check(ctx context.Context) error {
	if h.pinger == nil {
		return nil
	}
	return h.pinger.Ping(ctx)
}
