// Package database owns the connection pool, the rotation of the authority
// every credential is measured against, and the bounded rollback every
// transaction in the service is abandoned with.
package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connection pool limits. They are fixed rather than configurable: the service
// is stateless and horizontally scaled, so a per-instance pool that can grow
// without bound would exhaust the database's connection slots long before it
// helped throughput.
const (
	maxConnections        = 16
	minConnections        = 2
	maxConnectionLifetime = 30 * time.Minute
	maxConnectionIdleTime = 5 * time.Minute
	connectTimeout        = 10 * time.Second
	healthCheckPeriod     = 30 * time.Second
)

// ErrUnusableDatabaseURL reports a connection string the driver cannot use. It
// deliberately carries no detail, because the string holds the database
// password.
var ErrUnusableDatabaseURL = errors.New("the database connection string cannot be used")

// Open connects to PostgreSQL and proves the connection works before returning.
//
// Start-up fails rather than serving requests that would each discover the
// database is unreachable.
func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		// The parse error quotes the connection string, so it is not wrapped.
		return nil, ErrUnusableDatabaseURL
	}

	poolConfig.MaxConns = maxConnections
	poolConfig.MinConns = minConnections
	poolConfig.MaxConnLifetime = maxConnectionLifetime
	poolConfig.MaxConnIdleTime = maxConnectionIdleTime
	poolConfig.HealthCheckPeriod = healthCheckPeriod
	poolConfig.ConnConfig.ConnectTimeout = connectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, ErrUnusableDatabaseURL
	}

	pingContext, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	if err := pool.Ping(pingContext); err != nil {
		pool.Close()

		return nil, fmt.Errorf("the database did not answer: %w", err)
	}

	return pool, nil
}
