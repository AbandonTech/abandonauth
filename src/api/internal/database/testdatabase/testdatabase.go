// Package testdatabase gives a test its own PostgreSQL database, so tests run
// in parallel and cannot see each other's rows.
//
// The server is named by TEST_DATABASE_URL. Without it a test skips rather than
// fails, because a plain `go test` run has no PostgreSQL. Never point it at a
// database holding real accounts: these helpers create databases, drop them,
// and rewrite migration history.
package testdatabase

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database"
)

// ServerURLVariable names the environment variable that points at the server.
const ServerURLVariable = "TEST_DATABASE_URL"

// skipReason is matched by the check script, which fails a run where the
// database tests silently skipped instead of proving the schema works.
const skipReason = ServerURLVariable + " is not set, so the database tests cannot run"

// statementTimeout bounds every helper's work, so a test that deadlocks against
// another connection fails with its own message instead of the suite timing out.
const statementTimeout = 30 * time.Second

// ServerURL returns the server the database tests connect to, skipping the test
// when none is configured.
func ServerURL(t *testing.T) string {
	t.Helper()

	value := strings.TrimSpace(os.Getenv(ServerURLVariable))
	if value == "" {
		t.Skip(skipReason)
	}

	return value
}

// New creates an empty database for one test and returns a pool connected to it.
func New(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool, _ := NewWithURL(t)

	return pool
}

// NewWithURL creates an empty database and also returns its connection URL, for
// the tests that need to open a second connection of their own.
func NewWithURL(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()

	serverURL := ServerURL(t)
	name := uniqueName(t)

	administrative := connect(t, serverURL, 1)

	execute(t, administrative, fmt.Sprintf("CREATE DATABASE %s", quoteIdentifier(name)))

	t.Cleanup(func() {
		// FORCE closes connections the test left open. Without it a pool that
		// has not finished closing keeps the database alive and leaks it.
		dropContext, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), statementTimeout)
		defer cancel()

		_, err := administrative.Exec(
			dropContext,
			fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", quoteIdentifier(name)),
		)
		if err != nil {
			t.Errorf("dropping the test database: %v", err)
		}

		administrative.Close()
	})

	databaseURL := replaceDatabaseName(t, serverURL, name)
	pool := connect(t, databaseURL, maxTestConnections)

	t.Cleanup(pool.Close)

	return pool, databaseURL
}

// NewMigrated creates a database with this service's schema applied.
func NewMigrated(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool := New(t)

	Migrate(t, pool)

	return pool
}

// Migrate applies every migration this service carries.
func Migrate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	handle := database.OpenMigrationHandle(pool)
	defer handle.Close()

	if err := database.Migrate(t.Context(), handle, quietMigrationLog{}); err != nil {
		t.Fatalf("applying migrations: %v", err)
	}
}

// NewUnadopted creates a database that holds the account schema but no record of
// this service having migrated it.
func NewUnadopted(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool := New(t)

	MakeUnadopted(t, pool)

	return pool
}

// MakeUnadopted brings an empty database to the state a start-up must refuse to
// migrate: it holds the account schema, but nothing records that this service
// put it there.
func MakeUnadopted(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	handle := database.OpenMigrationHandle(pool)
	defer handle.Close()

	if err := database.MigrateTo(
		t.Context(), handle, quietMigrationLog{}, database.BaselineVersion,
	); err != nil {
		t.Fatalf("building the account schema: %v", err)
	}

	// Leaving the history the baseline just wrote would make the database look
	// migrated by this service, which is the state these tests need it not to be
	// in.
	execute(t, pool, "DROP TABLE IF EXISTS "+database.MigrationHistoryTable)
}

// quietMigrationLog keeps the migration runner's progress out of test output,
// where it would bury the assertion that failed.
type quietMigrationLog struct{}

func (quietMigrationLog) Printf(string, ...any) {}
func (quietMigrationLog) Fatalf(string, ...any) {}

// maxTestConnections keeps one test's pool small. Tests run in parallel and each
// one holds its own database, so a pool sized for a deployment would exhaust the
// server's connection slots long before the suite finished.
const maxTestConnections = 4

func connect(t *testing.T, databaseURL string, maxConnections int32) *pgxpool.Pool {
	t.Helper()

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("%s is not a usable connection string", ServerURLVariable)
	}

	poolConfig.MaxConns = maxConnections
	poolConfig.MinConns = 0
	poolConfig.ConnConfig.ConnectTimeout = statementTimeout

	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatalf("connecting to the test server: %v", err)
	}

	if err := pool.Ping(t.Context()); err != nil {
		pool.Close()
		t.Fatalf("the test server did not answer: %v", err)
	}

	return pool
}

// Execute runs setup statements against a test database.
func Execute(t *testing.T, pool *pgxpool.Pool, statements string, arguments ...any) {
	t.Helper()

	executeWithArguments(t, pool, statements, arguments...)
}

func execute(t *testing.T, pool *pgxpool.Pool, statements string) {
	t.Helper()

	executeWithArguments(t, pool, statements)
}

func executeWithArguments(t *testing.T, pool *pgxpool.Pool, statements string, arguments ...any) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), statementTimeout)
	defer cancel()

	if _, err := pool.Exec(ctx, statements, arguments...); err != nil {
		t.Fatalf("running test setup statements: %v", err)
	}
}

// uniqueName derives a database name from the test's name and random bytes, so
// a failure names the test that left it behind and two runs never collide.
func uniqueName(t *testing.T) string {
	t.Helper()

	safe := strings.Map(func(character rune) rune {
		switch {
		case character >= 'a' && character <= 'z',
			character >= '0' && character <= '9':
			return character
		case character >= 'A' && character <= 'Z':
			return character + ('a' - 'A')
		default:
			return '_'
		}
	}, t.Name())

	const maximumDerivedLength = 30
	if len(safe) > maximumDerivedLength {
		safe = safe[:maximumDerivedLength]
	}

	return "abandonauth_test_" + safe + "_" + newIdentifier(t)[:8]
}

// Identifier returns a random hexadecimal identifier, for the tests that must
// supply a primary key of their own.
func Identifier(t *testing.T) string {
	t.Helper()

	return newIdentifier(t)
}

func newIdentifier(t *testing.T) string {
	t.Helper()

	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generating a test identifier: %v", err)
	}

	return hex.EncodeToString(value)
}

func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func replaceDatabaseName(t *testing.T, serverURL, name string) string {
	t.Helper()

	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("%s is not a URL", ServerURLVariable)
	}

	parsed.Path = "/" + name

	return parsed.String()
}

// OpenMigrationHandle returns a database/sql handle for the procedures that are
// written against it.
func OpenMigrationHandle(t *testing.T, pool *pgxpool.Pool) *sql.DB {
	t.Helper()

	handle := database.OpenMigrationHandle(pool)
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Errorf("closing the migration handle: %v", err)
		}
	})

	return handle
}
