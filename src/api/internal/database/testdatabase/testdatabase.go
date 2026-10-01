// Package testdatabase gives a test its own PostgreSQL database, so tests run
// in parallel and cannot see each other's rows.
//
// The server is named by TEST_DATABASE_URL, connected to as its administrative
// database, and the schema comes from the template named by
// TEST_TEMPLATE_DATABASE, which the Goose CLI migrated before the tests start.
// Selecting a test that needs either is asking for PostgreSQL, so without them
// the test fails. Never point them at a server holding real accounts: these
// helpers create and drop databases.
package testdatabase

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ServerURLVariable names the environment variable that points at the server.
const ServerURLVariable = "TEST_DATABASE_URL"

// TemplateVariable names the environment variable holding the name of the
// migrated database every schema-bearing test database is cloned from.
const TemplateVariable = "TEST_TEMPLATE_DATABASE"

// statementTimeout bounds every helper's work, so a test that deadlocks against
// another connection fails with its own message instead of the suite timing out.
const statementTimeout = 30 * time.Second

// ServerURL returns the server the database tests connect to, failing the test
// when none is configured.
func ServerURL(t *testing.T) string {
	t.Helper()

	return requireSetting(t, ServerURLVariable)
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

	return create(t, "")
}

// NewMigrated creates a database holding this service's schema.
func NewMigrated(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool, _ := NewMigratedWithURL(t)

	return pool
}

// NewMigratedWithURL creates a database holding this service's schema and also
// returns its connection URL, for a test that starts a command against it.
func NewMigratedWithURL(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()

	return create(t, requireSetting(t, TemplateVariable))
}

func create(t *testing.T, template string) (*pgxpool.Pool, string) {
	t.Helper()

	serverURL := ServerURL(t)
	name := uniqueName(t)

	administrative := connect(t, serverURL, 1)

	statement := "CREATE DATABASE " + quoteIdentifier(name)
	if template != "" {
		statement += " TEMPLATE " + quoteIdentifier(template)
	}

	execute(t, administrative, statement)

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

// requireSetting reads a setting the database tests cannot run without.
func requireSetting(t *testing.T, name string) string {
	t.Helper()

	value, err := setting(name)
	if err != nil {
		t.Fatal(err)
	}

	return value
}

func setting(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is not set, so the database tests cannot run", name)
	}

	return value, nil
}

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

// AwaitLockWaiters returns once the given number of connections to the test
// database are waiting on a lock, which is how a test synchronises with work it
// has deliberately blocked. It reports a failure rather than waiting for ever,
// and returns it rather than failing the test because it is usually called
// from a goroutine of the test's own.
func AwaitLockWaiters(ctx context.Context, pool *pgxpool.Pool, waiting int) error {
	deadline := time.Now().Add(statementTimeout)

	for time.Now().Before(deadline) {
		var found int

		err := pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'`,
		).Scan(&found)
		if err != nil {
			return fmt.Errorf("reading which connections are waiting on a lock: %w", err)
		}

		if found >= waiting {
			return nil
		}

		time.Sleep(10 * time.Millisecond)
	}

	return fmt.Errorf("%d connections never came to wait on a lock", waiting)
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
