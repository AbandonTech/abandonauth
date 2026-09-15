//go:build integration && !devtools

package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
)

// rollbackBound is the longest a rollback may take before the test calls it
// hung: the five seconds the cleanup allows itself, and a margin for the
// machine.
const rollbackBound = 5*time.Second + 2*time.Second

// A request that has been abandoned by its client still gives its connection
// back: the transaction it began is rolled back with the row it wrote and the
// lock it held, within a bound, and nothing about the cancelled request stops
// the next one acquiring either.
func TestACancelledTransactionIsStillRolledBackInFull(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)

	ctx, cancel := context.WithCancel(t.Context())

	transaction, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning the transaction: %v", err)
	}

	if _, err := transaction.Exec(ctx, `INSERT INTO "User" ("username") VALUES ('half-created')`); err != nil {
		t.Fatalf("writing the row that must not survive: %v", err)
	}

	if _, err := transaction.Exec(ctx, "SELECT pg_advisory_xact_lock(4242)"); err != nil {
		t.Fatalf("taking the lock that must not survive: %v", err)
	}

	cancel()

	started := time.Now()

	if err := database.Rollback(ctx, transaction); err != nil {
		t.Errorf("rolling back after the request was cancelled: %v", err)
	}

	if elapsed := time.Since(started); elapsed > rollbackBound {
		t.Errorf("rolling back took %v, want it bounded", elapsed)
	}

	var remaining int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM "User" WHERE "username" = 'half-created'`,
	).Scan(&remaining); err != nil {
		t.Fatalf("reading what the cancelled request left: %v", err)
	}

	if remaining != 0 {
		t.Error("a row written by the cancelled request survived")
	}

	next, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("beginning the next transaction: %v", err)
	}

	defer func() { _ = database.Rollback(t.Context(), next) }()

	var acquired bool
	if err := next.QueryRow(t.Context(), "SELECT pg_try_advisory_xact_lock(4242)").Scan(&acquired); err != nil {
		t.Fatalf("asking for the lock the cancelled request held: %v", err)
	}

	if !acquired {
		t.Error("the lock the cancelled request held is still held")
	}

	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatalf("acquiring a connection after the cancelled request: %v", err)
	}

	connection.Release()
}

// Rolling back a transaction that has already committed is not a failure: the
// deferred cleanup on a successful path has nothing to undo.
func TestRollingBackACommittedTransactionIsNotAnError(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)

	transaction, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("beginning the transaction: %v", err)
	}

	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("committing: %v", err)
	}

	if err := database.Rollback(t.Context(), transaction); err != nil {
		t.Errorf("rolling back after a commit reported %v", err)
	}
}
