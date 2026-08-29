//go:build integration

package adoption_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database/adoption"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
)

// recordedHistory describes the migration history a database carries. These
// tests use it to reproduce what the deployed database shows, and to corrupt it
// in each of the ways adoption has to refuse.
type recordedHistory struct {
	// omit leaves the history table out entirely.
	omit bool
	// omitRows creates the table but records nothing in it.
	omitRows bool
	// changeChecksumOf records a different digest for the named migration, as a
	// database whose statements were edited would show.
	changeChecksumOf string
	// duplicateLast records the final migration twice, as a retried apply would.
	duplicateLast bool
	// appliedStepsOf records a different applied step count for the named
	// migration, and appliedSteps is that count.
	appliedStepsOf string
	appliedSteps   int
	// unfinishedLast leaves the final migration without a completion time.
	unfinishedLast bool
	// rolledBackLast marks the final migration as reversed.
	rolledBackLast bool
	// addUnknown records a migration this service has never heard of.
	addUnknown string
	// dropLast records one migration fewer than the schema needs.
	dropLast bool
}

// newUnadopted creates a database in the state adoption acts on: the account
// schema, no history of this service's own, and the recorded history described.
func newUnadopted(t *testing.T, history recordedHistory) *pgxpool.Pool {
	t.Helper()

	pool := testdatabase.NewUnadopted(t)

	applyRecordedHistory(t, pool, history)

	return pool
}

func applyRecordedHistory(t *testing.T, pool *pgxpool.Pool, history recordedHistory) {
	t.Helper()

	if history.omit {
		return
	}

	testdatabase.Execute(t, pool, `
		CREATE TABLE "`+adoption.RecordedHistoryTable+`" (
			id                  VARCHAR(36) PRIMARY KEY NOT NULL,
			checksum            VARCHAR(64) NOT NULL,
			finished_at         TIMESTAMPTZ,
			migration_name      VARCHAR(255) NOT NULL,
			logs                TEXT,
			rolled_back_at      TIMESTAMPTZ,
			started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
			applied_steps_count INTEGER NOT NULL DEFAULT 0
		)
	`)

	if history.omitRows {
		return
	}

	recordMigrations(t, pool, history)
}

func recordMigrations(t *testing.T, pool *pgxpool.Pool, history recordedHistory) {
	t.Helper()

	migrations := adoption.ExpectedHistory()

	if history.dropLast {
		migrations = migrations[:len(migrations)-1]
	}

	if history.addUnknown != "" {
		migrations = append(migrations, adoption.AppliedMigration{
			Name:     history.addUnknown,
			Checksum: strings.Repeat("0", 64),
		})
	}

	if history.duplicateLast && len(migrations) > 0 {
		migrations = append(migrations, migrations[len(migrations)-1])
	}

	// The recorded start times must order the rows the way they were applied,
	// which is how adoption reads them back.
	started := time.Date(2022, time.July, 30, 11, 17, 6, 0, time.UTC)

	for index, migration := range migrations {
		checksum := migration.Checksum
		if migration.Name == history.changeChecksumOf {
			checksum = strings.Repeat("f", 64)
		}

		steps := 1
		if migration.Name == history.appliedStepsOf {
			steps = history.appliedSteps
		}

		last := index == len(migrations)-1

		var finished any = started.Add(time.Second)
		if last && history.unfinishedLast {
			finished = nil
		}

		var rolledBack any
		if last && history.rolledBackLast {
			rolledBack = started.Add(2 * time.Second)
		}

		testdatabase.Execute(t, pool, `
			INSERT INTO "`+adoption.RecordedHistoryTable+`"
				(id, checksum, finished_at, migration_name, rolled_back_at, started_at, applied_steps_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`,
			testdatabase.Identifier(t), checksum, finished, migration.Name, rolledBack,
			started.Add(time.Duration(index)*time.Minute), steps,
		)
	}
}
