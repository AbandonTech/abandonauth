// Package adoption takes ownership of a database that already holds the account
// schema but no migration history of this service's own.
//
// Any mismatch between the schema and what this service expects is a hard stop,
// which is what lets start-up refuse a populated database outright rather than
// guess whether migrating it is safe.
//
// It runs once, from the command line, at cutover. Delete this package and its
// tests once that is done.
package adoption

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/pressly/goose/v3"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

// RecordedHistoryTable is the migration history the deployed database carries.
// The name is that database's, not a choice made here. Verify reads it to
// establish where the schema came from; migration 20260827000200 drops it once
// this service's own history is authoritative.
const RecordedHistoryTable = "_prisma_migrations"

// Reasons a database cannot be adopted. Each one is a stop: the operator has to
// look at the database, not retry.
var (
	ErrHistoryMissing = errors.New(
		"the database holds application tables but no record of the migrations that built them",
	)
	ErrHistoryMismatch = errors.New(
		"the recorded migrations are not the ones this service was built against",
	)
	ErrSchemaMismatch = errors.New(
		"the database schema differs from the one this service was built against",
	)
	ErrPartialMigrationHistory = errors.New(
		"the database has a migration history that does not include the baseline",
	)
	ErrUnsafeCallbackURIs = errors.New(
		"the database holds registered callback URIs that the current rules refuse",
	)
)

// Outcome is what inspecting a database concluded.
type Outcome string

const (
	// OutcomeNewDatabase means there is nothing to adopt: migrations can simply
	// be applied.
	OutcomeNewDatabase Outcome = "new database"
	// OutcomeAlreadyAdopted means this service already owns the schema.
	OutcomeAlreadyAdopted Outcome = "already adopted"
	// OutcomeAdoptable means the schema matches and adoption would succeed.
	OutcomeAdoptable Outcome = "adoptable"
	// OutcomeAdopted means the schema was adopted by this call.
	OutcomeAdopted Outcome = "adopted"
)

// Report is what an inspection found. It carries no callback URI and no other
// row value.
type Report struct {
	Outcome Outcome

	// RecordedMigrations is how many applied migrations the database records.
	RecordedMigrations int
	// SchemaDifferences lists how the schema differs from the expected shape.
	SchemaDifferences []FingerprintDifference
	// UnsafeCallbackURIIDs identifies the rows an operator has to correct, by
	// primary key, so they can be found without printing the URI itself.
	UnsafeCallbackURIIDs []int32
}

// Verify reports whether this service can take ownership of the schema in the
// database, without changing anything.
func Verify(ctx context.Context, conn database.Conn) (Report, error) {
	state, err := database.InspectSchema(ctx, conn)
	if err != nil {
		return Report{}, err
	}

	recorded, err := hasRecordedHistory(ctx, conn)
	if err != nil {
		return Report{}, err
	}

	if state.IsEmpty() {
		if recorded {
			return Report{}, fmt.Errorf(
				"%w: a migration history exists but the tables it describes do not",
				ErrSchemaMismatch,
			)
		}

		return Report{Outcome: OutcomeNewDatabase}, nil
	}

	if state.HasMigrationHistory {
		version, err := currentMigrationVersion(ctx, conn)
		if err != nil {
			return Report{}, err
		}

		if version >= database.BaselineVersion {
			return Report{Outcome: OutcomeAlreadyAdopted}, nil
		}

		return Report{}, fmt.Errorf("%w: it is at version %d", ErrPartialMigrationHistory, version)
	}

	if !state.IsComplete() {
		return Report{}, fmt.Errorf(
			"%w: these tables are missing: %v",
			ErrSchemaMismatch, state.MissingAccountTables,
		)
	}

	report := Report{Outcome: OutcomeAdoptable}

	if !recorded {
		return Report{}, ErrHistoryMissing
	}

	recordedMigrations, err := verifyRecordedMigrations(ctx, conn)
	if err != nil {
		return Report{}, err
	}

	report.RecordedMigrations = recordedMigrations

	fingerprint, err := ReadSchemaFingerprint(ctx, conn)
	if err != nil {
		return Report{}, err
	}

	if differences := CompareSchemaFingerprint(fingerprint); len(differences) > 0 {
		report.SchemaDifferences = differences

		return report, fmt.Errorf("%w: %d differences, first is %q",
			ErrSchemaMismatch, len(differences), differences[0].String())
	}

	unsafe, err := findUnsafeCallbackURIs(ctx, conn)
	if err != nil {
		return Report{}, err
	}

	if len(unsafe) > 0 {
		report.UnsafeCallbackURIIDs = unsafe

		return report, fmt.Errorf(
			"%w: %d rows, by CallbackUri id: %v",
			ErrUnsafeCallbackURIs, len(unsafe), unsafe,
		)
	}

	return report, nil
}

// Adopt records that the database already holds the schema the baseline
// migration would create, so later migrations can be applied to it.
//
// It verifies again while holding the advisory lock, so a database that changed
// between a verification run and this one is still refused. The baseline
// migration's statements are never executed against an adopted database.
func Adopt(ctx context.Context, db *sql.DB) (Report, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("taking a connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", database.AdvisoryLockKey); err != nil {
		return Report{}, fmt.Errorf("taking the adoption lock: %w", err)
	}

	defer func() {
		// Releasing is best effort: closing the connection releases the lock
		// anyway, and failing here must not mask the outcome of the adoption.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", database.AdvisoryLockKey)
	}()

	report, err := Verify(ctx, conn)
	if err != nil {
		return report, err
	}

	if report.Outcome != OutcomeAdoptable {
		return report, nil
	}

	if err := ensureMigrationHistoryTable(ctx, db); err != nil {
		return report, err
	}

	if err := recordBaselineApplied(ctx, conn); err != nil {
		return report, err
	}

	report.Outcome = OutcomeAdopted

	return report, nil
}

var setDialectOnce sync.Once

// ensureMigrationHistoryTable creates this service's migration history table
// through goose itself, so its shape is whatever the version in this binary
// expects rather than a copy that could drift.
func ensureMigrationHistoryTable(ctx context.Context, db *sql.DB) error {
	var dialectErr error

	setDialectOnce.Do(func() {
		dialectErr = goose.SetDialect(string(goose.DialectPostgres))
	})

	if dialectErr != nil {
		return fmt.Errorf("preparing the migration history: %w", dialectErr)
	}

	if _, err := goose.EnsureDBVersionContext(ctx, db); err != nil {
		return fmt.Errorf("creating the migration history: %w", err)
	}

	return nil
}

// recordBaselineApplied marks the baseline migration as applied without running
// it. The insert is conditional and runs in a transaction, so a second attempt
// that reaches this point cannot record it twice.
func recordBaselineApplied(ctx context.Context, conn *sql.Conn) error {
	transaction, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("recording the baseline: %w", err)
	}

	defer func() { _ = transaction.Rollback() }()

	var alreadyRecorded bool

	err = transaction.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM `+database.MigrationHistoryTable+` WHERE version_id = $1)
	`, database.BaselineVersion).Scan(&alreadyRecorded)
	if err != nil {
		return fmt.Errorf("recording the baseline: %w", err)
	}

	if !alreadyRecorded {
		_, err = transaction.ExecContext(ctx, `
			INSERT INTO `+database.MigrationHistoryTable+` (version_id, is_applied) VALUES ($1, TRUE)
		`, database.BaselineVersion)
		if err != nil {
			return fmt.Errorf("recording the baseline: %w", err)
		}
	}

	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("recording the baseline: %w", err)
	}

	return nil
}

func currentMigrationVersion(ctx context.Context, conn database.Conn) (int64, error) {
	var version sql.NullInt64

	err := conn.QueryRowContext(ctx, `
		SELECT max(version_id) FROM `+database.MigrationHistoryTable+` WHERE is_applied
	`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("reading the migration version: %w", err)
	}

	return version.Int64, nil
}

// verifyRecordedMigrations proves the database was built by exactly the
// migrations this service expects, in order, each applied once and completed.
func verifyRecordedMigrations(ctx context.Context, conn database.Conn) (int, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT
			migration_name,
			checksum,
			applied_steps_count,
			finished_at IS NOT NULL,
			rolled_back_at IS NOT NULL
		FROM `+`"`+RecordedHistoryTable+`"`+`
		ORDER BY started_at, migration_name
	`)
	if err != nil {
		return 0, fmt.Errorf("reading the recorded migrations: %w", err)
	}
	defer rows.Close()

	type recordedMigration struct {
		name       string
		checksum   string
		steps      int
		finished   bool
		rolledBack bool
	}

	var recorded []recordedMigration

	for rows.Next() {
		var row recordedMigration

		err := rows.Scan(&row.name, &row.checksum, &row.steps, &row.finished, &row.rolledBack)
		if err != nil {
			return 0, fmt.Errorf("reading the recorded migrations: %w", err)
		}

		recorded = append(recorded, row)
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("reading the recorded migrations: %w", err)
	}

	expected := ExpectedHistory()

	if len(recorded) != len(expected) {
		return len(recorded), fmt.Errorf(
			"%w: found %d records, expected %d",
			ErrHistoryMismatch, len(recorded), len(expected),
		)
	}

	for index, row := range recorded {
		want := expected[index]

		switch {
		case row.name != want.Name:
			return len(recorded), fmt.Errorf(
				"%w: record %d is %q, expected %q",
				ErrHistoryMismatch, index+1, row.name, want.Name,
			)
		case row.checksum != want.Checksum:
			return len(recorded), fmt.Errorf(
				"%w: %q was applied from different statements than this service expects",
				ErrHistoryMismatch, row.name,
			)
		case row.steps != 1:
			return len(recorded), fmt.Errorf(
				"%w: %q records %d applied steps, expected 1",
				ErrHistoryMismatch, row.name, row.steps,
			)
		case !row.finished:
			return len(recorded), fmt.Errorf("%w: %q never finished", ErrHistoryMismatch, row.name)
		case row.rolledBack:
			return len(recorded), fmt.Errorf("%w: %q was rolled back", ErrHistoryMismatch, row.name)
		}
	}

	return len(recorded), nil
}

// findUnsafeCallbackURIs returns the primary keys of registered callbacks the
// current rules would refuse. The URIs themselves are not returned or logged:
// they name the customers using the service.
func findUnsafeCallbackURIs(ctx context.Context, conn database.Conn) ([]int32, error) {
	rows, err := conn.QueryContext(ctx, `SELECT "id", "uri" FROM "CallbackUri" ORDER BY "id"`)
	if err != nil {
		return nil, fmt.Errorf("reading registered callbacks: %w", err)
	}
	defer rows.Close()

	var unsafe []int32

	for rows.Next() {
		var (
			id  int32
			uri string
		)

		if err := rows.Scan(&id, &uri); err != nil {
			return nil, fmt.Errorf("reading registered callbacks: %w", err)
		}

		if _, err := urlpolicy.ParseRegisteredCallbackURI(uri); err != nil {
			unsafe = append(unsafe, id)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading registered callbacks: %w", err)
	}

	return unsafe, nil
}

// hasRecordedHistory reports whether the database carries the migration history
// that records how its schema was built.
func hasRecordedHistory(ctx context.Context, conn database.Conn) (bool, error) {
	var present bool

	err := conn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = $1
		)
	`, RecordedHistoryTable).Scan(&present)
	if err != nil {
		return false, fmt.Errorf("looking for the recorded migration history: %w", err)
	}

	return present, nil
}
