//go:build integration

package adoption_test

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/adoption"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
)

func TestANewDatabaseHasNothingToAdopt(t *testing.T) {
	t.Parallel()

	pool := testdatabase.New(t)
	handle := testdatabase.OpenMigrationHandle(t, pool)

	report, err := adoption.Verify(t.Context(), handle)
	if err != nil {
		t.Fatalf("inspecting an empty database: %v", err)
	}

	if report.Outcome != adoption.OutcomeNewDatabase {
		t.Errorf("outcome = %q, want %q", report.Outcome, adoption.OutcomeNewDatabase)
	}
}

func TestAnExistingDatabaseIsAdoptedWithoutTouchingItsRows(t *testing.T) {
	t.Parallel()

	pool := newUnadopted(t, recordedHistory{})
	handle := testdatabase.OpenMigrationHandle(t, pool)

	userID, applicationID := insertAccount(t, pool)

	verified, err := adoption.Verify(t.Context(), handle)
	if err != nil {
		t.Fatalf("verifying an existing database: %v", err)
	}

	if verified.Outcome != adoption.OutcomeAdoptable {
		t.Fatalf("outcome = %q, want %q", verified.Outcome, adoption.OutcomeAdoptable)
	}

	if verified.RecordedMigrations != len(adoption.ExpectedHistory()) {
		t.Errorf("recorded migrations = %d, want %d",
			verified.RecordedMigrations, len(adoption.ExpectedHistory()))
	}

	adopted, err := adoption.Adopt(t.Context(), handle)
	if err != nil {
		t.Fatalf("adopting an existing database: %v", err)
	}

	if adopted.Outcome != adoption.OutcomeAdopted {
		t.Errorf("outcome = %q, want %q", adopted.Outcome, adoption.OutcomeAdopted)
	}

	// Adoption records that the baseline is applied. It must not run it: the
	// tables and the rows in them are already there.
	version, err := database.Version(t.Context(), handle, quietLog{})
	if err != nil {
		t.Fatalf("reading the migration version: %v", err)
	}

	if version != database.BaselineVersion {
		t.Errorf("migration version = %d, want %d", version, database.BaselineVersion)
	}

	assertAccountSurvives(t, pool, userID, applicationID)
}

// The whole point of adoption is that the additive migration can then be applied
// to a database that was built elsewhere.
func TestAnAdoptedDatabaseAcceptsTheRemainingMigrations(t *testing.T) {
	t.Parallel()

	pool := newUnadopted(t, recordedHistory{})
	handle := testdatabase.OpenMigrationHandle(t, pool)

	userID, applicationID := insertAccount(t, pool)

	if _, err := adoption.Adopt(t.Context(), handle); err != nil {
		t.Fatalf("adopting: %v", err)
	}

	if err := database.Migrate(t.Context(), handle, quietLog{}); err != nil {
		t.Fatalf("migrating an adopted database: %v", err)
	}

	assertAccountSurvives(t, pool, userID, applicationID)

	// Applications that existed before the migration must come out at the first
	// credential version, so their tokens validate.
	var credentialVersion int64

	err := pool.QueryRow(t.Context(),
		`SELECT "credential_version" FROM "DeveloperApplication" WHERE "id" = $1`, applicationID,
	).Scan(&credentialVersion)
	if err != nil {
		t.Fatalf("reading the credential version: %v", err)
	}

	if credentialVersion != 1 {
		t.Errorf("credential version = %d, want 1", credentialVersion)
	}

	// The recorded history is not authoritative once this service owns the
	// schema, and leaving it would invite a second adoption.
	var survived bool

	err = pool.QueryRow(t.Context(), `
		SELECT EXISTS (
			SELECT 1 FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		)
	`, adoption.RecordedHistoryTable).Scan(&survived)
	if err != nil {
		t.Fatalf("looking for the recorded history: %v", err)
	}

	if survived {
		t.Error("the recorded history survived the additive migration")
	}
}

func TestAdoptingAnAlreadyAdoptedDatabaseChangesNothing(t *testing.T) {
	t.Parallel()

	pool := newUnadopted(t, recordedHistory{})
	handle := testdatabase.OpenMigrationHandle(t, pool)

	if _, err := adoption.Adopt(t.Context(), handle); err != nil {
		t.Fatalf("adopting: %v", err)
	}

	report, err := adoption.Adopt(t.Context(), handle)
	if err != nil {
		t.Fatalf("adopting twice: %v", err)
	}

	if report.Outcome != adoption.OutcomeAlreadyAdopted {
		t.Errorf("outcome = %q, want %q", report.Outcome, adoption.OutcomeAlreadyAdopted)
	}
}

// Two operators running the command at once must not both create a history.
func TestConcurrentAdoptionIsSerialised(t *testing.T) {
	t.Parallel()

	pool, databaseURL := testdatabase.NewWithURL(t)
	testdatabase.MakeUnadopted(t, pool)
	applyRecordedHistory(t, pool, recordedHistory{})

	const attempts = 4

	var (
		waiting  sync.WaitGroup
		start    = make(chan struct{})
		outcomes = make(chan adoption.Outcome, attempts)
		failures = make(chan error, attempts)
	)

	for range attempts {
		waiting.Add(1)

		go func() {
			defer waiting.Done()

			attemptPool, err := database.Open(t.Context(), databaseURL)
			if err != nil {
				failures <- err

				return
			}
			defer attemptPool.Close()

			handle := database.OpenMigrationHandle(attemptPool)
			defer handle.Close()

			<-start

			report, err := adoption.Adopt(t.Context(), handle)
			if err != nil {
				failures <- err

				return
			}

			outcomes <- report.Outcome
		}()
	}

	close(start)
	waiting.Wait()
	close(outcomes)
	close(failures)

	for err := range failures {
		t.Errorf("a concurrent adoption failed: %v", err)
	}

	adopted := 0

	for outcome := range outcomes {
		switch outcome {
		case adoption.OutcomeAdopted:
			adopted++
		case adoption.OutcomeAlreadyAdopted:
		default:
			t.Errorf("unexpected outcome %q", outcome)
		}
	}

	if adopted != 1 {
		t.Errorf("%d attempts adopted the database, want exactly 1", adopted)
	}
}

func TestARecordedHistoryThatDoesNotMatchBlocksAdoption(t *testing.T) {
	t.Parallel()

	history := adoption.ExpectedHistory()
	last := history[len(history)-1].Name

	tests := []struct {
		name    string
		history recordedHistory
		want    error
	}{
		{
			name:    "no history at all",
			history: recordedHistory{omit: true},
			want:    adoption.ErrHistoryMissing,
		},
		{
			name:    "a history table with nothing in it",
			history: recordedHistory{omitRows: true},
			want:    adoption.ErrHistoryMismatch,
		},
		{
			name:    "statements that were edited after they were applied",
			history: recordedHistory{changeChecksumOf: history[0].Name},
			want:    adoption.ErrHistoryMismatch,
		},
		{
			name:    "a migration recorded twice",
			history: recordedHistory{duplicateLast: true},
			want:    adoption.ErrHistoryMismatch,
		},
		{
			name:    "a migration that recorded no applied steps",
			history: recordedHistory{appliedStepsOf: last, appliedSteps: 0},
			want:    adoption.ErrHistoryMismatch,
		},
		{
			name:    "a migration that recorded more steps than it has",
			history: recordedHistory{appliedStepsOf: last, appliedSteps: 2},
			want:    adoption.ErrHistoryMismatch,
		},
		{
			name:    "a migration that never finished",
			history: recordedHistory{unfinishedLast: true},
			want:    adoption.ErrHistoryMismatch,
		},
		{
			name:    "a migration that was reversed",
			history: recordedHistory{rolledBackLast: true},
			want:    adoption.ErrHistoryMismatch,
		},
		{
			name:    "a migration this service has never heard of",
			history: recordedHistory{addUnknown: "20260101000000_added_elsewhere"},
			want:    adoption.ErrHistoryMismatch,
		},
		{
			name:    "one migration fewer than the schema needs",
			history: recordedHistory{dropLast: true},
			want:    adoption.ErrHistoryMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pool := newUnadopted(t, test.history)
			handle := testdatabase.OpenMigrationHandle(t, pool)

			_, err := adoption.Verify(t.Context(), handle)
			if !errors.Is(err, test.want) {
				t.Fatalf("verification returned %v, want %v", err, test.want)
			}

			state, stateErr := database.InspectSchema(t.Context(), handle)
			if stateErr != nil {
				t.Fatalf("inspecting the schema: %v", stateErr)
			}

			if state.HasMigrationHistory {
				t.Error("a refused verification created a migration history")
			}

			// Adoption must reach the same conclusion, since it verifies again
			// while holding the lock.
			if _, err := adoption.Adopt(t.Context(), handle); !errors.Is(err, test.want) {
				t.Errorf("adoption returned %v, want %v", err, test.want)
			}
		})
	}
}

func TestASchemaThatDoesNotMatchBlocksAdoption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		statement string
	}{
		{name: "a missing column", statement: `ALTER TABLE "DeveloperApplication" DROP COLUMN "name"`},
		{name: "an added column", statement: `ALTER TABLE "User" ADD COLUMN "email" TEXT`},
		{name: "a widened column", statement: `ALTER TABLE "GitHubAccount" ALTER COLUMN "id" TYPE BIGINT`},
		{
			name:      "a dropped cascade",
			statement: `ALTER TABLE "CallbackUri" DROP CONSTRAINT "CallbackUri_developer_application_id_fkey"`,
		},
		{name: "a missing table", statement: `DROP TABLE "PasswordAccount"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pool := newUnadopted(t, recordedHistory{})
			handle := testdatabase.OpenMigrationHandle(t, pool)

			if _, err := pool.Exec(t.Context(), test.statement); err != nil {
				t.Fatalf("altering the schema: %v", err)
			}

			report, err := adoption.Verify(t.Context(), handle)
			if !errors.Is(err, adoption.ErrSchemaMismatch) {
				t.Fatalf("verification returned %v, want ErrSchemaMismatch", err)
			}

			if len(report.SchemaDifferences) == 0 && !strings.Contains(err.Error(), "missing") {
				t.Error("the refusal does not say how the schema differs")
			}
		})
	}
}

// A recorded history without the tables it describes is a database somebody
// has emptied. It is not a new database and must not be treated as one.
func TestAHistoryWithoutItsTablesIsRefused(t *testing.T) {
	t.Parallel()

	pool := testdatabase.New(t)
	handle := testdatabase.OpenMigrationHandle(t, pool)

	testdatabase.MakeUnadopted(t, pool)
	applyRecordedHistory(t, pool, recordedHistory{})

	for _, table := range []string{
		"CallbackUri", "DeveloperApplication", "DiscordAccount",
		"GitHubAccount", "GoogleAccount", "PasswordAccount", "User",
	} {
		if _, err := pool.Exec(t.Context(), `DROP TABLE "`+table+`" CASCADE`); err != nil {
			t.Fatalf("dropping %s: %v", table, err)
		}
	}

	_, err := adoption.Verify(t.Context(), handle)
	if !errors.Is(err, adoption.ErrSchemaMismatch) {
		t.Fatalf("verification returned %v, want ErrSchemaMismatch", err)
	}
}

// A database that this service has started to migrate, but that has not reached
// the baseline, is in a state no procedure here knows how to complete.
func TestAPartialHistoryOfThisServiceIsRefused(t *testing.T) {
	t.Parallel()

	pool := newUnadopted(t, recordedHistory{})
	handle := testdatabase.OpenMigrationHandle(t, pool)

	_, err := pool.Exec(t.Context(), `
		CREATE TABLE goose_db_version (
			id SERIAL PRIMARY KEY,
			version_id BIGINT NOT NULL,
			is_applied BOOLEAN NOT NULL,
			tstamp TIMESTAMP NOT NULL DEFAULT now()
		);
		INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, true);
	`)
	if err != nil {
		t.Fatalf("creating a partial history: %v", err)
	}

	if _, err := adoption.Verify(t.Context(), handle); !errors.Is(err, adoption.ErrPartialMigrationHistory) {
		t.Fatalf("verification returned %v, want ErrPartialMigrationHistory", err)
	}
}

// A registered callback the current rules refuse would send a browser somewhere
// this service will not send it. Adoption stops until an operator corrects it.
func TestUnsafeRegisteredCallbacksBlockAdoption(t *testing.T) {
	t.Parallel()

	pool := newUnadopted(t, recordedHistory{})
	handle := testdatabase.OpenMigrationHandle(t, pool)

	_, applicationID := insertAccount(t, pool)

	const unsafeCallback = "javascript:alert(1)"

	var callbackID int32

	err := pool.QueryRow(t.Context(),
		`INSERT INTO "CallbackUri" ("developer_application_id", "uri") VALUES ($1, $2) RETURNING "id"`,
		applicationID, unsafeCallback,
	).Scan(&callbackID)
	if err != nil {
		t.Fatalf("registering a callback: %v", err)
	}

	report, err := adoption.Verify(t.Context(), handle)
	if !errors.Is(err, adoption.ErrUnsafeCallbackURIs) {
		t.Fatalf("verification returned %v, want ErrUnsafeCallbackURIs", err)
	}

	if len(report.UnsafeCallbackURIIDs) != 1 || report.UnsafeCallbackURIIDs[0] != callbackID {
		t.Errorf("reported rows = %v, want [%d]", report.UnsafeCallbackURIIDs, callbackID)
	}

	// The URI names somebody else's deployment. The operator gets the primary
	// key to look the row up with, never the value.
	if strings.Contains(err.Error(), unsafeCallback) {
		t.Errorf("the refusal repeats the registered URI: %v", err)
	}
}

func TestASafeRegisteredCallbackDoesNotBlockAdoption(t *testing.T) {
	t.Parallel()

	pool := newUnadopted(t, recordedHistory{})
	handle := testdatabase.OpenMigrationHandle(t, pool)

	_, applicationID := insertAccount(t, pool)

	for _, callback := range []string{
		"https://application.example.test/callback",
		"https://application.example.test/callback?tenant=one",
		"http://localhost:3000/callback",
		"http://127.0.0.1:3000/callback",
	} {
		_, err := pool.Exec(t.Context(),
			`INSERT INTO "CallbackUri" ("developer_application_id", "uri") VALUES ($1, $2)`,
			applicationID, callback,
		)
		if err != nil {
			t.Fatalf("registering %s: %v", callback, err)
		}
	}

	report, err := adoption.Verify(t.Context(), handle)
	if err != nil {
		t.Fatalf("verification refused safe callbacks: %v", err)
	}

	if report.Outcome != adoption.OutcomeAdoptable {
		t.Errorf("outcome = %q, want %q", report.Outcome, adoption.OutcomeAdoptable)
	}
}

func insertAccount(t *testing.T, pool *pgxpool.Pool) (userID, applicationID uuid.UUID) {
	t.Helper()

	err := pool.QueryRow(t.Context(),
		`INSERT INTO "User" ("username") VALUES ('ada') RETURNING "id"`,
	).Scan(&userID)
	if err != nil {
		t.Fatalf("creating a user: %v", err)
	}

	err = pool.QueryRow(t.Context(), `
		INSERT INTO "DeveloperApplication" ("owner_id", "refresh_token", "name")
		VALUES ($1, $2, 'an application')
		RETURNING "id"
	`, userID, "$2b$12$placeholderplaceholderplaceholderplaceholderplaceholder00").Scan(&applicationID)
	if err != nil {
		t.Fatalf("creating a developer application: %v", err)
	}

	return userID, applicationID
}

func assertAccountSurvives(t *testing.T, pool *pgxpool.Pool, userID, applicationID uuid.UUID) {
	t.Helper()

	var username string

	if err := pool.QueryRow(t.Context(), `SELECT "username" FROM "User" WHERE "id" = $1`, userID).Scan(&username); err != nil {
		t.Fatalf("reading the user back: %v", err)
	}

	if username != "ada" {
		t.Errorf("username = %q, want ada", username)
	}

	var owner uuid.UUID

	err := pool.QueryRow(t.Context(),
		`SELECT "owner_id" FROM "DeveloperApplication" WHERE "id" = $1`, applicationID,
	).Scan(&owner)
	if err != nil {
		t.Fatalf("reading the application back: %v", err)
	}

	if owner != userID {
		t.Errorf("owner = %v, want %v", owner, userID)
	}
}

type quietLog struct{}

func (quietLog) Printf(string, ...any) {}
func (quietLog) Fatalf(string, ...any) {}
