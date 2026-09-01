//go:build integration

package database_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
)

// A database the baseline built, and nothing more, is the state a start-up that
// was interrupted between the two migrations leaves behind. It is migrated the
// rest of the way rather than refused.
func TestStartUpFinishesADatabaseTheBaselineBuilt(t *testing.T) {
	t.Parallel()

	pool := testdatabase.New(t)
	handle := testdatabase.OpenMigrationHandle(t, pool)

	if err := database.MigrateTo(
		t.Context(), handle, quietLog{}, database.BaselineVersion,
	); err != nil {
		t.Fatalf("applying the baseline: %v", err)
	}

	if err := database.Migrate(t.Context(), handle, quietLog{}); err != nil {
		t.Fatalf("finishing the migrations: %v", err)
	}

	versions, err := database.MigrationVersions()
	if err != nil {
		t.Fatalf("listing migrations: %v", err)
	}

	version, err := database.Version(t.Context(), handle, quietLog{})
	if err != nil {
		t.Fatalf("reading the migration version: %v", err)
	}

	if want := slices.Max(versions); version != want {
		t.Errorf("migration version = %d, want %d", version, want)
	}
}

// Every refusal must leave the database exactly as it was found. An operator
// whose start-up was refused still has the database they had before it.
func TestStartUpRefusesStatesItDidNotBuildWithoutChangingThem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(*testing.T, *pgxpool.Pool)
		want  error
	}{
		{
			name:  "application tables with no history and no marker",
			build: testdatabase.MakeUnrecognised,
			want:  database.ErrUnrecognisedSchema,
		},
		{
			name: "a history stamped over application tables the baseline did not build",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Migrate(t, pool)
				testdatabase.Execute(t, pool, "DROP TABLE "+database.SchemaIdentityTable)
			},
			want: database.ErrUnrecognisedSchema,
		},
		{
			name: "a marker claiming a baseline this binary does not carry",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Migrate(t, pool)
				testdatabase.Execute(t, pool, `
					ALTER TABLE schema_identity
						DROP CONSTRAINT schema_identity_baseline_version;
					UPDATE schema_identity SET baseline_version = 1;
				`)
			},
			want: database.ErrUnrecognisedSchema,
		},
		{
			name: "only some of the application tables",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Migrate(t, pool)
				testdatabase.Execute(t, pool, `DROP TABLE "GoogleAccount"`)
			},
			want: database.ErrIncompleteAccountSchema,
		},
		{
			name: "a history missing the baseline it must start from",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Migrate(t, pool)
				testdatabase.Execute(
					t, pool,
					"DELETE FROM "+database.MigrationHistoryTable+" WHERE version_id = $1",
					database.BaselineVersion,
				)
			},
			want: database.ErrUnsupportedMigrationHistory,
		},
		{
			name: "a history ahead of the migrations this binary carries",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Migrate(t, pool)
				testdatabase.Execute(
					t, pool,
					"INSERT INTO "+database.MigrationHistoryTable+
						" (version_id, is_applied) VALUES (99999999999999, TRUE)",
				)
			},
			want: database.ErrUnsupportedMigrationHistory,
		},
		{
			name: "a migration recorded as having not completed",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Migrate(t, pool)
				testdatabase.Execute(
					t, pool,
					"INSERT INTO "+database.MigrationHistoryTable+
						" (version_id, is_applied) VALUES (20260827000300, FALSE)",
				)
			},
			want: database.ErrUnsupportedMigrationHistory,
		},
		{
			name: "a history table this service cannot read",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Migrate(t, pool)
				testdatabase.Execute(t, pool,
					"DROP TABLE "+database.MigrationHistoryTable+";"+
						"CREATE TABLE "+database.MigrationHistoryTable+" (recorded TEXT NOT NULL)",
				)
			},
			want: database.ErrUnsupportedMigrationHistory,
		},
		{
			name: "a history against a schema that is not there",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Execute(t, pool,
					"CREATE TABLE "+database.MigrationHistoryTable+
						" (id SERIAL PRIMARY KEY, version_id BIGINT NOT NULL,"+
						" is_applied BOOLEAN NOT NULL, tstamp TIMESTAMP NOT NULL DEFAULT now())",
				)
			},
			want: database.ErrUnsupportedMigrationHistory,
		},
		{
			name: "a marker for a schema that is not there",
			build: func(t *testing.T, pool *pgxpool.Pool) {
				testdatabase.Execute(t, pool,
					"CREATE TABLE "+database.SchemaIdentityTable+" (baseline_version BIGINT NOT NULL)",
				)
				testdatabase.Execute(t, pool,
					"INSERT INTO "+database.SchemaIdentityTable+" (baseline_version) VALUES ($1)",
					database.BaselineVersion,
				)
			},
			want: database.ErrUnsupportedMigrationHistory,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pool := testdatabase.New(t)
			test.build(t, pool)

			before := contents(t, pool)

			handle := testdatabase.OpenMigrationHandle(t, pool)

			err := database.Migrate(t.Context(), handle, quietLog{})
			if !errors.Is(err, test.want) {
				t.Fatalf("migrating returned %v, want %v", err, test.want)
			}

			// The refusal is read by an operator whose start-up failed, so it
			// says the database was left alone rather than half migrated.
			if got := err.Error(); !strings.Contains(got, "will not be migrated") {
				t.Errorf("the refusal does not say what it did: %s", got)
			}

			if after := contents(t, pool); after != before {
				t.Errorf("the refused database changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

// The marker is what tells a start-up that these migrations built the schema in
// front of it, so a second row claiming a different baseline must be impossible
// to write rather than merely unexpected.
func TestTheSchemaMarkerAcceptsOnlyItsOwnSingleRow(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)

	statements := []string{
		`INSERT INTO schema_identity (singleton, baseline_version) VALUES (FALSE, 20260827000100)`,
		`INSERT INTO schema_identity (baseline_version) VALUES (20260827000100)`,
		`UPDATE schema_identity SET baseline_version = 1`,
	}

	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement); err == nil {
			t.Errorf("the database accepted %q", statement)
		}
	}
}

// Migrations own the tables they create and nothing else. A database this
// service is pointed at may hold records another system wrote, and deleting
// them is never this service's decision.
func TestMigrationsLeaveTablesTheyDoNotOwnAlone(t *testing.T) {
	t.Parallel()

	pool := testdatabase.New(t)

	unrelated := []string{"_prisma_migrations", "deployment_audit"}

	for _, table := range unrelated {
		testdatabase.Execute(t, pool, fmt.Sprintf(
			`CREATE TABLE %q (recorded TEXT NOT NULL); INSERT INTO %q (recorded) VALUES ('kept')`,
			table, table,
		))
	}

	testdatabase.Migrate(t, pool)

	for _, table := range unrelated {
		var recorded string

		query := fmt.Sprintf(`SELECT recorded FROM %q`, table)
		if err := pool.QueryRow(t.Context(), query).Scan(&recorded); err != nil {
			t.Errorf("reading %s after migrating: %v", table, err)

			continue
		}

		if recorded != "kept" {
			t.Errorf("%s holds %q, want \"kept\"", table, recorded)
		}
	}
}

// contents renders everything a refusal must not change: which tables exist, how
// many rows each holds, and what the migration history records.
func contents(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()

	var recorded strings.Builder

	for _, table := range tableNames(t, pool) {
		var count int64

		query := fmt.Sprintf(`SELECT count(*) FROM %q`, table)
		if err := pool.QueryRow(t.Context(), query).Scan(&count); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}

		fmt.Fprintf(&recorded, "%s %d\n", table, count)

		if table == database.MigrationHistoryTable {
			recorded.WriteString(historyRecords(t, pool))
		}
	}

	return recorded.String()
}

func tableNames(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()

	rows, err := pool.Query(t.Context(), `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r'
		ORDER BY c.relname
	`)
	if err != nil {
		t.Fatalf("listing tables: %v", err)
	}
	defer rows.Close()

	var names []string

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("listing tables: %v", err)
		}

		names = append(names, name)
	}

	if err := rows.Err(); err != nil {
		t.Fatalf("listing tables: %v", err)
	}

	return names
}

// historyRecords is read through a query that a deliberately unreadable history
// table fails, which is itself part of what must not change across a refusal.
func historyRecords(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()

	rows, err := pool.Query(
		t.Context(),
		`SELECT version_id, is_applied FROM `+database.MigrationHistoryTable+` ORDER BY version_id`,
	)
	if err != nil {
		return "  unreadable\n"
	}
	defer rows.Close()

	var recorded strings.Builder

	for rows.Next() {
		var (
			version int64
			applied bool
		)

		if err := rows.Scan(&version, &applied); err != nil {
			return "  unreadable\n"
		}

		fmt.Fprintf(&recorded, "  %d %t\n", version, applied)
	}

	if err := rows.Err(); err != nil {
		t.Fatalf("reading the migration history: %v", err)
	}

	return recorded.String()
}
