//go:build integration && !devtools

package testdatabase

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The helpers decide what every database test is run against, so a defect in
// them would quietly weaken the whole suite rather than fail it.

func TestEachTestGetsItsOwnEmptyDatabase(t *testing.T) {
	t.Parallel()

	first := New(t)
	_, firstURL := NewWithURL(t)
	_, secondURL := NewWithURL(t)

	if firstURL == secondURL {
		t.Fatal("two tests were given the same database")
	}

	if tables := publicTables(t, first); tables != 0 {
		t.Errorf("a new empty test database already holds %d tables", tables)
	}
}

func TestMigratedDatabaseIsReadyForAuthority(t *testing.T) {
	t.Parallel()

	pool := NewMigrated(t)

	var epochs int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_epoch`).Scan(&epochs); err != nil {
		t.Fatalf("reading the authority: %v", err)
	}

	if epochs != 1 {
		t.Errorf("auth_epoch holds %d rows, want 1", epochs)
	}
}

// Clones share a template, so a row written into one must not reach another or
// the template every later clone is made from.
func TestMigratedDatabasesAreIsolated(t *testing.T) {
	t.Parallel()

	first, firstURL := NewMigratedWithURL(t)
	second, secondURL := NewMigratedWithURL(t)

	if firstURL == secondURL {
		t.Fatal("two tests were given the same database")
	}

	Execute(t, first, `INSERT INTO "User" (username) VALUES ('isolated')`)

	for name, pool := range map[string]*pgxpool.Pool{
		"another clone":           second,
		"a clone made afterwards": NewMigrated(t),
	} {
		var users int

		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM "User"`).Scan(&users); err != nil {
			t.Fatalf("counting users in %s: %v", name, err)
		}

		if users != 0 {
			t.Errorf("%s holds %d users written elsewhere", name, users)
		}
	}
}

func TestServerURLNamesConfiguredServer(t *testing.T) {
	t.Parallel()

	if ServerURL(t) == "" {
		t.Error("the configured server URL is empty")
	}
}

func TestMissingSettingIsNamedInRefusal(t *testing.T) {
	t.Parallel()

	const absent = "ABANDONAUTH_TEST_SETTING_NEVER_SET"

	value, err := setting(absent)
	if err == nil {
		t.Fatalf("an absent setting was read as %q", value)
	}

	if !strings.Contains(err.Error(), absent) {
		t.Errorf("the refusal does not name the setting: %v", err)
	}
}

func publicTables(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()

	var tables int

	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM pg_tables WHERE schemaname = 'public'`,
	).Scan(&tables); err != nil {
		t.Fatalf("counting tables: %v", err)
	}

	return tables
}
