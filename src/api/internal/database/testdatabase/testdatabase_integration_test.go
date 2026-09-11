//go:build integration && !devtools

package testdatabase_test

import (
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
)

// The helpers decide what every database test is run against, so a defect in
// them would quietly weaken the whole suite rather than fail it.

func TestEachTestGetsItsOwnEmptyDatabase(t *testing.T) {
	t.Parallel()

	first, firstURL := testdatabase.NewWithURL(t)
	_, secondURL := testdatabase.NewWithURL(t)

	if firstURL == secondURL {
		t.Fatal("two tests were given the same database")
	}

	handle := testdatabase.OpenMigrationHandle(t, first)

	state, err := database.InspectSchema(t.Context(), handle)
	if err != nil {
		t.Fatalf("inspecting the schema: %v", err)
	}

	if !state.IsEmpty() {
		t.Errorf("a new test database already holds %v", state.PresentAccountTables)
	}
}

func TestAMigratedDatabaseIsReadyToUse(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)

	var epochs int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_epoch`).Scan(&epochs); err != nil {
		t.Fatalf("reading the authority: %v", err)
	}

	if epochs != 1 {
		t.Errorf("auth_epoch holds %d rows, want 1", epochs)
	}
}

func TestAnUnrecognisedDatabaseCanBeBuilt(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewUnrecognised(t)
	handle := testdatabase.OpenMigrationHandle(t, pool)

	state, err := database.InspectSchema(t.Context(), handle)
	if err != nil {
		t.Fatalf("inspecting the schema: %v", err)
	}

	if !state.IsComplete() {
		t.Errorf("these tables are missing: %v", state.MissingAccountTables)
	}

	if state.HasMigrationHistory {
		t.Error("a database this service did not build must not already carry its history")
	}
}

func TestServerURLNamesTheConfiguredServer(t *testing.T) {
	t.Parallel()

	if testdatabase.ServerURL(t) == "" {
		t.Error("the configured server URL is empty")
	}
}
