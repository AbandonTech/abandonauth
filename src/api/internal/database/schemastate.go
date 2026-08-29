package database

import (
	"context"
	"fmt"
	"slices"
)

// accountTables are the tables that hold accounts, applications and callbacks.
// Their presence is what distinguishes a database that has been in use from an
// empty one.
var accountTables = []string{
	"CallbackUri",
	"DeveloperApplication",
	"DiscordAccount",
	"GitHubAccount",
	"GoogleAccount",
	"PasswordAccount",
	"User",
}

// MigrationHistoryTable is where this service records the migrations it applied.
const MigrationHistoryTable = "goose_db_version"

// SchemaState is what a database looks like before anything is done to it.
type SchemaState struct {
	// PresentAccountTables are the account tables that already exist.
	PresentAccountTables []string
	// MissingAccountTables are the ones that do not.
	MissingAccountTables []string
	// HasMigrationHistory reports whether this service has already recorded
	// migrations against this database.
	HasMigrationHistory bool
}

// IsEmpty reports a database with none of the account tables.
func (s SchemaState) IsEmpty() bool {
	return len(s.PresentAccountTables) == 0
}

// IsComplete reports a database that holds every account table.
func (s SchemaState) IsComplete() bool {
	return len(s.MissingAccountTables) == 0
}

// NeedsAdoption reports a database that already holds account data but has no
// migration history of its own, so migrations must not simply be run against it.
func (s SchemaState) NeedsAdoption() bool {
	return !s.IsEmpty() && !s.HasMigrationHistory
}

// InspectSchema reports which of the tables this service cares about exist.
func InspectSchema(ctx context.Context, conn Conn) (SchemaState, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r'
	`)
	if err != nil {
		return SchemaState{}, fmt.Errorf("listing tables: %w", err)
	}
	defer rows.Close()

	present := make(map[string]bool)

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return SchemaState{}, fmt.Errorf("listing tables: %w", err)
		}

		present[name] = true
	}

	if err := rows.Err(); err != nil {
		return SchemaState{}, fmt.Errorf("listing tables: %w", err)
	}

	state := SchemaState{HasMigrationHistory: present[MigrationHistoryTable]}

	for _, table := range accountTables {
		if present[table] {
			state.PresentAccountTables = append(state.PresentAccountTables, table)
		} else {
			state.MissingAccountTables = append(state.MissingAccountTables, table)
		}
	}

	slices.Sort(state.PresentAccountTables)
	slices.Sort(state.MissingAccountTables)

	return state, nil
}
