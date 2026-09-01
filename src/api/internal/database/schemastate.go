package database

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// ErrUnrecognisedSchema reports a database that already holds the account schema
// without both this service's migration history and the marker its baseline
// writes.
//
// Migrating it blindly would either fail on tables that already exist or, worse,
// succeed against a schema that is subtly different from the one the service
// expects. Neither is something start-up may decide on its own, so it stops and
// leaves the database untouched.
var ErrUnrecognisedSchema = errors.New(
	"the database already holds application tables but no record of this service having migrated them, " +
		"so it will not be migrated",
)

// ErrIncompleteAccountSchema reports a database holding only part of the account
// schema, which is not a state any migration this service carries produces.
var ErrIncompleteAccountSchema = errors.New(
	"the database holds only some of the application tables, so it will not be migrated",
)

// ErrUnsupportedMigrationHistory reports a history this service could not have
// written by running its own migrations in order, so what the schema actually
// is cannot be established from it.
var ErrUnsupportedMigrationHistory = errors.New(
	"the database's migration history is not one this service wrote, so it will not be migrated",
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

// SchemaIdentityTable is the marker the baseline migration writes to claim the
// schema it built.
const SchemaIdentityTable = "schema_identity"

// initialHistoryVersion is the placeholder row the migration runner writes when
// it creates its history table. It records no migration of this service's own.
const initialHistoryVersion int64 = 0

// SchemaState is what a database looks like before anything is done to it.
type SchemaState struct {
	// PresentAccountTables are the account tables that already exist.
	PresentAccountTables []string
	// MissingAccountTables are the ones that do not.
	MissingAccountTables []string
	// HasMigrationHistory reports whether this service has already recorded
	// migrations against this database.
	HasMigrationHistory bool
	// AppliedVersions are the migrations the history records as complete, in
	// ascending order and without duplicates.
	AppliedVersions []int64
	// HasIncompleteRecord reports a history entry for a migration that did not
	// finish, which leaves the schema somewhere between two known versions.
	HasIncompleteRecord bool
	// HistoryUnreadable reports a history table this service cannot read, so
	// what it records cannot be established.
	HistoryUnreadable bool
	// ClaimedBaselineVersion is the baseline the schema marker claims built this
	// database, or zero when the marker is absent, empty or duplicated.
	ClaimedBaselineVersion int64
}

// IsEmpty reports a database with none of the account tables.
func (s SchemaState) IsEmpty() bool {
	return len(s.PresentAccountTables) == 0
}

// IsComplete reports a database that holds every account table.
func (s SchemaState) IsComplete() bool {
	return len(s.MissingAccountTables) == 0
}

// supported reports whether start-up may run migrations against this state.
//
// Three states are accepted: a database nothing has touched, one the baseline
// built and no more, and one already at a version this binary carries. Every
// other state is refused with the database left exactly as it was found, because
// a schema this service did not build is one it cannot reason about.
func (s SchemaState) supported(known []int64) error {
	if s.HistoryUnreadable || s.HasIncompleteRecord {
		return ErrUnsupportedMigrationHistory
	}

	if s.IsEmpty() {
		if s.HasMigrationHistory || s.ClaimedBaselineVersion != 0 {
			return ErrUnsupportedMigrationHistory
		}

		return nil
	}

	if !s.IsComplete() {
		return ErrIncompleteAccountSchema
	}

	if !s.HasMigrationHistory || s.ClaimedBaselineVersion != BaselineVersion {
		return ErrUnrecognisedSchema
	}

	// What was applied must be the start of what this binary carries. A gap, a
	// version it does not know, and one ahead of it all mean the schema in front
	// of it is not the schema these migrations build.
	if len(s.AppliedVersions) == 0 || len(s.AppliedVersions) > len(known) {
		return ErrUnsupportedMigrationHistory
	}

	if !slices.Equal(s.AppliedVersions, known[:len(s.AppliedVersions)]) {
		return ErrUnsupportedMigrationHistory
	}

	return nil
}

// InspectSchema reports the tables this service cares about, what the migration
// history records, and which baseline the schema marker claims.
func InspectSchema(ctx context.Context, conn Conn) (SchemaState, error) {
	present, err := listTables(ctx, conn)
	if err != nil {
		return SchemaState{}, err
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

	if state.HasMigrationHistory {
		readHistory(ctx, conn, &state)
	}

	if present[SchemaIdentityTable] {
		state.ClaimedBaselineVersion = readClaimedBaseline(ctx, conn)
	}

	return state, nil
}

func listTables(ctx context.Context, conn Conn) (map[string]bool, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r'
	`)
	if err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}
	defer rows.Close()

	present := make(map[string]bool)

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("listing tables: %w", err)
		}

		present[name] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}

	return present, nil
}

// readHistory fills in what the history table records. A table this service
// cannot read is reported as unreadable rather than as an error, because the
// caller's answer to both is the same refusal and neither may name a value.
func readHistory(ctx context.Context, conn Conn, state *SchemaState) {
	rows, err := conn.QueryContext(
		ctx,
		`SELECT version_id, is_applied FROM `+MigrationHistoryTable+` ORDER BY version_id`,
	)
	if err != nil {
		state.HistoryUnreadable = true

		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			version int64
			applied bool
		)

		if err := rows.Scan(&version, &applied); err != nil {
			state.HistoryUnreadable = true

			return
		}

		switch {
		case version == initialHistoryVersion:
		case !applied:
			state.HasIncompleteRecord = true
		default:
			state.AppliedVersions = append(state.AppliedVersions, version)
		}
	}

	if err := rows.Err(); err != nil {
		state.HistoryUnreadable = true

		return
	}

	slices.Sort(state.AppliedVersions)
	state.AppliedVersions = slices.Compact(state.AppliedVersions)
}

// readClaimedBaseline returns the baseline the marker claims. Anything other
// than exactly one row is reported as no claim at all, which start-up refuses.
func readClaimedBaseline(ctx context.Context, conn Conn) int64 {
	rows, err := conn.QueryContext(ctx, `SELECT baseline_version FROM `+SchemaIdentityTable)
	if err != nil {
		return 0
	}
	defer rows.Close()

	var claimed []int64

	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return 0
		}

		claimed = append(claimed, version)
	}

	if err := rows.Err(); err != nil || len(claimed) != 1 {
		return 0
	}

	return claimed[0]
}
