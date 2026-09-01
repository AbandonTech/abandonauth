package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationDirectory is where the statements sit inside the embedded files. The
// runner is handed the directory itself rather than the enclosing filesystem,
// because it looks for migrations at the root of what it is given.
const migrationDirectory = "migrations"

func embeddedMigrations() (fs.FS, error) {
	statements, err := fs.Sub(migrationFiles, migrationDirectory)
	if err != nil {
		return nil, fmt.Errorf("reading embedded migrations: %w", err)
	}

	return statements, nil
}

// BaselineVersion is the migration that creates the account schema.
//
// A database that already holds that schema without having run this version is
// one this service did not build, and start-up refuses it.
const BaselineVersion int64 = 20260827000100

// ErrUnrecognisedSchema reports a database that already holds the account
// schema but has no migration history of its own.
//
// Migrating it blindly would either fail on tables that already exist or, worse,
// succeed against a schema that is subtly different from the one the service
// expects. Neither is something start-up may decide on its own, so it stops and
// leaves the database untouched.
var ErrUnrecognisedSchema = errors.New(
	"the database already holds application tables but no record of this service having migrated them, " +
		"so it will not be migrated",
)

// Migrate applies every migration the database has not yet run.
//
// It is safe to call from every instance at start-up: the session lock means one
// instance migrates and the others wait for it.
func Migrate(ctx context.Context, db *sql.DB, logger goose.Logger) error {
	state, err := InspectSchema(ctx, db)
	if err != nil {
		return err
	}

	if state.IsUnrecognised() {
		return ErrUnrecognisedSchema
	}

	provider, err := newMigrationProvider(db, logger)
	if err != nil {
		return err
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}

	return nil
}

// MigrateTo applies migrations up to and including the given version.
//
// It exists so a test can look at the database as it is immediately after the
// baseline, before the tables the rest of the service depends on are added.
func MigrateTo(ctx context.Context, db *sql.DB, logger goose.Logger, version int64) error {
	provider, err := newMigrationProvider(db, logger)
	if err != nil {
		return err
	}

	if _, err := provider.UpTo(ctx, version); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}

	return nil
}

// Version reports the migration the database has reached.
func Version(ctx context.Context, db *sql.DB, logger goose.Logger) (int64, error) {
	provider, err := newMigrationProvider(db, logger)
	if err != nil {
		return 0, err
	}

	version, err := provider.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("reading the migration version: %w", err)
	}

	return version, nil
}

// MigrationVersions lists the versions carried in the binary, in order.
//
// The version is the numeric prefix of the file name, which is also what the
// runner records, so the list can be read without a database to run against.
func MigrationVersions() ([]int64, error) {
	entries, err := migrationFiles.ReadDir(migrationDirectory)
	if err != nil {
		return nil, fmt.Errorf("reading embedded migrations: %w", err)
	}

	versions := make([]int64, 0, len(entries))

	for _, entry := range entries {
		name := entry.Name()

		prefix, _, separated := strings.Cut(name, "_")
		if !separated {
			return nil, fmt.Errorf("embedded migration %q has no version prefix", name)
		}

		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("embedded migration %q has no version prefix", name)
		}

		versions = append(versions, version)
	}

	slices.Sort(versions)

	return versions, nil
}

func newMigrationProvider(db *sql.DB, logger goose.Logger) (*goose.Provider, error) {
	statements, err := embeddedMigrations()
	if err != nil {
		return nil, err
	}

	sessionLocker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, fmt.Errorf("preparing the migration lock: %w", err)
	}

	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		statements,
		goose.WithSessionLocker(sessionLocker),
		goose.WithLogger(logger),
		// Every migration must be applied in order. Allowing one that was
		// authored earlier to run after a later one would let two deployments
		// reach different schemas from the same set of files.
		goose.WithAllowOutofOrder(false),
	)
	if err != nil {
		return nil, fmt.Errorf("preparing the migration runner: %w", err)
	}

	return provider, nil
}
