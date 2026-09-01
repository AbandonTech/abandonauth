//go:build integration

package database_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
)

func TestMigratingAFreshDatabaseReachesTheNewestVersion(t *testing.T) {
	t.Parallel()

	pool := testdatabase.New(t)
	handle := testdatabase.OpenMigrationHandle(t, pool)

	if err := database.Migrate(t.Context(), handle, quietLog{}); err != nil {
		t.Fatalf("applying migrations: %v", err)
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

// Every instance runs the migrations at start-up, so the second and later
// callers must find nothing to do rather than fail.
func TestApplyingMigrationsTwiceSucceeds(t *testing.T) {
	t.Parallel()

	pool := testdatabase.New(t)
	handle := testdatabase.OpenMigrationHandle(t, pool)

	if err := database.Migrate(t.Context(), handle, quietLog{}); err != nil {
		t.Fatalf("applying migrations: %v", err)
	}

	if err := database.Migrate(t.Context(), handle, quietLog{}); err != nil {
		t.Errorf("applying migrations a second time: %v", err)
	}
}

// Two instances start at once in a deployment. One migrates and the other waits
// for it; neither may apply a migration the other is already applying.
func TestConcurrentMigrationsAreSerialised(t *testing.T) {
	t.Parallel()

	_, databaseURL := testdatabase.NewWithURL(t)

	const instances = 4

	var (
		waiting sync.WaitGroup
		start   = make(chan struct{})
		results = make(chan error, instances)
	)

	for range instances {
		waiting.Add(1)

		go func() {
			defer waiting.Done()

			pool, err := database.Open(t.Context(), databaseURL)
			if err != nil {
				results <- err

				return
			}
			defer pool.Close()

			handle := database.OpenMigrationHandle(pool)
			defer handle.Close()

			<-start

			results <- database.Migrate(t.Context(), handle, quietLog{})
		}()
	}

	close(start)
	waiting.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Errorf("a concurrent start-up failed to migrate: %v", err)
		}
	}
}

func TestOpenProvesTheConnectionWorks(t *testing.T) {
	t.Parallel()

	_, databaseURL := testdatabase.NewWithURL(t)

	pool, err := database.Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatalf("opening the pool: %v", err)
	}

	if err := pool.Ping(t.Context()); err != nil {
		t.Errorf("the pool did not answer: %v", err)
	}

	// Closing releases the connections; a second close would panic, so the
	// lifecycle is proven once here rather than deferred.
	pool.Close()
}

func TestOpenRefusesAConnectionStringItCannotUse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		databaseURL string
	}{
		{name: "not a connection string", databaseURL: "://"},
		{name: "a scheme the driver does not speak", databaseURL: "mysql://host/db"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pool, err := database.Open(t.Context(), test.databaseURL)
			if err == nil {
				pool.Close()
				t.Fatal("an unusable connection string was accepted")
			}

			// The connection string holds the database password, so nothing
			// about it may appear in the error.
			if !errors.Is(err, database.ErrUnusableDatabaseURL) {
				t.Errorf("error = %v, want ErrUnusableDatabaseURL", err)
			}
		})
	}
}

func TestOpenFailsWhenTheServerDoesNotAnswer(t *testing.T) {
	t.Parallel()

	// Port 1 on the loopback interface has nothing listening on it.
	pool, err := database.Open(t.Context(), "postgres://placeholder:placeholder@127.0.0.1:1/abandonauth")
	if err == nil {
		pool.Close()
		t.Fatal("connecting to a server that is not there succeeded")
	}
}

func TestOpenStopsWhenItsContextIsCancelled(t *testing.T) {
	t.Parallel()

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	pool, err := database.Open(cancelled, testdatabase.ServerURL(t))
	if err == nil {
		pool.Close()
		t.Fatal("connecting with a cancelled context succeeded")
	}
}

type quietLog struct{}

func (quietLog) Printf(string, ...any) {}
func (quietLog) Fatalf(string, ...any) {}
