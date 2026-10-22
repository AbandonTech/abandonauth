//go:build integration && !devtools

package database_test

import (
	"context"
	"errors"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
)

func TestOpenProvesConnectionWorks(t *testing.T) {
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

func TestOpenRefusesConnectionStringItCannotUse(t *testing.T) {
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

func TestOpenFailsWhenServerDoesNotAnswer(t *testing.T) {
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
