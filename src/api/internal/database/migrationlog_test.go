package database_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/database"
)

// recorded runs one call against a migration log and returns the single event
// it wrote.
func recorded(t *testing.T, write func(database.MigrationLog)) map[string]any {
	t.Helper()

	var written bytes.Buffer

	write(database.NewMigrationLog(zerolog.New(&written)))

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(written.Bytes()), &event); err != nil {
		t.Fatalf("the migration log wrote something that is not one event: %v (%q)", err, written.String())
	}

	return event
}

// The runner formats its own messages and ends them with a newline. A log that
// kept it would write a blank line into the middle of the service's output.
func TestTheMigrationLogWritesOneLineWithoutTheRunnersNewline(t *testing.T) {
	t.Parallel()

	event := recorded(t, func(log database.MigrationLog) {
		log.Printf("applied %s in %d ms\n", "20260827000100_baseline_schema.sql", 12)
	})

	message, _ := event["message"].(string)

	if want := "applied 20260827000100_baseline_schema.sql in 12 ms"; message != want {
		t.Errorf("message = %q, want %q", message, want)
	}

	if strings.ContainsAny(message, "\r\n") {
		t.Error("the message carried the runner's line ending into the log")
	}

	if level, _ := event["level"].(string); level != "info" {
		t.Errorf("level = %q, want info", level)
	}
}

// The log is attributed, so migration output can be told apart from a request.
func TestTheMigrationLogSaysWhatWroteIt(t *testing.T) {
	t.Parallel()

	event := recorded(t, func(log database.MigrationLog) { log.Printf("anything") })

	if component, _ := event["component"].(string); component != "migrations" {
		t.Errorf("component = %q, want migrations", component)
	}
}

// The runner calls this for a condition it considers fatal. It must record the
// condition and return: exiting here would skip the release of the migration
// lock, leaving the next start-up waiting on a lock nothing holds.
func TestAFatalMigrationConditionIsRecordedAndDoesNotExit(t *testing.T) {
	t.Parallel()

	event := recorded(t, func(log database.MigrationLog) {
		log.Fatalf("cannot open %s\n\n", "the schema")
	})

	if message, _ := event["message"].(string); message != "cannot open the schema" {
		t.Errorf("message = %q, want %q", message, "cannot open the schema")
	}

	if level, _ := event["level"].(string); level != "error" {
		t.Errorf("level = %q, want error", level)
	}
}
