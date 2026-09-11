package logging_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/logging"
)

func TestNewWritesJSONWithATimestamp(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	logger := logging.New(logging.Options{Output: &output})
	logger.Info().Str("route", "current-user").Msg("served")

	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("output is not JSON: %v (%q)", err, output.String())
	}

	for _, field := range []string{"time", "level", "message", "route"} {
		if _, present := event[field]; !present {
			t.Errorf("event has no %q field: %v", field, event)
		}
	}
}

func TestNewDropsDebugEventsUnlessVerbose(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		verbose bool
		want    bool
	}{
		{name: "default level hides debug", verbose: false, want: false},
		{name: "verbose shows debug", verbose: true, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer

			logger := logging.New(logging.Options{Verbose: test.verbose, Output: &output})
			logger.Debug().Msg("consuming authorization state")

			if got := output.Len() > 0; got != test.want {
				t.Errorf("debug event written = %t, want %t", got, test.want)
			}
		})
	}
}

func TestNewPrettyWritesReadableLines(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	logger := logging.New(logging.Options{Pretty: true, Output: &output})
	logger.Info().Msg("listening")

	if !strings.Contains(output.String(), "listening") {
		t.Errorf("pretty output does not carry the message: %q", output.String())
	}

	if json.Valid(output.Bytes()) {
		t.Errorf("pretty output is still JSON: %q", output.String())
	}
}
