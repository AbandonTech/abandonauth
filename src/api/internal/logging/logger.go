// Package logging builds the service's logger: where it writes and at what
// level.
//
// It does not filter fields. Callers decide what goes into an event. Request
// logging records method, route, status and duration. It must not record query
// strings, headers, cookies or bodies: those carry credentials.
package logging

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Options select the log destination and how much detail it receives.
type Options struct {
	// Verbose lowers the level from info to debug. It does not widen what any
	// event is allowed to contain.
	Verbose bool

	// Pretty writes human-readable lines instead of JSON. It is for a terminal;
	// a deployment leaves it off so the output can be parsed.
	Pretty bool

	// Output defaults to standard error, which is where a container runtime
	// collects diagnostics from.
	Output io.Writer
}

// New builds the logger the service writes through.
func New(options Options) zerolog.Logger {
	destination := options.Output
	if destination == nil {
		destination = os.Stderr
	}

	if options.Pretty {
		destination = zerolog.ConsoleWriter{Out: destination, TimeFormat: time.RFC3339}
	}

	level := zerolog.InfoLevel
	if options.Verbose {
		level = zerolog.DebugLevel
	}

	return zerolog.New(destination).Level(level).With().Timestamp().Logger()
}
