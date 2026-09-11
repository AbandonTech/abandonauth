package database

import (
	"fmt"

	"github.com/rs/zerolog"
)

// MigrationLog adapts the service logger to the migration runner's interface.
//
// The runner prints migration names and versions, never a value from a table, so
// its output is safe at info level.
type MigrationLog struct {
	logger zerolog.Logger
}

// NewMigrationLog returns a migration log that writes through the given logger.
func NewMigrationLog(logger zerolog.Logger) MigrationLog {
	return MigrationLog{logger: logger.With().Str("component", "migrations").Logger()}
}

// Printf records the runner's progress.
func (l MigrationLog) Printf(format string, arguments ...any) {
	l.logger.Info().Msg(trimmed(format, arguments...))
}

// Fatalf records a condition the runner considers fatal.
//
// It does not exit. The runner returns the error as well, and the caller decides
// whether start-up continues. Exiting here would skip the deferred release of
// the migration lock.
func (l MigrationLog) Fatalf(format string, arguments ...any) {
	l.logger.Error().Msg(trimmed(format, arguments...))
}

func trimmed(format string, arguments ...any) string {
	message := fmt.Sprintf(format, arguments...)

	for len(message) > 0 && (message[len(message)-1] == '\n' || message[len(message)-1] == '\r') {
		message = message[:len(message)-1]
	}

	return message
}
