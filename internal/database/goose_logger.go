package database

import (
	"strings"

	zerolog "github.com/rs/zerolog"
)

type LoggerAdapter struct {
	zerolog.Logger
}

func (s LoggerAdapter) Fatalf(format string, v ...interface{}) {
	s.Logger.Error().Msgf(strings.TrimSuffix(format, "\n"), v...)
}
func (s LoggerAdapter) Printf(format string, v ...interface{}) {
	s.Logger.Info().Msgf(strings.TrimSuffix(format, "\n"), v...)
}
