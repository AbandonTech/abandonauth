package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/buildmode"
	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/adoption"
	"github.com/abandontech/abandonauth/src/api/internal/logging"
	"github.com/abandontech/abandonauth/src/api/internal/web"
)

// service performs the commands against the real database and network.
type service struct{}

// Serve brings the schema up to date and then answers requests until the
// context is cancelled.
func (service) Serve(ctx context.Context, configuration config.Config) error {
	logger := loggerFor(configuration)

	pool, err := database.Open(ctx, configuration.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := migrate(ctx, pool, logger); err != nil {
		return err
	}

	server, err := web.NewServer(configuration, web.Dependencies{Pool: pool, Logger: logger})
	if err != nil {
		return err
	}

	// Fail closed: a declared route with nothing behind it would answer with a
	// surprise instead of its contract.
	if missing := server.MissingHandlers(); len(missing) > 0 {
		return fmt.Errorf("these routes have no handler: %v", missing)
	}

	logger.Info().
		Str("build", buildmode.Name).
		Str("version", version).
		Str("address", configuration.BindAddress).
		Msg("serving")

	return listenUntilStopped(ctx, logger, configuration.BindAddress, server.Handler())
}

// Maintenance answers every request with a temporary failure.
//
// It opens no database connection and reads no setting beyond the address, so a
// deployment whose configuration is the reason it cannot serve can still put
// this in front of its traffic.
func (service) Maintenance(ctx context.Context, address string) error {
	logger := logging.New(logging.Options{})

	logger.Info().
		Str("build", buildmode.Name).
		Str("version", version).
		Str("address", address).
		Msg("serving maintenance responses only")

	return listenUntilStopped(ctx, logger, address, web.MaintenanceHandler())
}

// AdoptExistingSchema takes ownership of a database that already holds the
// account schema without a record of this service having migrated it, or reports
// whether doing so would succeed.
func (service) AdoptExistingSchema(ctx context.Context, configuration config.Config, verifyOnly bool) error {
	logger := loggerFor(configuration)

	pool, err := database.Open(ctx, configuration.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	defer pool.Close()

	handle := database.OpenMigrationHandle(pool)
	defer handle.Close()

	var report adoption.Report

	if verifyOnly {
		report, err = adoption.Verify(ctx, handle)
	} else {
		report, err = adoption.Adopt(ctx, handle)
	}

	reportAdoption(logger, report)

	if err != nil {
		return err
	}

	if verifyOnly && report.Outcome == adoption.OutcomeAdoptable {
		logger.Info().Msg("run the command again without --verify-only to adopt this schema")
	}

	return nil
}

// RotateAuthority withdraws every credential the service has issued.
func (service) RotateAuthority(ctx context.Context, configuration config.Config) error {
	logger := loggerFor(configuration)

	pool, err := database.Open(ctx, configuration.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	defer pool.Close()

	rotation, err := database.RotateAuthority(ctx, pool)
	if err != nil {
		return err
	}

	logger.Info().
		Int64("abandoned_logins", rotation.AbandonedLogins).
		Int64("withdrawn_codes", rotation.AbandonedExchanges).
		Int64("ended_sessions", rotation.EndedSessions).
		Int64("cleared_revocations", rotation.ClearedRevocations).
		Msg("a new authority is in place; every credential issued before it is refused")

	return nil
}

func loggerFor(configuration config.Config) zerolog.Logger {
	return logging.New(logging.Options{
		Verbose: configuration.Verbose,
		Pretty:  configuration.Pretty,
	})
}

func migrate(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger) error {
	handle := database.OpenMigrationHandle(pool)
	defer handle.Close()

	return database.Migrate(ctx, handle, database.NewMigrationLog(logger))
}

func reportAdoption(logger zerolog.Logger, report adoption.Report) {
	if report.Outcome != "" {
		logger.Info().
			Str("outcome", string(report.Outcome)).
			Int("recorded_migrations", report.RecordedMigrations).
			Msg("inspected the database")
	}

	for _, difference := range report.SchemaDifferences {
		logger.Error().Str("difference", difference.String()).Msg("the schema does not match")
	}

	// Identified by primary key rather than by value: a callback URI is a
	// deployment detail of somebody else's application.
	if len(report.UnsafeCallbackURIIDs) > 0 {
		logger.Error().
			Ints32("callback_uri_ids", report.UnsafeCallbackURIIDs).
			Msg("these registered callback URIs are refused by the current rules and must be corrected")
	}
}

// listenUntilStopped serves until the context is cancelled, then stops taking
// new connections and gives the requests already in flight a bounded time to
// finish.
func listenUntilStopped(ctx context.Context, logger zerolog.Logger, address string, handler http.Handler) error {
	server := web.NewHTTPServer(address, handler)

	failed := make(chan error, 1)

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failed <- fmt.Errorf("listening on %s: %w", address, err)

			return
		}

		failed <- nil
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}

	logger.Info().Msg("stopping")

	shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), web.ShutdownGracePeriod)
	defer cancel()

	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("stopping the listener: %w", err)
	}

	return <-failed
}
