package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/buildmode"
	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/logging"
	"github.com/abandontech/abandonauth/src/api/internal/services/housekeeping"
	"github.com/abandontech/abandonauth/src/api/internal/services/siteapplication"
	"github.com/abandontech/abandonauth/src/api/internal/web"
)

// service performs the commands against the real database and network.
type service struct{}

// Serve answers requests until the context is cancelled. It never changes the
// schema; the deployment migrates the database before starting it.
func (service) Serve(ctx context.Context, configuration config.Config) error {
	logger := loggerFor(configuration)

	pool, err := database.Open(ctx, configuration.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	defer pool.Close()

	server, err := web.NewServer(configuration, web.Dependencies{
		Pool:   pool,
		Logger: logger,
	})
	if err != nil {
		return err
	}

	// Fail closed: a declared route with nothing behind it would answer with a
	// surprise instead of its contract.
	if missing := server.MissingHandlers(); len(missing) > 0 {
		return fmt.Errorf("these routes have no handler: %v", missing)
	}

	keeper, err := housekeeping.New(server.ExpiredRecordSweeps(), housekeeping.Options{Logger: logger})
	if err != nil {
		return err
	}

	listener, err := listen(configuration.BindAddress)
	if err != nil {
		return err
	}

	// The sweeps run for exactly as long as requests are answered: they start
	// once the listener is open, and stop however serving ends, including an
	// ending the parent context knows nothing about.
	run, stop := context.WithCancel(ctx)

	swept := make(chan struct{})

	go func() {
		defer close(swept)

		keeper.Run(run)
	}()

	logger.Info().
		Str("build", buildmode.Name).
		Str("version", version).
		Str("address", listener.Addr().String()).
		Msg("serving")

	err = serveUntilStopped(run, logger, listener, server.Handler())

	stop()
	<-swept

	return err
}

// Maintenance answers every request with a temporary failure.
//
// It opens no database connection and reads no setting beyond the address, so a
// deployment whose configuration is the reason it cannot serve can still put
// this in front of its traffic.
func (service) Maintenance(ctx context.Context, address string) error {
	logger := logging.New(logging.Options{})

	listener, err := listen(address)
	if err != nil {
		return err
	}

	logger.Info().
		Str("build", buildmode.Name).
		Str("version", version).
		Str("address", listener.Addr().String()).
		Msg("serving maintenance responses only")

	return serveUntilStopped(ctx, logger, listener, web.MaintenanceHandler())
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

// Provision creates the site's application on a migrated database unless its
// identifier is already in use. It reports what it did and nothing else: the
// application's credential is never returned.
func (service) Provision(
	ctx context.Context, databaseURL config.Secret, applicationID uuid.UUID, callback string,
) (siteapplication.Outcome, error) {
	pool, err := database.Open(ctx, databaseURL.Reveal())
	if err != nil {
		return 0, err
	}
	defer pool.Close()

	return siteapplication.Provision(ctx, pool, applicationID, callback)
}

func loggerFor(configuration config.Config) zerolog.Logger {
	return logging.New(logging.Options{
		Verbose: configuration.Verbose,
		Pretty:  configuration.Pretty,
	})
}

// listen opens the address before anything is served on it, so an address that
// cannot be bound is reported at once rather than from a goroutine racing the
// caller's cancellation.
func listen(address string) (net.Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", address, err)
	}

	return listener, nil
}

// serveUntilStopped answers requests on an open listener until the context is
// cancelled, then stops taking new connections and gives the requests already
// in flight a bounded time to finish. It closes the listener however it ends.
func serveUntilStopped(
	ctx context.Context, logger zerolog.Logger, listener net.Listener, handler http.Handler,
) error {
	server := web.NewHTTPServer(listener.Addr().String(), handler)

	ended := make(chan error, 1)

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			ended <- fmt.Errorf("serving on %s: %w", listener.Addr(), err)

			return
		}

		ended <- nil
	}()

	select {
	case err := <-ended:
		return err
	case <-ctx.Done():
	}

	logger.Info().Msg("stopping")

	shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), web.ShutdownGracePeriod)
	defer cancel()

	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("stopping the listener: %w", err)
	}

	return <-ended
}
