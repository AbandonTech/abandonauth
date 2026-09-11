package database

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database/query"
)

// AuthorityRotation counts what a rotation withdrew. It carries counts only.
// The epoch and the credential values are not in it, so they cannot reach an
// operator's terminal or the deployment log.
type AuthorityRotation struct {
	AbandonedLogins    int64
	AbandonedExchanges int64
	EndedSessions      int64
	ClearedRevocations int64
}

// RotateAuthority replaces the value stamped into every credential this service
// issues, so that all of them stop validating at once.
//
// Deleting the outstanding credentials and installing the new value happen in
// one transaction, under AdvisoryLockKey. On commit, nothing issued earlier is
// accepted. On rollback, everything issued earlier still works. There is no
// state where a token validates but the login that produced it is gone.
//
// It runs during a maintenance window: every signed-in browser has to sign in
// again, and every login in progress has to be restarted.
func RotateAuthority(ctx context.Context, pool *pgxpool.Pool) (AuthorityRotation, error) {
	transaction, err := pool.Begin(ctx)
	if err != nil {
		return AuthorityRotation{}, fmt.Errorf("starting the rotation: %w", err)
	}

	defer func() {
		// Rolling back after a commit is a no-op, so this only takes effect on
		// the paths that return early.
		_ = transaction.Rollback(context.WithoutCancel(ctx))
	}()

	if err := takeRotationLock(ctx, transaction); err != nil {
		return AuthorityRotation{}, err
	}

	rotation, err := withdrawOutstandingCredentials(ctx, query.New(transaction))
	if err != nil {
		return AuthorityRotation{}, err
	}

	if err := transaction.Commit(ctx); err != nil {
		return AuthorityRotation{}, fmt.Errorf("committing the rotation: %w", err)
	}

	return rotation, nil
}

// takeRotationLock serialises rotation against migration and against another
// operator running the same command, both of which decide what the database
// considers authoritative.
func takeRotationLock(ctx context.Context, transaction pgx.Tx) error {
	if _, err := transaction.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", AdvisoryLockKey); err != nil {
		return fmt.Errorf("taking the rotation lock: %w", err)
	}

	return nil
}

func withdrawOutstandingCredentials(ctx context.Context, queries *query.Queries) (AuthorityRotation, error) {
	var (
		rotation AuthorityRotation
		err      error
	)

	if rotation.AbandonedLogins, err = queries.DeleteAllAuthorizationState(ctx); err != nil {
		return AuthorityRotation{}, fmt.Errorf("abandoning logins in progress: %w", err)
	}

	if rotation.AbandonedExchanges, err = queries.DeleteAllExchangeCodes(ctx); err != nil {
		return AuthorityRotation{}, fmt.Errorf("withdrawing one-time codes: %w", err)
	}

	if rotation.EndedSessions, err = queries.DeleteAllBrowserSessions(ctx); err != nil {
		return AuthorityRotation{}, fmt.Errorf("ending browser sessions: %w", err)
	}

	// Every token a revocation could refuse is refused by the new epoch, so the
	// records are cleared rather than left to expire.
	if rotation.ClearedRevocations, err = queries.DeleteAllRevocations(ctx); err != nil {
		return AuthorityRotation{}, fmt.Errorf("clearing withdrawn tokens: %w", err)
	}

	epoch, err := uuid.NewRandom()
	if err != nil {
		return AuthorityRotation{}, fmt.Errorf("generating the new authority: %w", err)
	}

	if _, err := queries.RotateAuthEpoch(ctx, epoch); err != nil {
		return AuthorityRotation{}, fmt.Errorf("installing the new authority: %w", err)
	}

	return rotation, nil
}
