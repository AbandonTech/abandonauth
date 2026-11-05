package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/query"
)

// MaxAccessTokenRevocations is how many unexpired access tokens one person and
// one application may hold revoked at once.
const MaxAccessTokenRevocations = 1000

// Reasons an access token is not honoured or a revocation is not recorded.
var (
	// ErrRevocationCapacity reports that a person and application already hold
	// the most revoked access tokens there is room for, so the token was not
	// recorded as revoked.
	ErrRevocationCapacity = errors.New("the access token revocations for this person and application are full")
	// ErrAccessNotGranted reports that what an access token names no longer
	// stands: its client, its person, their relationship, its authority, or the
	// token itself has been withdrawn.
	ErrAccessNotGranted = errors.New("the access token no longer grants anything")
)

// PublicClientUsers records which people each public client has issued tokens
// to, and the access tokens refused before they expire.
type PublicClientUsers struct {
	pool    *pgxpool.Pool
	queries *query.Queries
}

// NewPublicClientUsers builds the service.
func NewPublicClientUsers(pool *pgxpool.Pool) *PublicClientUsers {
	return &PublicClientUsers{pool: pool, queries: query.New(pool)}
}

// Ensure records, inside the caller's transaction, that a public client issues
// tokens to a person. Two issuances recording the first at once converge on
// one row.
func (p *PublicClientUsers) Ensure(
	ctx context.Context, queries *query.Queries, applicationID, userID uuid.UUID,
) error {
	if err := queries.EnsurePublicClientUser(ctx, query.EnsurePublicClientUserParams{
		ApplicationID: applicationID, UserID: userID,
	}); err != nil {
		return fmt.Errorf("recording a public client's user: %w", err)
	}

	return nil
}

// AccessHolder is who an accepted access token was issued for.
type AccessHolder struct {
	Username string
}

// Holder establishes, under the shared authority lock, that an access token's
// client is still a public client that has issued tokens to the person it
// names, its epoch is current and it has not been revoked.
func (p *PublicClientUsers) Holder(
	ctx context.Context, clientID, userID, tokenID, authEpoch uuid.UUID,
) (AccessHolder, error) {
	resolved, err := p.queries.ResolveAccessTokenGrant(ctx, query.ResolveAccessTokenGrantParams{
		ApplicationID: clientID, UserID: userID, AuthEpoch: authEpoch, Jti: tokenID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessHolder{}, ErrAccessNotGranted
	}

	if err != nil {
		return AccessHolder{}, fmt.Errorf("resolving an access token's holder: %w", err)
	}

	if !resolved.CurrentAuthority || resolved.Revoked {
		return AccessHolder{}, ErrAccessNotGranted
	}

	return AccessHolder{Username: resolved.Username}, nil
}

// AccessRevocation names an access token whose signature and claims were
// already accepted.
type AccessRevocation struct {
	ClientID  uuid.UUID
	UserID    uuid.UUID
	TokenID   uuid.UUID
	ExpiresAt time.Time
}

// RevokeAccessToken records that this service refuses an access token before
// it expires.
//
// The exact person and application are locked first, so their revocations are
// counted and added one at a time across workers. Revoked tokens that have
// since expired are reclaimed before counting. At the ceiling, the token is not
// recorded and ErrRevocationCapacity is returned: the ceiling exists so that a
// holder of valid tokens cannot grow this table without bound, and refusing is
// honest where pretending to have revoked would not be. A person the
// application has no relationship with revokes nothing and is not an error.
func (p *PublicClientUsers) RevokeAccessToken(ctx context.Context, revocation AccessRevocation) error {
	transaction, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := p.queries.WithTx(transaction)

	if _, err := queries.LockAuthEpochShared(ctx); err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	userID, err := queries.LockPublicClientUser(ctx, query.LockPublicClientUserParams{
		ApplicationID: revocation.ClientID, UserID: revocation.UserID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	pair := query.DeleteExpiredAccessTokenRevocationsForPairParams{ApplicationID: revocation.ClientID, UserID: userID}

	if _, err := queries.DeleteExpiredAccessTokenRevocationsForPair(ctx, pair); err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	already, err := queries.AccessTokenRevocationExists(ctx, revocation.TokenID)
	if err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	if already {
		return nil
	}

	held, err := queries.CountAccessTokenRevocationsForPair(ctx, query.CountAccessTokenRevocationsForPairParams(pair))
	if err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	if held >= MaxAccessTokenRevocations {
		return ErrRevocationCapacity
	}

	if _, err := queries.CreateAccessTokenRevocation(ctx, query.CreateAccessTokenRevocationParams{
		Jti:           revocation.TokenID,
		ApplicationID: revocation.ClientID,
		UserID:        userID,
		ExpiresAt:     revocation.ExpiresAt,
	}); err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	return nil
}

// ForgetRevocations removes revocations of access tokens that have since
// expired and are refused on their own.
func (p *PublicClientUsers) ForgetRevocations(ctx context.Context) (int64, error) {
	removed, err := withSharedAuthority(ctx, p.pool, func(queries *query.Queries) (int64, error) {
		return queries.DeleteExpiredAccessTokenRevocations(ctx, maximumCleanupRows)
	})
	if err != nil {
		return 0, fmt.Errorf("removing expired access token revocations: %w", err)
	}

	return removed, nil
}

// withSharedAuthority runs work in a transaction holding the shared authority
// lock, so it can never interleave with a rotation.
func withSharedAuthority(
	ctx context.Context, pool *pgxpool.Pool, work func(*query.Queries) (int64, error),
) (int64, error) {
	transaction, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := query.New(transaction)

	if _, err := queries.LockAuthEpochShared(ctx); err != nil {
		return 0, err
	}

	affected, err := work(queries)
	if err != nil {
		return 0, err
	}

	if err := transaction.Commit(ctx); err != nil {
		return 0, err
	}

	return affected, nil
}
