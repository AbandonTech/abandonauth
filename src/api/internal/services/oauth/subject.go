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
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
)

// subjectAttempts bounds how often a fresh subject is drawn when the one drawn
// is already another person's at the same application. Thirty-two random bytes
// colliding even once is not expected; a third collision means the generator
// is broken, and issuance fails rather than continuing with it.
const subjectAttempts = 3

// MaxAccessTokenRevocations is how many unexpired access tokens one person and
// one application may hold revoked at once.
const MaxAccessTokenRevocations = 1000

// Reasons a subject or a revocation cannot be produced.
var (
	// ErrSubjectUnavailable reports that no unused subject could be drawn.
	ErrSubjectUnavailable = errors.New("no unused pairwise subject could be drawn")
	// ErrRevocationCapacity reports that a person and application already hold
	// the most revoked access tokens there is room for, so the token was not
	// recorded as revoked.
	ErrRevocationCapacity = errors.New("the access token revocations for this person and application are full")
	// ErrAccessNotGranted reports that what an access token names no longer
	// stands: its client, its person, its subject, its authority, or the token
	// itself has been withdrawn.
	ErrAccessNotGranted = errors.New("the access token no longer grants anything")
)

// PairwiseSubjects holds the identifier each application knows each person by,
// and the access tokens refused before they expire.
type PairwiseSubjects struct {
	pool       *pgxpool.Pool
	queries    *query.Queries
	newSubject func() (string, error)
}

// NewPairwiseSubjects builds the service. A nil generator draws subjects from
// the system's random source; only a test supplies one, to force collisions.
func NewPairwiseSubjects(pool *pgxpool.Pool, generate func() (string, error)) *PairwiseSubjects {
	if generate == nil {
		generate = credentials.NewOpaqueValue
	}

	return &PairwiseSubjects{pool: pool, queries: query.New(pool), newSubject: generate}
}

// Resolve returns the subject an application knows a person by, creating it
// inside the caller's transaction when there is none.
//
// Two sign-ins creating the first subject at once both end with the one that
// committed first, and a drawn subject another person already holds at the
// application is never assigned twice.
func (p *PairwiseSubjects) Resolve(
	ctx context.Context, queries *query.Queries, applicationID, userID uuid.UUID,
) (string, error) {
	existing, err := queries.GetPairwiseSubject(ctx, query.GetPairwiseSubjectParams{
		ApplicationID: applicationID, UserID: userID,
	})
	if err == nil {
		return existing, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("reading a pairwise subject: %w", err)
	}

	for range subjectAttempts {
		drawn, err := p.newSubject()
		if err != nil {
			return "", err
		}

		if !credentials.IsOpaqueValue(drawn) {
			return "", ErrSubjectUnavailable
		}

		created, err := queries.CreatePairwiseSubject(ctx, query.CreatePairwiseSubjectParams{
			ApplicationID: applicationID, UserID: userID, Subject: drawn,
		})
		if err != nil {
			return "", fmt.Errorf("recording a pairwise subject: %w", err)
		}

		if created == 1 {
			return drawn, nil
		}

		existing, err := queries.GetPairwiseSubject(ctx, query.GetPairwiseSubjectParams{
			ApplicationID: applicationID, UserID: userID,
		})
		if err == nil {
			return existing, nil
		}

		if !errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("reading a pairwise subject: %w", err)
		}
	}

	return "", ErrSubjectUnavailable
}

// AccessHolder is who an accepted access token was issued for.
type AccessHolder struct {
	Username string
}

// Holder establishes, under the shared authority lock, that an access token's
// client is still a public client, its subject still names a person, its epoch
// is current and it has not been revoked.
func (p *PairwiseSubjects) Holder(
	ctx context.Context, clientID uuid.UUID, subject string, tokenID, authEpoch uuid.UUID,
) (AccessHolder, error) {
	resolved, err := p.queries.ResolveAccessTokenGrant(ctx, query.ResolveAccessTokenGrantParams{
		ApplicationID: clientID, Subject: subject, AuthEpoch: authEpoch, Jti: tokenID,
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
	Subject   string
	TokenID   uuid.UUID
	ExpiresAt time.Time
}

// RevokeAccessToken records that this service refuses an access token before
// it expires.
//
// The person and application are locked first, so their revocations are
// counted and added one at a time across workers. Revoked tokens that have
// since expired are reclaimed before counting. At the ceiling, the token is not
// recorded and ErrRevocationCapacity is returned: the ceiling exists so that a
// holder of valid tokens cannot grow this table without bound, and refusing is
// honest where pretending to have revoked would not be. A subject this service
// no longer knows revokes nothing and is not an error.
func (p *PairwiseSubjects) RevokeAccessToken(ctx context.Context, revocation AccessRevocation) error {
	transaction, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := p.queries.WithTx(transaction)

	if _, err := queries.LockAuthEpochShared(ctx); err != nil {
		return fmt.Errorf("revoking an access token: %w", err)
	}

	userID, err := queries.LockPairwiseSubjectBySubject(ctx, query.LockPairwiseSubjectBySubjectParams{
		ApplicationID: revocation.ClientID, Subject: revocation.Subject,
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
func (p *PairwiseSubjects) ForgetRevocations(ctx context.Context) (int64, error) {
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
