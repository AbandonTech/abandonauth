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
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
)

// Fixed bounds of a public client's authorization. They are protocol
// constants, not settings.
const (
	// NativeAuthorizationLifetime is how long an authorization, its page, its
	// browser binding and everything it leads to may last, measured from its
	// creation and never extended.
	NativeAuthorizationLifetime = 5 * time.Minute
	// NativeAuthorizationCapacity is how many authorizations may be in progress
	// across the whole service at once.
	NativeAuthorizationCapacity = 10000
	// nativeCapacityReclaimRows is enough to reclaim every expired
	// authorization the capacity can hold, in one statement.
	nativeCapacityReclaimRows = NativeAuthorizationCapacity
)

// Reasons an authorization request is refused.
var (
	// ErrNoSuchAuthorization reports that no authorization matches what was
	// presented: unknown, expired, already spent, from another browser, or
	// begun under an authority that has since been rotated.
	ErrNoSuchAuthorization = errors.New("no authorization in progress matches this request")
	// ErrAuthorizationCapacity reports that the service already holds as many
	// authorizations in progress as it permits.
	ErrAuthorizationCapacity = errors.New("too many authorizations are in progress")
)

// AuthorizationRequests holds public clients' authorizations from the moment a
// client opens the browser until its code is redeemed or the authorization
// ends. Each one occupies one of a fixed number of slots for its whole life.
type AuthorizationRequests struct {
	pool    *pgxpool.Pool
	queries *query.Queries
	logins  *Store
}

// NewAuthorizationRequests builds the service over the connection pool and the
// store provider sign-ins are recorded in.
func NewAuthorizationRequests(pool *pgxpool.Pool, logins *Store) *AuthorizationRequests {
	return &AuthorizationRequests{pool: pool, queries: query.New(pool), logins: logins}
}

// AuthorizationRequest is a public client's validated authorization request.
type AuthorizationRequest struct {
	ApplicationID uuid.UUID

	// RedirectURI is the exact redirect, port included, already proven to be one
	// of the client's registered templates.
	RedirectURI string

	Scopes        oidc.Scopes
	ClientState   string
	ClientNonce   string
	CodeChallenge string

	// HeldBinding is a syntactically valid binding the browser already carries,
	// reused so its other authorizations keep working; empty for a new one.
	HeldBinding string
}

// Begun is what the browser carries away from a new authorization.
type Begun struct {
	PageHandle     string
	BrowserBinding string
}

// PendingAuthorization is everything the authorization page may show.
type PendingAuthorization struct {
	ApplicationName string
	Scopes          oidc.Scopes
	ExpiresAt       time.Time
}

// ClientReturn is where a public client is returned and the state it is
// returned with, both as stored when the authorization began.
type ClientReturn struct {
	RedirectURI string
	ClientState string
}

// Begin records an authorization in one of the service's fixed slots.
//
// The slot count is serialised by a lock, expired authorizations are reclaimed
// before counting, and at capacity nothing is written. The authorization
// records the current authority, so a rotation ends it.
func (a *AuthorizationRequests) Begin(ctx context.Context, request AuthorizationRequest) (Begun, error) {
	handle, err := credentials.NewOpaqueValue()
	if err != nil {
		return Begun{}, err
	}

	binding := request.HeldBinding
	if !credentials.IsOpaqueValue(binding) {
		if binding, err = credentials.NewOpaqueValue(); err != nil {
			return Begun{}, err
		}
	}

	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return Begun{}, fmt.Errorf("beginning an authorization: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	epoch, err := queries.LockAuthEpochShared(ctx)
	if err != nil {
		return Begun{}, fmt.Errorf("beginning an authorization: %w", err)
	}

	if _, err := queries.LockNativeAuthorizationCapacity(ctx); err != nil {
		return Begun{}, fmt.Errorf("beginning an authorization: %w", err)
	}

	if _, err := queries.DeleteExpiredNativeAuthorizations(ctx, nativeCapacityReclaimRows); err != nil {
		return Begun{}, fmt.Errorf("beginning an authorization: %w", err)
	}

	held, err := queries.CountNativeAuthorizations(ctx)
	if err != nil {
		return Begun{}, fmt.Errorf("beginning an authorization: %w", err)
	}

	if held >= NativeAuthorizationCapacity {
		return Begun{}, ErrAuthorizationCapacity
	}

	if _, err := queries.CreateNativeAuthorization(ctx, query.CreateNativeAuthorizationParams{
		ApplicationID:      request.ApplicationID,
		BrowserBindingHash: credentials.Digest(credentials.DomainNativeBrowserBinding, binding),
		RedirectUri:        request.RedirectURI,
		Scopes:             request.Scopes.String(),
		ClientState:        request.ClientState,
		ClientNonce:        request.ClientNonce,
		CodeChallenge:      request.CodeChallenge,
		PageHandleHash:     credentials.Digest(credentials.DomainAuthorizationPage, handle),
		AuthEpoch:          epoch,
	}); err != nil {
		return Begun{}, fmt.Errorf("beginning an authorization: %w", err)
	}

	if err := transaction.Commit(ctx); err != nil {
		return Begun{}, fmt.Errorf("beginning an authorization: %w", err)
	}

	return Begun{PageHandle: handle, BrowserBinding: binding}, nil
}

// View returns what the page may show for an authorization still waiting for
// a choice in the browser that began it. Reading it changes nothing.
func (a *AuthorizationRequests) View(ctx context.Context, handle, binding string) (PendingAuthorization, error) {
	if !credentials.IsOpaqueValue(handle) || !credentials.IsOpaqueValue(binding) {
		return PendingAuthorization{}, ErrNoSuchAuthorization
	}

	pending, err := a.queries.GetPendingNativeAuthorization(ctx, query.GetPendingNativeAuthorizationParams{
		PageHandleHash:     credentials.Digest(credentials.DomainAuthorizationPage, handle),
		BrowserBindingHash: credentials.Digest(credentials.DomainNativeBrowserBinding, binding),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingAuthorization{}, ErrNoSuchAuthorization
	}

	if err != nil {
		return PendingAuthorization{}, fmt.Errorf("reading an authorization: %w", err)
	}

	scopes, err := oidc.ParseScopes(pending.Scopes)
	if err != nil {
		return PendingAuthorization{}, fmt.Errorf("reading an authorization: %w", err)
	}

	return PendingAuthorization{
		ApplicationName: pending.ApplicationName,
		Scopes:          scopes,
		ExpiresAt:       pending.ExpiresAt,
	}, nil
}

// BeginProvider spends an authorization's page on a provider and records the
// provider sign-in that continues it, in one transaction. Of a choice and a
// cancellation for one authorization, exactly one finds it.
func (a *AuthorizationRequests) BeginProvider(
	ctx context.Context, handle, binding string, provider Provider,
) (Start, error) {
	if !credentials.IsOpaqueValue(handle) || !credentials.IsOpaqueValue(binding) {
		return Start{}, ErrNoSuchAuthorization
	}

	if _, known := ParseProvider(string(provider)); !known {
		return Start{}, ErrNoSuchAuthorization
	}

	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return Start{}, fmt.Errorf("choosing a provider: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	epoch, err := queries.LockAuthEpochShared(ctx)
	if err != nil {
		return Start{}, fmt.Errorf("choosing a provider: %w", err)
	}

	advanced, err := queries.AdvanceNativeAuthorizationToProvider(ctx, query.AdvanceNativeAuthorizationToProviderParams{
		PageHandleHash:     credentials.Digest(credentials.DomainAuthorizationPage, handle),
		BrowserBindingHash: credentials.Digest(credentials.DomainNativeBrowserBinding, binding),
		AuthEpoch:          epoch,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Start{}, ErrNoSuchAuthorization
	}

	if err != nil {
		return Start{}, fmt.Errorf("choosing a provider: %w", err)
	}

	started, err := a.logins.beginNative(ctx, queries, provider, advanced.ID, binding)
	if err != nil {
		return Start{}, err
	}

	if err := transaction.Commit(ctx); err != nil {
		return Start{}, fmt.Errorf("choosing a provider: %w", err)
	}

	return started, nil
}

// Cancel ends an authorization still waiting for a choice and returns where its
// client is told so.
func (a *AuthorizationRequests) Cancel(ctx context.Context, handle, binding string) (ClientReturn, error) {
	if !credentials.IsOpaqueValue(handle) || !credentials.IsOpaqueValue(binding) {
		return ClientReturn{}, ErrNoSuchAuthorization
	}

	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return ClientReturn{}, fmt.Errorf("cancelling an authorization: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	epoch, err := queries.LockAuthEpochShared(ctx)
	if err != nil {
		return ClientReturn{}, fmt.Errorf("cancelling an authorization: %w", err)
	}

	cancelled, err := queries.CancelNativeAuthorization(ctx, query.CancelNativeAuthorizationParams{
		PageHandleHash:     credentials.Digest(credentials.DomainAuthorizationPage, handle),
		BrowserBindingHash: credentials.Digest(credentials.DomainNativeBrowserBinding, binding),
		AuthEpoch:          epoch,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ClientReturn{}, ErrNoSuchAuthorization
	}

	if err != nil {
		return ClientReturn{}, fmt.Errorf("cancelling an authorization: %w", err)
	}

	if err := transaction.Commit(ctx); err != nil {
		return ClientReturn{}, fmt.Errorf("cancelling an authorization: %w", err)
	}

	return ClientReturn{RedirectURI: cancelled.RedirectUri, ClientState: cancelled.ClientState}, nil
}

// ConsumeProvider spends the provider sign-in a callback presents when it
// continues a public client's authorization in the browser that began it.
// ErrNoSuchLogin means the callback is not one, and the caller may then try it
// as a confidential application's login.
func (a *AuthorizationRequests) ConsumeProvider(
	ctx context.Context, provider Provider, state, binding string,
) (Login, error) {
	return a.logins.consumeNative(ctx, provider, state, binding)
}

// CompleteProvider ends an authorization whose provider sign-in finished.
//
// With a user, the authorization's code is issued in the same transaction that
// advances it, under the shared authority lock, and only while the
// authorization still waits and its client is still public: a rotation that
// committed first leaves nothing to advance, and one that waits deletes the
// code with the authorization. Without a user, the provider refused, and the
// authorization is ended.
func (a *AuthorizationRequests) CompleteProvider(
	ctx context.Context, continuation NativeContinuation, userID uuid.UUID,
) (string, error) {
	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("completing an authorization: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	epoch, err := queries.LockAuthEpochShared(ctx)
	if err != nil {
		return "", fmt.Errorf("completing an authorization: %w", err)
	}

	if _, err := queries.LockNativeAuthorizationAwaitingProvider(ctx, query.LockNativeAuthorizationAwaitingProviderParams{
		ID: continuation.AuthorizationID, AuthEpoch: epoch,
	}); errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoSuchAuthorization
	} else if err != nil {
		return "", fmt.Errorf("completing an authorization: %w", err)
	}

	if userID == uuid.Nil {
		if _, err := queries.DeleteNativeAuthorization(ctx, continuation.AuthorizationID); err != nil {
			return "", fmt.Errorf("ending an authorization: %w", err)
		}

		if err := transaction.Commit(ctx); err != nil {
			return "", fmt.Errorf("ending an authorization: %w", err)
		}

		return "", nil
	}

	code, err := credentials.NewOpaqueValue()
	if err != nil {
		return "", err
	}

	created, err := queries.CreateNativeAuthorizationCode(ctx, query.CreateNativeAuthorizationCodeParams{
		CodeHash:        credentials.Digest(credentials.DomainNativeAuthorizationCode, code),
		UserID:          userID,
		AuthorizationID: continuation.AuthorizationID,
	})
	if err != nil {
		return "", fmt.Errorf("issuing an authorization code: %w", err)
	}

	advanced, err := queries.MarkNativeAuthorizationCodeIssued(ctx, continuation.AuthorizationID)
	if err != nil {
		return "", fmt.Errorf("issuing an authorization code: %w", err)
	}

	// The authorization is locked above, so both rows are there to change.
	if created != 1 || advanced != 1 {
		return "", ErrNoSuchAuthorization
	}

	if err := transaction.Commit(ctx); err != nil {
		return "", fmt.Errorf("issuing an authorization code: %w", err)
	}

	return code, nil
}

// Forget removes authorizations that expired, with everything that continued
// them, releasing their slots.
func (a *AuthorizationRequests) Forget(ctx context.Context) (int64, error) {
	removed, err := withSharedAuthority(ctx, a.pool, func(queries *query.Queries) (int64, error) {
		if _, err := queries.LockNativeAuthorizationCapacity(ctx); err != nil {
			return 0, err
		}

		return queries.DeleteExpiredNativeAuthorizations(ctx, maximumCleanupRows)
	})
	if err != nil {
		return 0, fmt.Errorf("removing expired authorizations: %w", err)
	}

	return removed, nil
}
