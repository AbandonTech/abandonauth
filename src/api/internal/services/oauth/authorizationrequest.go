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

// ProviderSelection is everything the provider selection page may show.
type ProviderSelection struct {
	ApplicationName string
	ExpiresAt       time.Time
}

// PendingConsent is everything the consent screen may show.
type PendingConsent struct {
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
func (a *AuthorizationRequests) View(ctx context.Context, handle, binding string) (ProviderSelection, error) {
	if !credentials.IsOpaqueValue(handle) || !credentials.IsOpaqueValue(binding) {
		return ProviderSelection{}, ErrNoSuchAuthorization
	}

	selection, err := a.queries.GetNativeAuthorizationProviderSelection(ctx, query.GetNativeAuthorizationProviderSelectionParams{
		PageHandleHash:     credentials.Digest(credentials.DomainAuthorizationPage, handle),
		BrowserBindingHash: credentials.Digest(credentials.DomainNativeBrowserBinding, binding),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderSelection{}, ErrNoSuchAuthorization
	}

	if err != nil {
		return ProviderSelection{}, fmt.Errorf("reading an authorization: %w", err)
	}

	return ProviderSelection{ApplicationName: selection.ApplicationName, ExpiresAt: selection.ExpiresAt}, nil
}

// BeginProvider spends an authorization's page on a provider and records the
// provider sign-in that continues it, in one transaction. Of two choices for
// one authorization, exactly one finds it.
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

// ConsumeProvider spends the provider sign-in a callback presents when it
// continues a public client's authorization in the browser that began it.
// ErrNoSuchLogin means the callback is not one, and the caller may then try it
// as a confidential application's login.
func (a *AuthorizationRequests) ConsumeProvider(
	ctx context.Context, provider Provider, state, binding string,
) (Login, error) {
	return a.logins.consumeNative(ctx, provider, state, binding)
}

// BeginConsent moves an authorization whose provider authenticated a person to
// the stage where that person decides, and returns the fresh handle that alone
// can read or answer it.
//
// The move happens under the shared authority lock and only while the
// authorization still waits and its client is still public: a rotation that
// committed first leaves nothing to advance, and one that waits deletes the
// consent with the authorization. It creates no code and no grant.
func (a *AuthorizationRequests) BeginConsent(
	ctx context.Context, continuation NativeContinuation, userID uuid.UUID,
) (string, error) {
	handle, err := credentials.NewOpaqueValue()
	if err != nil {
		return "", err
	}

	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("beginning a consent: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	if err := lockAwaitingProvider(ctx, queries, continuation); err != nil {
		return "", err
	}

	advanced, err := queries.AdvanceNativeAuthorizationToConsent(ctx, query.AdvanceNativeAuthorizationToConsentParams{
		ID:                continuation.AuthorizationID,
		ConsentHandleHash: credentials.Digest(credentials.DomainAuthorizationConsent, handle),
		ConsentUserID:     &userID,
	})
	if err != nil {
		return "", fmt.Errorf("beginning a consent: %w", err)
	}

	// The authorization is locked above, so its row is there to change.
	if advanced != 1 {
		return "", ErrNoSuchAuthorization
	}

	if err := transaction.Commit(ctx); err != nil {
		return "", fmt.Errorf("beginning a consent: %w", err)
	}

	return handle, nil
}

// EndProvider ends an authorization whose provider did not authenticate a
// person, or whose sign-in could not be completed, before any consent exists.
func (a *AuthorizationRequests) EndProvider(ctx context.Context, continuation NativeContinuation) error {
	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ending an authorization: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	if err := lockAwaitingProvider(ctx, queries, continuation); err != nil {
		return err
	}

	if _, err := queries.DeleteNativeAuthorization(ctx, continuation.AuthorizationID); err != nil {
		return fmt.Errorf("ending an authorization: %w", err)
	}

	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("ending an authorization: %w", err)
	}

	return nil
}

// lockAwaitingProvider takes the shared authority lock and then the row of an
// authorization still waiting for its provider under the current authority.
func lockAwaitingProvider(ctx context.Context, queries *query.Queries, continuation NativeContinuation) error {
	epoch, err := queries.LockAuthEpochShared(ctx)
	if err != nil {
		return fmt.Errorf("continuing an authorization: %w", err)
	}

	if _, err := queries.LockNativeAuthorizationAwaitingProvider(ctx, query.LockNativeAuthorizationAwaitingProviderParams{
		ID: continuation.AuthorizationID, AuthEpoch: epoch,
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrNoSuchAuthorization
	} else if err != nil {
		return fmt.Errorf("continuing an authorization: %w", err)
	}

	return nil
}

// ViewConsent returns what the consent screen may show for an authorization
// waiting for the person's answer in the browser that began it. Reading it
// changes nothing.
func (a *AuthorizationRequests) ViewConsent(ctx context.Context, handle, binding string) (PendingConsent, error) {
	if !credentials.IsOpaqueValue(handle) || !credentials.IsOpaqueValue(binding) {
		return PendingConsent{}, ErrNoSuchAuthorization
	}

	pending, err := a.queries.GetNativeAuthorizationConsent(ctx, query.GetNativeAuthorizationConsentParams{
		ConsentHandleHash:  credentials.Digest(credentials.DomainAuthorizationConsent, handle),
		BrowserBindingHash: credentials.Digest(credentials.DomainNativeBrowserBinding, binding),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingConsent{}, ErrNoSuchAuthorization
	}

	if err != nil {
		return PendingConsent{}, fmt.Errorf("reading a consent: %w", err)
	}

	scopes, err := oidc.ParseScopes(pending.Scopes)
	if err != nil {
		return PendingConsent{}, fmt.Errorf("reading a consent: %w", err)
	}

	return PendingConsent{
		ApplicationName: pending.ApplicationName,
		Scopes:          scopes,
		ExpiresAt:       pending.ExpiresAt,
	}, nil
}

// AllowConsent issues the authorization's code on the person's approval, moving
// the person and authentication time the consent recorded onto the code in one
// transaction. It returns where the client receives the code, and the code.
func (a *AuthorizationRequests) AllowConsent(
	ctx context.Context, handle, binding string,
) (ClientReturn, string, error) {
	if !credentials.IsOpaqueValue(handle) || !credentials.IsOpaqueValue(binding) {
		return ClientReturn{}, "", ErrNoSuchAuthorization
	}

	code, err := credentials.NewOpaqueValue()
	if err != nil {
		return ClientReturn{}, "", err
	}

	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return ClientReturn{}, "", fmt.Errorf("allowing a consent: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	awaiting, err := lockAwaitingConsent(ctx, queries, handle, binding)
	if err != nil {
		return ClientReturn{}, "", err
	}

	created, err := queries.CreateNativeAuthorizationCode(ctx, query.CreateNativeAuthorizationCodeParams{
		CodeHash:        credentials.Digest(credentials.DomainNativeAuthorizationCode, code),
		AuthorizationID: awaiting.ID,
	})
	if err != nil {
		return ClientReturn{}, "", fmt.Errorf("issuing an authorization code: %w", err)
	}

	advanced, err := queries.MarkNativeAuthorizationCodeIssued(ctx, awaiting.ID)
	if err != nil {
		return ClientReturn{}, "", fmt.Errorf("issuing an authorization code: %w", err)
	}

	// The authorization is locked above, so both rows are there to change.
	if created != 1 || advanced != 1 {
		return ClientReturn{}, "", ErrNoSuchAuthorization
	}

	if err := transaction.Commit(ctx); err != nil {
		return ClientReturn{}, "", fmt.Errorf("issuing an authorization code: %w", err)
	}

	return ClientReturn{RedirectURI: awaiting.RedirectUri, ClientState: awaiting.ClientState}, code, nil
}

// CancelConsent ends an authorization on the person's refusal and returns where
// its client is told so. The client is left with nothing; the account the
// person's provider sign-in resolved to stays.
func (a *AuthorizationRequests) CancelConsent(ctx context.Context, handle, binding string) (ClientReturn, error) {
	if !credentials.IsOpaqueValue(handle) || !credentials.IsOpaqueValue(binding) {
		return ClientReturn{}, ErrNoSuchAuthorization
	}

	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return ClientReturn{}, fmt.Errorf("cancelling a consent: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	awaiting, err := lockAwaitingConsent(ctx, queries, handle, binding)
	if err != nil {
		return ClientReturn{}, err
	}

	if _, err := queries.DeleteNativeAuthorization(ctx, awaiting.ID); err != nil {
		return ClientReturn{}, fmt.Errorf("cancelling a consent: %w", err)
	}

	if err := transaction.Commit(ctx); err != nil {
		return ClientReturn{}, fmt.Errorf("cancelling a consent: %w", err)
	}

	return ClientReturn{RedirectURI: awaiting.RedirectUri, ClientState: awaiting.ClientState}, nil
}

// lockAwaitingConsent takes the shared authority lock and then the row of the
// consent a handle and binding name, so an approval, a cancellation and a
// rotation racing for one consent are ordered and only one of the first two
// finds it.
func lockAwaitingConsent(
	ctx context.Context, queries *query.Queries, handle, binding string,
) (query.LockNativeAuthorizationAwaitingConsentRow, error) {
	epoch, err := queries.LockAuthEpochShared(ctx)
	if err != nil {
		return query.LockNativeAuthorizationAwaitingConsentRow{}, fmt.Errorf("answering a consent: %w", err)
	}

	awaiting, err := queries.LockNativeAuthorizationAwaitingConsent(ctx, query.LockNativeAuthorizationAwaitingConsentParams{
		ConsentHandleHash:  credentials.Digest(credentials.DomainAuthorizationConsent, handle),
		BrowserBindingHash: credentials.Digest(credentials.DomainNativeBrowserBinding, binding),
		AuthEpoch:          epoch,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return query.LockNativeAuthorizationAwaitingConsentRow{}, ErrNoSuchAuthorization
	}

	if err != nil {
		return query.LockNativeAuthorizationAwaitingConsentRow{}, fmt.Errorf("answering a consent: %w", err)
	}

	return awaiting, nil
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
