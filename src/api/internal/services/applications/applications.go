// Package applications owns developer applications: the credential they
// authenticate with and the exact URIs they may be returned to.
//
// A refresh token is shown once, when it is created or replaced, and is stored
// only as a bcrypt hash. Replacing it also raises the application's credential
// version, in the same statement, so every access token minted against the
// replaced credential stops being accepted at the moment the replacement
// commits.
package applications

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database/query"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

// Reasons a request about an application is refused.
var (
	// ErrNoSuchApplication reports that no application has the given
	// identifier. A caller that is not the owner is told the same, so the
	// endpoint cannot be used to discover which applications exist.
	ErrNoSuchApplication = errors.New("no such developer application")
	// ErrInvalidCredential reports that the presented refresh token is not the
	// application's.
	ErrInvalidCredential = errors.New("the application's credential was not accepted")
)

// UnsafeCallbackError names a callback URI an application may not register and
// why. It deliberately does not carry the URI: it is another deployment's
// address and travels back to the caller.
type UnsafeCallbackError struct {
	// Index is the position of the refused URI in the list that was submitted.
	Index int

	Reason error
}

func (e UnsafeCallbackError) Error() string {
	return fmt.Sprintf("callback %d is not a URI this service will return a browser to: %s", e.Index, e.Reason)
}

// Unwrap gives the policy rule the URI broke.
func (e UnsafeCallbackError) Unwrap() error {
	return e.Reason
}

// Application is a developer application.
type Application struct {
	ID      uuid.UUID
	OwnerID uuid.UUID
	Name    string

	// CredentialVersion rises every time the refresh token is replaced. An
	// access token carries the version it was issued under.
	CredentialVersion int64

	credentialHash string
}

// UnknownApplicationComparisonInput is the published value the comparison hash
// below was made from. Presenting it for an application that does not exist
// makes the comparison succeed and grants nothing, because no application is
// found to grant.
const UnknownApplicationComparisonInput = "unknown-application-placeholder"

// unknownApplicationComparisonHash is what a presented credential is compared
// against when no application has the identifier it was presented for. It is
// bcrypt at HashCost, so the attempt costs what a stored credential costs, and
// it is valid from process start, so the first unknown request creates nothing.
const unknownApplicationComparisonHash = "$2a$12$YHRnbj5/MjY3jGMLwtZ5S.m44ZzB7aLchXMwhFCIQh/4CxCs6HAwe"

// Applications reads and changes developer applications.
type Applications struct {
	pool    *pgxpool.Pool
	queries *query.Queries
}

// New builds the service over the connection pool, which replacing a set of
// callbacks needs so that it happens all at once or not at all.
func New(pool *pgxpool.Pool) *Applications {
	return &Applications{pool: pool, queries: query.New(pool)}
}

// Create registers an application and returns its refresh token, which is not
// recoverable afterwards.
func (a *Applications) Create(ctx context.Context, ownerID uuid.UUID, name string) (Application, string, error) {
	token, hashed, err := a.newCredential()
	if err != nil {
		return Application{}, "", err
	}

	created, err := a.queries.CreateDeveloperApplication(ctx, query.CreateDeveloperApplicationParams{
		OwnerID:      ownerID,
		RefreshToken: hashed,
		Name:         name,
	})
	if err != nil {
		return Application{}, "", fmt.Errorf("creating an application: %w", err)
	}

	return Application{
		ID:                created.ID,
		OwnerID:           created.OwnerID,
		Name:              created.Name,
		CredentialVersion: created.CredentialVersion,
		credentialHash:    created.RefreshToken,
	}, token, nil
}

// Get returns one application.
func (a *Applications) Get(ctx context.Context, id uuid.UUID) (Application, error) {
	found, err := a.queries.GetDeveloperApplication(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, ErrNoSuchApplication
	}

	if err != nil {
		return Application{}, fmt.Errorf("reading an application: %w", err)
	}

	return Application{
		ID:                found.ID,
		OwnerID:           found.OwnerID,
		Name:              found.Name,
		CredentialVersion: found.CredentialVersion,
		credentialHash:    found.RefreshToken,
	}, nil
}

// OwnedBy returns one application only when a person owns it, and reports the
// same refusal when they do not as when it does not exist.
func (a *Applications) OwnedBy(ctx context.Context, id, ownerID uuid.UUID) (Application, error) {
	found, err := a.Get(ctx, id)
	if err != nil {
		return Application{}, err
	}

	if found.OwnerID != ownerID {
		return Application{}, ErrNoSuchApplication
	}

	return found, nil
}

// ListByOwner returns every application a person owns.
func (a *Applications) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]Application, error) {
	rows, err := a.queries.ListDeveloperApplicationsByOwner(ctx, ownerID)
	if err != nil {
		return nil, fmt.Errorf("listing applications: %w", err)
	}

	applications := make([]Application, 0, len(rows))
	for _, row := range rows {
		applications = append(applications, Application{
			ID:                row.ID,
			OwnerID:           row.OwnerID,
			Name:              row.Name,
			CredentialVersion: row.CredentialVersion,
			credentialHash:    row.RefreshToken,
		})
	}

	return applications, nil
}

// Delete removes an application and everything that referred to it.
func (a *Applications) Delete(ctx context.Context, id uuid.UUID) (Application, error) {
	deleted, err := a.queries.DeleteDeveloperApplication(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, ErrNoSuchApplication
	}

	if err != nil {
		return Application{}, fmt.Errorf("deleting an application: %w", err)
	}

	return Application{
		ID:                deleted.ID,
		OwnerID:           deleted.OwnerID,
		Name:              deleted.Name,
		CredentialVersion: deleted.CredentialVersion,
	}, nil
}

// ReplaceCredential issues a new refresh token and withdraws every access token
// issued against the one it replaces.
func (a *Applications) ReplaceCredential(ctx context.Context, id uuid.UUID) (Application, string, error) {
	token, hashed, err := a.newCredential()
	if err != nil {
		return Application{}, "", err
	}

	updated, err := a.queries.ResetDeveloperApplicationCredential(
		ctx, query.ResetDeveloperApplicationCredentialParams{ID: id, RefreshToken: hashed},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, "", ErrNoSuchApplication
	}

	if err != nil {
		return Application{}, "", fmt.Errorf("replacing an application's credential: %w", err)
	}

	return Application{
		ID:                updated.ID,
		OwnerID:           updated.OwnerID,
		Name:              updated.Name,
		CredentialVersion: updated.CredentialVersion,
	}, token, nil
}

// Authenticate returns the application a refresh token belongs to.
//
// An unknown application and a wrong token are refused identically, and both
// take one hash comparison, so the refusal does not say which of the two it
// was. A token bcrypt could not have made a hash from is refused before the
// identifier is looked up, so that refusal is the same for every identifier.
func (a *Applications) Authenticate(ctx context.Context, id uuid.UUID, refreshToken string) (Application, error) {
	if refreshToken == "" || len(refreshToken) > credentials.MaxSecretBytes {
		return Application{}, ErrInvalidCredential
	}

	found, err := a.Get(ctx, id)
	if err != nil && !errors.Is(err, ErrNoSuchApplication) {
		return Application{}, err
	}

	exists := err == nil

	comparedTo := unknownApplicationComparisonHash
	if exists {
		comparedTo = found.credentialHash
	}

	// The comparison runs before the existence result is consulted, so neither
	// branch can skip it.
	matched := credentials.Matches(refreshToken, comparedTo)

	if !exists || !matched {
		return Application{}, ErrInvalidCredential
	}

	return found, nil
}

// CallbackURIs lists where an application may be returned to.
func (a *Applications) CallbackURIs(ctx context.Context, id uuid.UUID) ([]string, error) {
	rows, err := a.queries.ListCallbackUris(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("listing callback URIs: %w", err)
	}

	uris := make([]string, 0, len(rows))
	for _, row := range rows {
		uris = append(uris, row.Uri)
	}

	return uris, nil
}

// CallbackIsRegistered reports whether an application registered exactly this
// URI. Nothing is normalised: the comparison is against the string the
// application submitted.
func (a *Applications) CallbackIsRegistered(ctx context.Context, id uuid.UUID, uri string) (bool, error) {
	if uri == "" {
		return false, nil
	}

	registered, err := a.queries.CallbackUriIsRegistered(ctx, query.CallbackUriIsRegisteredParams{
		DeveloperApplicationID: id,
		Uri:                    uri,
	})
	if err != nil {
		return false, fmt.Errorf("checking a callback URI: %w", err)
	}

	return registered, nil
}

// ReplaceCallbackURIs makes the registered set exactly the one submitted.
//
// Every URI is checked against the policy first, so one the service would
// refuse to return a browser to cannot be stored. The additions and removals
// are one transaction: a failure leaves the application with the set it had.
func (a *Applications) ReplaceCallbackURIs(ctx context.Context, id uuid.UUID, uris []string) error {
	wanted, err := acceptableURIs(uris)
	if err != nil {
		return err
	}

	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("replacing callback URIs: %w", err)
	}

	defer func() { _ = transaction.Rollback(ctx) }()

	queries := a.queries.WithTx(transaction)

	existing, err := queries.ListCallbackUris(ctx, id)
	if err != nil {
		return fmt.Errorf("replacing callback URIs: %w", err)
	}

	held := make(map[string]int32, len(existing))
	for _, row := range existing {
		held[row.Uri] = row.ID
	}

	for uri := range wanted {
		if _, already := held[uri]; already {
			continue
		}

		err = queries.CreateCallbackUri(ctx, query.CreateCallbackUriParams{
			DeveloperApplicationID: id,
			Uri:                    uri,
		})
		if err != nil {
			return fmt.Errorf("replacing callback URIs: %w", err)
		}
	}

	for uri, rowID := range held {
		if _, keep := wanted[uri]; keep {
			continue
		}

		if err := queries.DeleteCallbackUri(ctx, rowID); err != nil {
			return fmt.Errorf("replacing callback URIs: %w", err)
		}
	}

	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("replacing callback URIs: %w", err)
	}

	return nil
}

// acceptableURIs checks every submitted URI and collapses repeats, which the
// unique index would otherwise refuse as a conflict.
func acceptableURIs(uris []string) (map[string]struct{}, error) {
	accepted := make(map[string]struct{}, len(uris))

	for index, uri := range uris {
		if _, err := urlpolicy.ParseRegisteredCallbackURI(uri); err != nil {
			return nil, UnsafeCallbackError{Index: index, Reason: err}
		}

		accepted[uri] = struct{}{}
	}

	return accepted, nil
}

func (a *Applications) newCredential() (string, string, error) {
	token, err := credentials.NewOpaqueValue()
	if err != nil {
		return "", "", err
	}

	hashed, err := credentials.Hash(token)
	if err != nil {
		return "", "", err
	}

	return token, hashed, nil
}
