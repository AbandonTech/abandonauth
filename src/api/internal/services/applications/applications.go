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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database"
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
	// ErrPublicClientHasNoCredential reports a credential operation on a public
	// client, which never holds one.
	ErrPublicClientHasNoCredential = errors.New("a public client has no credential")
)

// ClientType is the RFC 6749 client type an application is registered as. It
// never changes: moving to the other type means registering another
// application.
type ClientType string

// The two client types.
const (
	// Confidential is a server-side application that can protect a credential.
	Confidential ClientType = "confidential"
	// Public is an installed application that cannot protect a shared
	// credential, holds none and signs in only with PKCE.
	Public ClientType = "public"
)

// ParseClientType returns the client type a value names exactly.
func ParseClientType(value string) (ClientType, bool) {
	switch ClientType(value) {
	case Confidential, Public:
		return ClientType(value), true
	default:
		return "", false
	}
}

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
	ID         uuid.UUID
	OwnerID    uuid.UUID
	Name       string
	ClientType ClientType

	// CredentialVersion rises every time the refresh token is replaced. An
	// access token carries the version it was issued under.
	CredentialVersion int64

	credentialHash string
}

// describe is the application a stored row records. A row whose client type is
// neither known value is refused rather than given a default.
func describe(
	id, ownerID uuid.UUID, name string, credentialHash pgtype.Text, version int64, clientType string,
) (Application, error) {
	parsed, known := ParseClientType(clientType)
	if !known {
		return Application{}, errors.New("an application row records an unknown client type")
	}

	return Application{
		ID:                id,
		OwnerID:           ownerID,
		Name:              name,
		ClientType:        parsed,
		CredentialVersion: version,
		credentialHash:    credentialHash.String,
	}, nil
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

// CredentialHasher makes and checks the stored form of a refresh token.
type CredentialHasher interface {
	Hash(secret string) (string, error)
	Matches(secret, hashed string) bool
}

// credentialHasher is bcrypt at credentials.HashCost.
type credentialHasher struct{}

func (credentialHasher) Hash(secret string) (string, error) {
	return credentials.Hash(secret)
}

func (credentialHasher) Matches(secret, hashed string) bool {
	return credentials.Matches(secret, hashed)
}

// Applications reads and changes developer applications.
type Applications struct {
	pool    *pgxpool.Pool
	queries *query.Queries
	hasher  CredentialHasher
}

// New builds the service over the connection pool, which replacing a set of
// callbacks needs so that it happens all at once or not at all.
//
// A nil hasher is bcrypt at credentials.HashCost, so a composition that leaves
// it out cannot lower the work factor a stored credential is made with.
func New(pool *pgxpool.Pool, hasher CredentialHasher) *Applications {
	if hasher == nil {
		hasher = credentialHasher{}
	}

	return &Applications{pool: pool, queries: query.New(pool), hasher: hasher}
}

// Create registers an application. A confidential application's refresh token
// is returned, and is not recoverable afterwards; a public client receives
// none, and the empty string is returned in its place.
func (a *Applications) Create(
	ctx context.Context, ownerID uuid.UUID, name string, clientType ClientType,
) (Application, string, error) {
	if _, known := ParseClientType(string(clientType)); !known {
		return Application{}, "", errors.New("an application needs a known client type")
	}

	var (
		token  string
		stored pgtype.Text
	)

	if clientType == Confidential {
		var (
			hashed string
			err    error
		)

		token, hashed, err = a.newCredential()
		if err != nil {
			return Application{}, "", err
		}

		stored = pgtype.Text{String: hashed, Valid: true}
	}

	created, err := a.queries.CreateDeveloperApplication(ctx, query.CreateDeveloperApplicationParams{
		OwnerID:      ownerID,
		RefreshToken: stored,
		Name:         name,
		ClientType:   string(clientType),
	})
	if err != nil {
		return Application{}, "", fmt.Errorf("creating an application: %w", err)
	}

	application, err := describe(
		created.ID, created.OwnerID, created.Name, created.RefreshToken, created.CredentialVersion, created.ClientType,
	)
	if err != nil {
		return Application{}, "", err
	}

	return application, token, nil
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

	return describe(found.ID, found.OwnerID, found.Name, found.RefreshToken, found.CredentialVersion, found.ClientType)
}

// PublicClient returns an application only when it is a public client. A
// confidential application is refused exactly as one that does not exist.
func (a *Applications) PublicClient(ctx context.Context, id uuid.UUID) (Application, error) {
	found, err := a.Get(ctx, id)
	if err != nil {
		return Application{}, err
	}

	if found.ClientType != Public {
		return Application{}, ErrNoSuchApplication
	}

	return found, nil
}

// NativeRedirect returns the redirect a public client asked for when it is one
// of the client's registered loopback templates with a port added.
func (a *Applications) NativeRedirect(ctx context.Context, client Application, requested string) (string, bool, error) {
	if client.ClientType != Public {
		return "", false, nil
	}

	templates, err := a.CallbackURIs(ctx, client.ID)
	if err != nil {
		return "", false, err
	}

	for _, registered := range templates {
		template, err := urlpolicy.ParseNativeCallbackTemplate(registered)
		if err != nil {
			continue
		}

		if redirect, matched := urlpolicy.MatchNativeCallback(template, requested); matched {
			return redirect, true, nil
		}
	}

	return "", false, nil
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
		application, err := describe(
			row.ID, row.OwnerID, row.Name, row.RefreshToken, row.CredentialVersion, row.ClientType,
		)
		if err != nil {
			return nil, err
		}

		applications = append(applications, application)
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

	application, err := describe(
		deleted.ID, deleted.OwnerID, deleted.Name, pgtype.Text{}, deleted.CredentialVersion, deleted.ClientType,
	)
	if err != nil {
		return Application{}, err
	}

	return application, nil
}

// ReplaceCredential issues a new refresh token and withdraws every access token
// issued against the one it replaces. A public client has no credential to
// replace, and nothing is changed.
func (a *Applications) ReplaceCredential(ctx context.Context, id uuid.UUID) (Application, string, error) {
	found, err := a.Get(ctx, id)
	if err != nil {
		return Application{}, "", err
	}

	if found.ClientType != Confidential {
		return Application{}, "", ErrPublicClientHasNoCredential
	}

	token, hashed, err := a.newCredential()
	if err != nil {
		return Application{}, "", err
	}

	updated, err := a.queries.ResetDeveloperApplicationCredential(
		ctx, query.ResetDeveloperApplicationCredentialParams{ID: id, RefreshToken: pgtype.Text{String: hashed, Valid: true}},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, "", ErrNoSuchApplication
	}

	if err != nil {
		return Application{}, "", fmt.Errorf("replacing an application's credential: %w", err)
	}

	application, err := describe(
		updated.ID, updated.OwnerID, updated.Name, pgtype.Text{}, updated.CredentialVersion, updated.ClientType,
	)
	if err != nil {
		return Application{}, "", err
	}

	return application, token, nil
}

// Authenticate returns the confidential application a refresh token belongs
// to.
//
// An unknown application, a public client and a wrong token are refused
// identically, and each takes one hash comparison, so the refusal does not say
// which it was. A token bcrypt could not have made a hash from is refused
// before the identifier is looked up, so that refusal is the same for every
// identifier.
func (a *Applications) Authenticate(ctx context.Context, id uuid.UUID, refreshToken string) (Application, error) {
	if refreshToken == "" || len(refreshToken) > credentials.MaxSecretBytes {
		return Application{}, ErrInvalidCredential
	}

	found, err := a.Get(ctx, id)
	if err != nil && !errors.Is(err, ErrNoSuchApplication) {
		return Application{}, err
	}

	exists := err == nil && found.ClientType == Confidential

	comparedTo := unknownApplicationComparisonHash
	if exists {
		comparedTo = found.credentialHash
	}

	// The comparison runs before the existence result is consulted, so neither
	// branch can skip it.
	matched := a.hasher.Matches(refreshToken, comparedTo)

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
// Every URI is checked against the policy for the application's client type
// first, so one the service would refuse to return a browser to cannot be
// stored. The additions and removals are one transaction under the
// application's row lock: a failure leaves the application with the set it
// had, and two replacements arriving together leave it with one of the two sets
// rather than a mixture. An application that is gone by the time the lock is
// granted is ErrNoSuchApplication.
func (a *Applications) ReplaceCallbackURIs(ctx context.Context, application Application, uris []string) error {
	wanted, err := acceptableURIs(application.ClientType, uris)
	if err != nil {
		return err
	}

	id := application.ID

	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("replacing callback URIs: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := a.queries.WithTx(transaction)

	if _, err := queries.LockDeveloperApplication(ctx, id); errors.Is(err, pgx.ErrNoRows) {
		return ErrNoSuchApplication
	} else if err != nil {
		return fmt.Errorf("replacing callback URIs: %w", err)
	}

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

// acceptableURIs checks every submitted URI against the policy for the client
// type and collapses repeats, which the unique index would otherwise refuse as
// a conflict.
func acceptableURIs(clientType ClientType, uris []string) (map[string]struct{}, error) {
	accepted := make(map[string]struct{}, len(uris))

	for index, uri := range uris {
		var err error

		switch clientType {
		case Confidential:
			_, err = urlpolicy.ParseRegisteredCallbackURI(uri)
		case Public:
			_, err = urlpolicy.ParseNativeCallbackTemplate(uri)
		default:
			err = urlpolicy.ErrMalformed
		}

		if err != nil {
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

	hashed, err := a.hasher.Hash(token)
	if err != nil {
		return "", "", err
	}

	return token, hashed, nil
}
