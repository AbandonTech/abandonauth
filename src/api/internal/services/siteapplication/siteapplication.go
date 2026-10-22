// Package siteapplication creates the developer application that represents
// the AbandonAuth site itself, under the identifier the deployment is
// configured with.
//
// The application's owner holds no provider or password account, so nobody can
// sign in as it. The application's credential is generated and stored as a hash
// like any other, and never handed out: the site does not authenticate as an
// application.
package siteapplication

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/query"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

// Fixed labels of what provisioning creates.
const (
	// OwnerUsername is the display name of the account that owns the site's
	// application.
	OwnerUsername = "abandonauth"
	// ApplicationName is the name of the site's application.
	ApplicationName = "AbandonAuth"
)

// ErrNilApplicationID reports the all-zero UUID, which identifies nothing.
var ErrNilApplicationID = errors.New("the application identifier must not be the nil UUID")

// Outcome says what provisioning did.
type Outcome int

const (
	// Created reports that the owner, application and callback were written.
	Created Outcome = iota + 1
	// AlreadyPresent reports that an application already holds the identifier,
	// and that nothing was written or changed.
	AlreadyPresent
)

// Provision creates the site's application under applicationID, registered to
// return a browser to exactly callback, unless an application already holds
// that identifier.
//
// An existing application is left exactly as it is, whoever owns it and
// whatever it is registered with. The owner, application and callback are
// written in one transaction, so a failure or a concurrent provisioner leaves
// none of them behind.
func Provision(ctx context.Context, pool *pgxpool.Pool, applicationID uuid.UUID, callback string) (Outcome, error) {
	if applicationID == uuid.Nil {
		return 0, ErrNilApplicationID
	}

	if _, err := urlpolicy.ParseRegisteredCallbackURI(callback); err != nil {
		return 0, fmt.Errorf("the site's callback is not one this service will return a browser to: %w", err)
	}

	queries := query.New(pool)

	present, err := applicationExists(ctx, queries, applicationID)
	if err != nil {
		return 0, err
	}

	if present {
		return AlreadyPresent, nil
	}

	// Hashed before the transaction opens, so bcrypt's cost holds no
	// connection. The value itself is discarded here.
	secret, err := credentials.NewOpaqueValue()
	if err != nil {
		return 0, err
	}

	hashed, err := credentials.Hash(secret)
	if err != nil {
		return 0, err
	}

	return create(ctx, pool, queries, applicationID, hashed, callback)
}

func create(
	ctx context.Context, pool *pgxpool.Pool, queries *query.Queries,
	applicationID uuid.UUID, hashed, callback string,
) (Outcome, error) {
	transaction, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("provisioning the site's application: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries = queries.WithTx(transaction)

	present, err := applicationExists(ctx, queries, applicationID)
	if err != nil {
		return 0, err
	}

	if present {
		return AlreadyPresent, nil
	}

	owner, err := queries.CreateUser(ctx, OwnerUsername)
	if err != nil {
		return 0, fmt.Errorf("creating the site application's owner: %w", err)
	}

	inserted, err := queries.CreateDeveloperApplicationWithID(ctx, query.CreateDeveloperApplicationWithIDParams{
		ID:           applicationID,
		OwnerID:      owner.ID,
		RefreshToken: hashed,
		Name:         ApplicationName,
	})
	if err != nil {
		return 0, fmt.Errorf("creating the site's application: %w", err)
	}

	// Another provisioner committed the identifier while this one waited, and
	// the rollback takes this owner with it.
	if inserted == 0 {
		return AlreadyPresent, nil
	}

	if err := queries.CreateCallbackUri(ctx, query.CreateCallbackUriParams{
		DeveloperApplicationID: applicationID,
		Uri:                    callback,
	}); err != nil {
		return 0, fmt.Errorf("registering the site's callback: %w", err)
	}

	if err := transaction.Commit(ctx); err != nil {
		return 0, fmt.Errorf("provisioning the site's application: %w", err)
	}

	return Created, nil
}

func applicationExists(ctx context.Context, queries *query.Queries, applicationID uuid.UUID) (bool, error) {
	_, err := queries.GetDeveloperApplication(ctx, applicationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("reading the site's application: %w", err)
	}

	return true, nil
}
