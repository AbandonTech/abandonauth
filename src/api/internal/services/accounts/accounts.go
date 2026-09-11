// Package accounts maps a provider's idea of a person onto this service's.
//
// A person is recognised by the identifier their provider issued and by nothing
// else. Two accounts that happen to share a display name or an address are two
// people here, because a provider that let someone claim either could otherwise
// take over an existing account.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database/query"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// uniqueViolation is the SQLSTATE PostgreSQL reports when two requests insert
// the same provider identity at once.
const uniqueViolation = "23505"

// Reasons an identity cannot be used.
var (
	// ErrNoSuchUser reports that no account has the given identifier.
	ErrNoSuchUser = errors.New("no such user")
	// ErrUnusableIdentity reports that a provider described a person in a way
	// this service cannot store.
	ErrUnusableIdentity = errors.New("the provider described this person in a way this service cannot store")
)

// User is an account.
type User struct {
	ID       uuid.UUID
	Username string
}

// Identity is a person as one provider describes them.
type Identity struct {
	Provider oauth.Provider

	// ID is the identifier the provider issued, in the provider's own spelling.
	ID string

	// Username is what the person is shown as. It is a display value only and
	// is never used to find an existing account.
	Username string
}

// Accounts reads and creates accounts.
type Accounts struct {
	pool    *pgxpool.Pool
	queries *query.Queries
}

// New builds the service over the connection pool. It needs the pool rather
// than a single handle because creating an account writes two tables and must
// leave neither behind.
func New(pool *pgxpool.Pool) *Accounts {
	return &Accounts{pool: pool, queries: query.New(pool)}
}

// Get returns the account with an identifier.
func (a *Accounts) Get(ctx context.Context, id uuid.UUID) (User, error) {
	found, err := a.queries.GetUser(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNoSuchUser
	}

	if err != nil {
		return User{}, fmt.Errorf("reading a user: %w", err)
	}

	return User{ID: found.ID, Username: found.Username}, nil
}

// Resolve returns the account a provider identity belongs to, creating it the
// first time that identity is seen.
//
// Two requests that arrive with the same new identity at once produce one
// account: the one that loses the insert reads the winner's row rather than
// creating a second account for the same person.
func (a *Accounts) Resolve(ctx context.Context, identity Identity) (User, error) {
	if identity.Username == "" || identity.ID == "" {
		return User{}, ErrUnusableIdentity
	}

	found, err := a.lookup(ctx, identity)
	if err == nil {
		return found, nil
	}

	if !errors.Is(err, ErrNoSuchUser) {
		return User{}, err
	}

	created, err := a.create(ctx, identity)
	if err == nil {
		return created, nil
	}

	var failure *pgconn.PgError
	if !errors.As(err, &failure) || failure.Code != uniqueViolation {
		return User{}, err
	}

	return a.lookup(ctx, identity)
}

func (a *Accounts) lookup(ctx context.Context, identity Identity) (User, error) {
	var (
		id       uuid.UUID
		username string
		err      error
	)

	switch identity.Provider {
	case oauth.Discord:
		number, parseErr := discordIdentifier(identity.ID)
		if parseErr != nil {
			return User{}, parseErr
		}

		var row query.GetUserByDiscordAccountRow
		row, err = a.queries.GetUserByDiscordAccount(ctx, number)
		id, username = row.ID, row.Username
	case oauth.GitHub:
		number, parseErr := gitHubIdentifier(identity.ID)
		if parseErr != nil {
			return User{}, parseErr
		}

		var row query.GetUserByGitHubAccountRow
		row, err = a.queries.GetUserByGitHubAccount(ctx, number)
		id, username = row.ID, row.Username
	case oauth.Google:
		var row query.GetUserByGoogleAccountRow
		row, err = a.queries.GetUserByGoogleAccount(ctx, identity.ID)
		id, username = row.ID, row.Username
	default:
		return User{}, ErrUnusableIdentity
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNoSuchUser
	}

	if err != nil {
		return User{}, fmt.Errorf("reading a provider account: %w", err)
	}

	return User{ID: id, Username: username}, nil
}

// create writes the account and the provider identity together, so a failure
// cannot leave a user nobody can sign in as.
func (a *Accounts) create(ctx context.Context, identity Identity) (User, error) {
	transaction, err := a.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("creating an account: %w", err)
	}

	defer func() { _ = transaction.Rollback(ctx) }()

	queries := a.queries.WithTx(transaction)

	created, err := queries.CreateUser(ctx, identity.Username)
	if err != nil {
		return User{}, fmt.Errorf("creating an account: %w", err)
	}

	if err := linkIdentity(ctx, queries, identity, created.ID); err != nil {
		return User{}, err
	}

	if err := transaction.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("creating an account: %w", err)
	}

	return User{ID: created.ID, Username: created.Username}, nil
}

func linkIdentity(ctx context.Context, queries *query.Queries, identity Identity, userID uuid.UUID) error {
	switch identity.Provider {
	case oauth.Discord:
		number, err := discordIdentifier(identity.ID)
		if err != nil {
			return err
		}

		return queries.CreateDiscordAccount(ctx, query.CreateDiscordAccountParams{ID: number, UserID: userID})
	case oauth.GitHub:
		number, err := gitHubIdentifier(identity.ID)
		if err != nil {
			return err
		}

		return queries.CreateGitHubAccount(ctx, query.CreateGitHubAccountParams{ID: number, UserID: userID})
	case oauth.Google:
		return queries.CreateGoogleAccount(ctx, query.CreateGoogleAccountParams{ID: identity.ID, UserID: userID})
	default:
		return ErrUnusableIdentity
	}
}

// discordIdentifier reads the decimal identifier Discord issues, which is
// unsigned and wider than the column would hold if it were negative.
func discordIdentifier(value string) (int64, error) {
	number, err := strconv.ParseUint(value, 10, 63)
	if err != nil || number == 0 {
		return 0, ErrUnusableIdentity
	}

	return int64(number), nil
}

// gitHubIdentifier reads the identifier GitHub issues, which the column holds
// as a 32-bit integer.
func gitHubIdentifier(value string) (int32, error) {
	number, err := strconv.ParseInt(value, 10, 32)
	if err != nil || number <= 0 {
		return 0, ErrUnusableIdentity
	}

	return int32(number), nil
}
