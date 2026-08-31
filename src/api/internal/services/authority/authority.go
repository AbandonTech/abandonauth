// Package authority answers the two questions a valid signature cannot: which
// authority is current, and whether a particular token has been withdrawn.
//
// Every credential this service issues is stamped with the authority epoch it
// was made under. Rotating the epoch refuses all of them at once, which is what
// makes recovering from a suspected key compromise a single operation. A
// lookup that fails is never read as "not withdrawn"; the error is returned and
// the caller refuses the request.
package authority

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/database/query"
)

// ErrNoAuthority reports that the database holds no authority epoch. It is a
// schema that was never migrated, so nothing may be accepted.
var ErrNoAuthority = errors.New("the database holds no authority epoch")

// Authority reads the current epoch and the record of withdrawn tokens.
type Authority struct {
	queries *query.Queries
}

// New builds the service over a database handle.
func New(database query.DBTX) *Authority {
	return &Authority{queries: query.New(database)}
}

// Current returns the epoch every credential must have been issued under.
func (a *Authority) Current(ctx context.Context) (uuid.UUID, error) {
	epoch, err := a.queries.GetAuthEpoch(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("reading the current authority: %w", err)
	}

	if epoch.Epoch == uuid.Nil {
		return uuid.Nil, ErrNoAuthority
	}

	return epoch.Epoch, nil
}

// Withdraw refuses a token for the rest of its life.
//
// Withdrawing a token that was already withdrawn, or that never existed, is not
// an error: the endpoint that does it answers the same either way, so it cannot
// be used to discover which tokens exist.
func (a *Authority) Withdraw(ctx context.Context, identifier uuid.UUID, expiresAt time.Time) error {
	if identifier == uuid.Nil {
		return errors.New("a token cannot be withdrawn without being identified")
	}

	if err := a.queries.RevokeToken(ctx, query.RevokeTokenParams{
		Jti:       identifier,
		ExpiresAt: expiresAt,
	}); err != nil {
		return fmt.Errorf("withdrawing a token: %w", err)
	}

	return nil
}

// IsWithdrawn reports whether a token has been refused before its expiry.
func (a *Authority) IsWithdrawn(ctx context.Context, identifier uuid.UUID) (bool, error) {
	withdrawn, err := a.queries.TokenIsRevoked(ctx, identifier)
	if err != nil {
		return false, fmt.Errorf("reading whether a token was withdrawn: %w", err)
	}

	return withdrawn, nil
}
