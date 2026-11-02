package oauth

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
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
)

// MaxRefreshTokensPerFamily is how many tokens, consumed and current, one
// family may hold. It permits a refresh every fifteen minutes for the family's
// whole ninety days, and keeps every consumed token for reuse detection.
const MaxRefreshTokensPerFamily = 10000

// ErrScopeNotGranted reports a refresh asking for scope its grant does not
// hold, or for a set without openid.
var ErrScopeNotGranted = errors.New("the requested scope is not a narrowing of the grant")

// RefreshTokens rotates and revokes public clients' offline grants.
type RefreshTokens struct {
	pool    *pgxpool.Pool
	queries *query.Queries
}

// NewRefreshTokens builds the service.
func NewRefreshTokens(pool *pgxpool.Pool) *RefreshTokens {
	return &RefreshTokens{pool: pool, queries: query.New(pool)}
}

// Refresh is what a client presents to rotate a refresh token. A nil Scopes
// keeps the grant; otherwise it must narrow it.
type Refresh struct {
	ClientID uuid.UUID
	Token    string
	Scopes   *oidc.Scopes
}

// Rotate spends a refresh token and issues its replacement and fresh tokens, in
// one transaction under the shared authority lock with the family locked.
//
// A consumed token presented again revokes the whole family, so of two parallel
// refreshes with one token at most one succeeds and the other ends the family.
// Narrowing away offline_access ends the family with no replacement. A family
// that would exceed its token ceiling is revoked instead of rotated.
func (r *RefreshTokens) Rotate(ctx context.Context, refresh Refresh, sign TokenSigner) (IssuedTokens, error) {
	if !credentials.IsOpaqueValue(refresh.Token) || refresh.ClientID == uuid.Nil {
		return IssuedTokens{}, ErrInvalidGrant
	}

	transaction, err := r.pool.Begin(ctx)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("rotating a refresh token: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := r.queries.WithTx(transaction)

	epoch, err := queries.LockAuthEpochShared(ctx)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("rotating a refresh token: %w", err)
	}

	tokenHash := credentials.Digest(credentials.DomainRefreshToken, refresh.Token)

	held, err := queries.LockRefreshToken(ctx, query.LockRefreshTokenParams{
		TokenHash: tokenHash, ApplicationID: refresh.ClientID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return IssuedTokens{}, ErrInvalidGrant
	}

	if err != nil {
		return IssuedTokens{}, fmt.Errorf("rotating a refresh token: %w", err)
	}

	if held.Consumed {
		return IssuedTokens{}, r.endFamily(ctx, transaction, queries, held.FamilyID)
	}

	if !held.Unexpired || !held.FamilyActive || held.AuthEpoch != epoch || held.ClientType != "public" {
		return IssuedTokens{}, ErrInvalidGrant
	}

	granted, err := oidc.ParseScopes(held.Scopes)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("rotating a refresh token: %w", err)
	}

	scopes := granted
	if refresh.Scopes != nil {
		scopes = *refresh.Scopes
		if !scopes.Has(oidc.ScopeOpenID) || !granted.Has(scopes) {
			return IssuedTokens{}, ErrScopeNotGranted
		}
	}

	issued := IssuedTokens{Scopes: scopes}

	switch {
	case !scopes.Has(oidc.ScopeOfflineAccess):
		if _, err := queries.DeleteRefreshFamily(ctx, held.FamilyID); err != nil {
			return IssuedTokens{}, fmt.Errorf("ending an offline grant: %w", err)
		}
	case held.MemberCount >= MaxRefreshTokensPerFamily:
		return IssuedTokens{}, r.endFamily(ctx, transaction, queries, held.FamilyID)
	default:
		if issued.RefreshToken, issued.RefreshExpiresIn, err = advanceFamily(
			ctx, queries, tokenHash, held.FamilyID, scopes,
		); err != nil {
			return IssuedTokens{}, err
		}
	}

	if issued.SignedTokens, err = sign(Grant{
		ClientID:  refresh.ClientID,
		Subject:   held.Subject,
		Username:  held.Username,
		Scopes:    scopes,
		AuthTime:  held.AuthenticatedAt,
		AuthEpoch: epoch,
	}); err != nil {
		return IssuedTokens{}, err
	}

	if err := transaction.Commit(ctx); err != nil {
		return IssuedTokens{}, fmt.Errorf("rotating a refresh token: %w", err)
	}

	return issued, nil
}

func advanceFamily(
	ctx context.Context, queries *query.Queries, presented []byte, family uuid.UUID, scopes oidc.Scopes,
) (string, int64, error) {
	consumed, err := queries.ConsumeRefreshToken(ctx, presented)
	if err != nil {
		return "", 0, fmt.Errorf("consuming a refresh token: %w", err)
	}

	advanced, err := queries.AdvanceRefreshFamily(ctx, query.AdvanceRefreshFamilyParams{
		ID: family, Scopes: scopes.String(),
	})
	if err != nil {
		return "", 0, fmt.Errorf("advancing an offline grant: %w", err)
	}

	// Both rows are locked by the caller, so each is there to change.
	if consumed != 1 || advanced != 1 {
		return "", 0, ErrInvalidGrant
	}

	return issueRefreshToken(ctx, queries, family)
}

// endFamily revokes a family, commits that revocation, and reports the refusal
// the presented token earns.
func (r *RefreshTokens) endFamily(
	ctx context.Context, transaction pgx.Tx, queries *query.Queries, family uuid.UUID,
) error {
	if _, err := queries.DeleteRefreshFamily(ctx, family); err != nil {
		return fmt.Errorf("revoking an offline grant: %w", err)
	}

	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("revoking an offline grant: %w", err)
	}

	return ErrInvalidGrant
}

// Revoke ends the offline grant a refresh token belongs to, when it belongs to
// the client. A value that names no family of that client revokes nothing and
// is not an error.
func (r *RefreshTokens) Revoke(ctx context.Context, clientID uuid.UUID, token string) error {
	if !credentials.IsOpaqueValue(token) {
		return nil
	}

	_, err := withSharedAuthority(ctx, r.pool, func(queries *query.Queries) (int64, error) {
		return queries.RevokeRefreshFamilyByToken(ctx, query.RevokeRefreshFamilyByTokenParams{
			TokenHash:     credentials.Digest(credentials.DomainRefreshToken, token),
			ApplicationID: clientID,
		})
	})
	if err != nil {
		return fmt.Errorf("revoking a refresh token: %w", err)
	}

	return nil
}

// Forget removes families that have ended, with their consumed tokens, once no
// token in them can be presented.
func (r *RefreshTokens) Forget(ctx context.Context) (int64, error) {
	removed, err := withSharedAuthority(ctx, r.pool, func(queries *query.Queries) (int64, error) {
		return queries.DeleteEndedRefreshFamilies(ctx, maximumCleanupRows)
	})
	if err != nil {
		return 0, fmt.Errorf("removing ended offline grants: %w", err)
	}

	return removed, nil
}
