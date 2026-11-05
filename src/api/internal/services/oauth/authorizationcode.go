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

// The bounds of an RFC 7636 code verifier.
const (
	minVerifierBytes = 43
	maxVerifierBytes = 128
)

// ErrInvalidGrant reports a code or refresh token that grants nothing: unknown,
// expired, spent, revoked, or bound to another client, redirect, verifier or
// authority. Every case is the same refusal.
var ErrInvalidGrant = errors.New("the grant is not valid")

// Grant is what a set of tokens is issued for. UserID is the AbandonAuth user
// identifier every token for the grant carries as its subject.
type Grant struct {
	ClientID  uuid.UUID
	UserID    uuid.UUID
	Username  string
	Scopes    oidc.Scopes
	AuthTime  time.Time
	AuthEpoch uuid.UUID

	// Nonce is the authorization's nonce for a code, and empty for a refresh.
	Nonce string
}

// SignedTokens are the access and ID tokens signed for a grant.
type SignedTokens struct {
	AccessToken string
	IDToken     string
}

// TokenSigner signs the tokens for a grant. It runs inside the transaction that
// issues them, so a failure to sign leaves the code or refresh token usable.
type TokenSigner func(Grant) (SignedTokens, error)

// IssuedTokens are everything a token response carries.
type IssuedTokens struct {
	SignedTokens

	Scopes oidc.Scopes

	// RefreshToken is empty unless offline_access is granted.
	RefreshToken string

	// RefreshExpiresIn is the refresh token's remaining life in whole seconds,
	// measured by the database clock that issued it.
	RefreshExpiresIn int64
}

// ChallengeForVerifier returns the S256 challenge of a syntactically valid RFC
// 7636 code verifier.
func ChallengeForVerifier(verifier string) (string, bool) {
	if len(verifier) < minVerifierBytes || len(verifier) > maxVerifierBytes {
		return "", false
	}

	for index := range len(verifier) {
		character := verifier[index]

		unreserved := (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '.' ||
			character == '_' || character == '~'
		if !unreserved {
			return "", false
		}
	}

	return challengeFor(verifier), true
}

// AuthorizationCodes redeems the codes public clients' authorizations end in.
type AuthorizationCodes struct {
	pool    *pgxpool.Pool
	queries *query.Queries
	users   *PublicClientUsers
}

// NewAuthorizationCodes builds the service.
func NewAuthorizationCodes(pool *pgxpool.Pool, users *PublicClientUsers) *AuthorizationCodes {
	return &AuthorizationCodes{pool: pool, queries: query.New(pool), users: users}
}

// Redemption is what a client presents for a code.
type Redemption struct {
	ClientID    uuid.UUID
	Code        string
	RedirectURI string
	Verifier    string
}

// Redeem spends a code and issues its tokens in one transaction under the
// shared authority lock: the code and its authorization are deleted, the
// client's relationship with the person recorded, an offline grant's refresh
// family created, and the tokens signed, and nothing is issued unless all of
// it commits.
//
// The code is spent only when the client, the exact redirect, the current
// authority and the verifier's challenge all match, so a wrong attempt leaves
// it for the rightful one. Of two concurrent redemptions one succeeds.
func (c *AuthorizationCodes) Redeem(ctx context.Context, redemption Redemption, sign TokenSigner) (IssuedTokens, error) {
	challenge, valid := ChallengeForVerifier(redemption.Verifier)
	if !valid || !credentials.IsOpaqueValue(redemption.Code) || redemption.ClientID == uuid.Nil {
		return IssuedTokens{}, ErrInvalidGrant
	}

	transaction, err := c.pool.Begin(ctx)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("redeeming a code: %w", err)
	}

	defer func() { _ = database.Rollback(ctx, transaction) }()

	queries := c.queries.WithTx(transaction)

	epoch, err := queries.LockAuthEpochShared(ctx)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("redeeming a code: %w", err)
	}

	redeemed, err := queries.RedeemNativeAuthorizationCode(ctx, query.RedeemNativeAuthorizationCodeParams{
		CodeHash:      credentials.Digest(credentials.DomainNativeAuthorizationCode, redemption.Code),
		ApplicationID: redemption.ClientID,
		RedirectUri:   redemption.RedirectURI,
		CodeChallenge: challenge,
		AuthEpoch:     epoch,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return IssuedTokens{}, ErrInvalidGrant
	}

	if err != nil {
		return IssuedTokens{}, fmt.Errorf("redeeming a code: %w", err)
	}

	if _, err := queries.DeleteNativeAuthorization(ctx, redeemed.AuthorizationID); err != nil {
		return IssuedTokens{}, fmt.Errorf("redeeming a code: %w", err)
	}

	scopes, err := oidc.ParseScopes(redeemed.Scopes)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("redeeming a code: %w", err)
	}

	if err := c.users.Ensure(ctx, queries, redemption.ClientID, redeemed.UserID); err != nil {
		return IssuedTokens{}, err
	}

	grant := Grant{
		ClientID:  redemption.ClientID,
		UserID:    redeemed.UserID,
		Username:  redeemed.Username,
		Scopes:    scopes,
		AuthTime:  redeemed.AuthenticatedAt,
		AuthEpoch: epoch,
		Nonce:     redeemed.ClientNonce,
	}

	issued := IssuedTokens{Scopes: scopes}

	if scopes.Has(oidc.ScopeOfflineAccess) {
		issued.RefreshToken, issued.RefreshExpiresIn, err = startRefreshFamily(ctx, queries, grant)
		if err != nil {
			return IssuedTokens{}, err
		}
	}

	if issued.SignedTokens, err = sign(grant); err != nil {
		return IssuedTokens{}, err
	}

	if err := transaction.Commit(ctx); err != nil {
		return IssuedTokens{}, fmt.Errorf("redeeming a code: %w", err)
	}

	return issued, nil
}

// startRefreshFamily creates an offline grant's family and its first token,
// within the caller's transaction, under the person and application's lock.
// Ended families are removed first, and at ten the least recently created are
// revoked to make room, so one person and application hold at most ten.
func startRefreshFamily(ctx context.Context, queries *query.Queries, grant Grant) (string, int64, error) {
	if _, err := queries.LockPublicClientUser(ctx, query.LockPublicClientUserParams{
		ApplicationID: grant.ClientID, UserID: grant.UserID,
	}); err != nil {
		return "", 0, fmt.Errorf("locking an offline grant's holder: %w", err)
	}

	if _, err := queries.DeleteEndedRefreshFamiliesForPair(ctx, query.DeleteEndedRefreshFamiliesForPairParams{
		ApplicationID: grant.ClientID, UserID: grant.UserID,
	}); err != nil {
		return "", 0, fmt.Errorf("removing ended offline grants: %w", err)
	}

	if _, err := queries.EvictOldestRefreshFamilies(ctx, query.EvictOldestRefreshFamiliesParams{
		ApplicationID: grant.ClientID, UserID: grant.UserID,
	}); err != nil {
		return "", 0, fmt.Errorf("making room for an offline grant: %w", err)
	}

	family, err := queries.CreateRefreshFamily(ctx, query.CreateRefreshFamilyParams{
		ApplicationID:   grant.ClientID,
		UserID:          grant.UserID,
		Scopes:          grant.Scopes.String(),
		AuthenticatedAt: grant.AuthTime,
		AuthEpoch:       grant.AuthEpoch,
	})
	if err != nil {
		return "", 0, fmt.Errorf("creating an offline grant: %w", err)
	}

	return issueRefreshToken(ctx, queries, family)
}

func issueRefreshToken(ctx context.Context, queries *query.Queries, family uuid.UUID) (string, int64, error) {
	token, err := credentials.NewOpaqueValue()
	if err != nil {
		return "", 0, err
	}

	expiresIn, err := queries.CreateRefreshToken(ctx, query.CreateRefreshTokenParams{
		TokenHash: credentials.Digest(credentials.DomainRefreshToken, token),
		FamilyID:  family,
	})
	if err != nil {
		return "", 0, fmt.Errorf("issuing a refresh token: %w", err)
	}

	if expiresIn <= 0 {
		return "", 0, ErrInvalidGrant
	}

	return token, expiresIn, nil
}
