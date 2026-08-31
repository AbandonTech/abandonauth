package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abandontech/abandonauth/src/api/internal/database/query"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
)

// ErrNoSuchCode reports that no one-time code matches what was presented. It is
// returned whether the code never existed, expired, was already spent, or
// belongs to a different application, so a caller learns nothing from it.
var ErrNoSuchCode = errors.New("no one-time code matches this request")

// Redeemed is the sign-in a one-time code stood for.
type Redeemed struct {
	UserID        uuid.UUID
	ApplicationID uuid.UUID
	Provider      Provider
}

// ExchangeCodes issues and spends the one-time codes an application collects an
// access token with.
//
// The code travels through the person's browser, so it is short-lived, stored
// only as a digest, bound to the application it was issued for, and spent by a
// single delete that no second attempt can repeat.
type ExchangeCodes struct {
	queries  *query.Queries
	lifetime time.Duration
}

// NewExchangeCodes builds the service over a database handle.
func NewExchangeCodes(database query.DBTX, lifetime time.Duration) (*ExchangeCodes, error) {
	if lifetime <= 0 {
		return nil, errors.New("a one-time code needs a lifetime")
	}

	return &ExchangeCodes{queries: query.New(database), lifetime: lifetime}, nil
}

// Issue returns a fresh code for an application to collect a token with.
func (e *ExchangeCodes) Issue(
	ctx context.Context, userID, applicationID uuid.UUID, provider Provider,
) (string, error) {
	if userID == uuid.Nil || applicationID == uuid.Nil {
		return "", errors.New("a one-time code needs a user and an application")
	}

	code, err := credentials.NewOpaqueValue()
	if err != nil {
		return "", err
	}

	err = e.queries.CreateExchangeCode(ctx, query.CreateExchangeCodeParams{
		CodeHash:        credentials.Digest(credentials.DomainExchangeCode, code),
		UserID:          userID,
		ApplicationID:   applicationID,
		Provider:        string(provider),
		LifetimeSeconds: e.lifetime.Seconds(),
	})
	if err != nil {
		return "", fmt.Errorf("recording a one-time code: %w", err)
	}

	return code, nil
}

// Redeem spends a code on behalf of the application it was issued to.
func (e *ExchangeCodes) Redeem(ctx context.Context, code string, applicationID uuid.UUID) (Redeemed, error) {
	if code == "" || applicationID == uuid.Nil {
		return Redeemed{}, ErrNoSuchCode
	}

	spent, err := e.queries.ConsumeExchangeCode(ctx, query.ConsumeExchangeCodeParams{
		CodeHash:      credentials.Digest(credentials.DomainExchangeCode, code),
		ApplicationID: applicationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Redeemed{}, ErrNoSuchCode
	}

	if err != nil {
		return Redeemed{}, fmt.Errorf("spending a one-time code: %w", err)
	}

	return Redeemed{
		UserID:        spent.UserID,
		ApplicationID: spent.ApplicationID,
		Provider:      Provider(spent.Provider),
	}, nil
}

// Discard removes a code without spending it.
//
// It does not report whether the code existed, so the endpoint that withdraws a
// credential cannot be used to discover which codes are outstanding.
func (e *ExchangeCodes) Discard(ctx context.Context, code string) error {
	if code == "" {
		return nil
	}

	digest := credentials.Digest(credentials.DomainExchangeCode, code)

	if _, err := e.queries.DeleteExchangeCode(ctx, digest); err != nil {
		return fmt.Errorf("withdrawing a one-time code: %w", err)
	}

	return nil
}
