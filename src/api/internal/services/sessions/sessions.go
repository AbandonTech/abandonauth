// Package sessions is the authority behind a signed-in browser.
//
// The browser holds a random value; the database holds its digest and the user
// it stands for. Nothing about the session is signed into the cookie, so ending
// a session is a delete and takes effect immediately for every worker. Expiry
// is absolute: using a session does not extend it.
//
// A cookie is sent by the browser whether or not the site made the request, so
// every session also carries a second value the site must echo back in a header
// before the session may change anything.
package sessions

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

// ErrNoSuchSession reports that no session matches what was presented, whether
// it never existed, expired, was signed out, or was issued under an authority
// that has since been rotated.
var ErrNoSuchSession = errors.New("no session matches this request")

// Issued is a new session and the values the browser is given.
type Issued struct {
	// Value goes in the session cookie and is never stored.
	Value string

	// CSRFToken goes in a cookie the site can read, and is sent back in a
	// header on every request that changes something.
	CSRFToken string

	ExpiresAt time.Time
}

// Session is a signed-in browser, as read back from a cookie.
type Session struct {
	UserID    uuid.UUID
	ExpiresAt time.Time

	csrfDigest []byte
}

// MatchesCSRFToken reports whether a value is the one this session was issued
// with.
func (s Session) MatchesCSRFToken(token string) bool {
	if token == "" {
		return false
	}

	return credentials.Equal(s.csrfDigest, credentials.Digest(credentials.DomainCSRFToken, token))
}

// Store creates, reads and ends browser sessions.
type Store struct {
	queries  *query.Queries
	lifetime time.Duration
	now      func() time.Time
}

// Options are what the store needs.
type Options struct {
	// Lifetime is how long a browser stays signed in without proving itself to
	// a provider again. It does not slide.
	Lifetime time.Duration

	// Now is the clock the returned expiry is measured from. The database sets
	// the stored expiry itself; this only tells the browser how long to keep
	// the cookie.
	Now func() time.Time
}

// NewStore builds the store over a database handle.
func NewStore(database query.DBTX, options Options) (*Store, error) {
	if options.Lifetime <= 0 {
		return nil, errors.New("a session needs a lifetime")
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}

	return &Store{queries: query.New(database), lifetime: options.Lifetime, now: now}, nil
}

// Lifetime is how long a session lasts, which is also how long its cookies are
// kept.
func (s *Store) Lifetime() time.Duration {
	return s.lifetime
}

// Create signs a browser in.
func (s *Store) Create(ctx context.Context, userID uuid.UUID) (Issued, error) {
	if userID == uuid.Nil {
		return Issued{}, errors.New("a session needs a user")
	}

	value, err := credentials.NewOpaqueValue()
	if err != nil {
		return Issued{}, err
	}

	token, err := credentials.NewOpaqueValue()
	if err != nil {
		return Issued{}, err
	}

	err = s.queries.CreateBrowserSession(ctx, query.CreateBrowserSessionParams{
		SessionHash:     credentials.Digest(credentials.DomainBrowserSession, value),
		UserID:          userID,
		CsrfHash:        credentials.Digest(credentials.DomainCSRFToken, token),
		LifetimeSeconds: s.lifetime.Seconds(),
	})
	if err != nil {
		return Issued{}, fmt.Errorf("creating a session: %w", err)
	}

	return Issued{
		Value:     value,
		CSRFToken: token,
		ExpiresAt: s.now().UTC().Add(s.lifetime),
	}, nil
}

// Lookup returns the session a cookie value stands for.
func (s *Store) Lookup(ctx context.Context, value string) (Session, error) {
	if value == "" {
		return Session{}, ErrNoSuchSession
	}

	found, err := s.queries.GetBrowserSession(
		ctx, credentials.Digest(credentials.DomainBrowserSession, value),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNoSuchSession
	}

	if err != nil {
		return Session{}, fmt.Errorf("reading a session: %w", err)
	}

	return Session{
		UserID:     found.UserID,
		ExpiresAt:  found.ExpiresAt,
		csrfDigest: found.CsrfHash,
	}, nil
}

// End signs a browser out. Ending a session that is already gone is not an
// error, so signing out twice answers the same way.
func (s *Store) End(ctx context.Context, value string) error {
	if value == "" {
		return nil
	}

	digest := credentials.Digest(credentials.DomainBrowserSession, value)

	if _, err := s.queries.DeleteBrowserSession(ctx, digest); err != nil {
		return fmt.Errorf("ending a session: %w", err)
	}

	return nil
}

// maximumCleanupRows bounds one sweep so that tidying up can never become the
// slowest thing running against the database.
const maximumCleanupRows = 500

// Forget removes sessions that have reached their expiry.
//
// Reading a session already requires it to be unexpired, so nobody is signed
// out by this who was not already signed out by the clock.
func (s *Store) Forget(ctx context.Context) (int64, error) {
	removed, err := s.queries.DeleteExpiredBrowserSessions(ctx, maximumCleanupRows)
	if err != nil {
		return 0, fmt.Errorf("removing expired sessions: %w", err)
	}

	return removed, nil
}
