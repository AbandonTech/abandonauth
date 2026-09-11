// Package ratelimit counts requests in fixed windows so that guessing a
// password, a refresh token or a one-time code is slow, and so that a provider
// cannot be flooded on this service's behalf.
//
// Counting happens in the database, so a limit holds across every worker. What
// is counted is a keyed hash of whoever is being limited, never a client
// address in clear.
//
// Who is counted matters as much as how often. Anyone can name a public
// application identifier, so a bucket keyed on one alone would let a stranger
// lock a real application out. A caller therefore counts against the client
// address, or the address combined with what was supplied, until something
// unguessable has been proven; only then may it count against the principal
// itself.
package ratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/database/query"
)

// Group names a set of endpoints that share one budget. The values are the ones
// the database accepts, so a group that is not one of these cannot be counted.
type Group string

// The groups requests are counted against.
const (
	// ProviderCallback covers returning from a provider, which costs an
	// outbound request to that provider.
	ProviderCallback Group = "provider_callback"
	// LoginExchange covers spending a one-time code for an access token.
	LoginExchange Group = "login_exchange"
	// DeveloperApplicationLogin covers presenting an application's refresh
	// token, which costs a bcrypt comparison.
	DeveloperApplicationLogin Group = "developer_application_login"
	// PasswordSignIn covers the development-only password endpoints.
	PasswordSignIn Group = "debug_password_auth"
	// DeveloperApplicationMutation covers creating an application, resetting its
	// credential and replacing its callbacks.
	DeveloperApplicationMutation Group = "developer_application_mutation"
	// BurnToken covers withdrawing a credential.
	BurnToken Group = "burn_token"
)

// Policy is how many requests a group allows in one window.
type Policy struct {
	Limit  int64
	Window time.Duration
}

// policies are fixed in the binary. There is deliberately no setting that
// raises or removes a limit, because a misconfiguration would then be the way
// past every one of them at once.
var policies = map[Group]Policy{
	ProviderCallback:             {Limit: 30, Window: 10 * time.Minute},
	LoginExchange:                {Limit: 20, Window: time.Minute},
	DeveloperApplicationLogin:    {Limit: 10, Window: 5 * time.Minute},
	PasswordSignIn:               {Limit: 5, Window: 10 * time.Minute},
	DeveloperApplicationMutation: {Limit: 20, Window: time.Hour},
	BurnToken:                    {Limit: 60, Window: time.Minute},
}

// PolicyFor returns the budget of a group.
func PolicyFor(group Group) (Policy, bool) {
	policy, known := policies[group]

	return policy, known
}

// keySeparator ends each part of a bucket's identity so that two different
// identities cannot be spelled as one.
const keySeparator = 0x00

// maximumCleanupRows bounds an opportunistic delete so that tidying up expired
// windows can never become the slowest part of a request.
const maximumCleanupRows = 500

// Decision is whether a request may proceed.
type Decision struct {
	Allowed bool

	// RetryAfter is how long until the window this request fell in ends. It is
	// only meaningful when the request was refused.
	RetryAfter time.Duration
}

// Limiter counts requests.
type Limiter struct {
	queries *query.Queries
	key     []byte
	now     func() time.Time
}

// Options are what the limiter needs.
type Options struct {
	// Key turns an identity into the value stored. Without it the table would
	// hold client addresses, which are personal data this service has no reason
	// to keep.
	Key []byte

	// Now is the clock windows are derived from. The count itself is atomic in
	// the database; only the window boundary comes from here.
	Now func() time.Time
}

// New builds the limiter over a database handle.
func New(database query.DBTX, options Options) (*Limiter, error) {
	if len(options.Key) == 0 {
		return nil, errors.New("the limiter needs a key to pseudonymise callers with")
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}

	return &Limiter{queries: query.New(database), key: options.Key, now: now}, nil
}

// Count records one request against a group and reports whether it may proceed.
//
// The parts identify who is being counted. A caller passes the client address,
// and adds whatever else it may safely include: something the caller supplied
// but did not have to prove only narrows the bucket, while something proven may
// stand alone.
func (l *Limiter) Count(ctx context.Context, group Group, parts ...string) (Decision, error) {
	policy, known := policies[group]
	if !known {
		return Decision{}, fmt.Errorf("there is no limit for %q", group)
	}

	if len(parts) == 0 {
		return Decision{}, errors.New("a limit needs something to count against")
	}

	now := l.now().UTC()
	windowStart := now.Truncate(policy.Window)
	expiresAt := windowStart.Add(policy.Window)

	count, err := l.queries.CountRequestInWindow(ctx, query.CountRequestInWindowParams{
		BucketKey:     l.bucketKey(group, parts),
		EndpointGroup: string(group),
		WindowStart:   windowStart,
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		return Decision{}, fmt.Errorf("counting a request: %w", err)
	}

	if count > policy.Limit {
		return Decision{Allowed: false, RetryAfter: expiresAt.Sub(now)}, nil
	}

	return Decision{Allowed: true}, nil
}

// Forget removes the windows that have ended. It is bounded so that a caller
// that runs it opportunistically cannot stall behind a large delete.
func (l *Limiter) Forget(ctx context.Context) (int64, error) {
	removed, err := l.queries.DeleteExpiredRateLimitBuckets(ctx, maximumCleanupRows)
	if err != nil {
		return 0, fmt.Errorf("removing ended windows: %w", err)
	}

	return removed, nil
}

func (l *Limiter) bucketKey(group Group, parts []string) []byte {
	keyed := hmac.New(sha256.New, l.key)
	keyed.Write([]byte(group))
	keyed.Write([]byte{keySeparator})

	for _, part := range parts {
		keyed.Write([]byte(part))
		keyed.Write([]byte{keySeparator})
	}

	return keyed.Sum(nil)
}
