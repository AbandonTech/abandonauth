// Package ratelimit counts a signed-in user's requests in fixed windows so that
// one account cannot make unbounded changes to developer applications.
//
// Counting happens in the database, and the window a request falls in is
// decided by the database clock, so a limit holds across every worker whatever
// each one's own clock says. What is counted is a keyed hash of whoever is
// being limited, never their identifier in clear.
//
// A budget is counted only against a principal the caller has proven. Anyone
// can name a public identifier, so a bucket keyed on one would let a stranger
// spend someone else's budget.
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

// DeveloperApplicationMutation covers a signed-in user creating, changing or
// deleting a developer application.
const DeveloperApplicationMutation Group = "developer_application_mutation"

// policy is how many requests a group allows in one window.
type policy struct {
	limit  int64
	window time.Duration
}

// policies are fixed in the binary. There is deliberately no setting that
// raises or removes a limit, because a misconfiguration would then be the way
// past every one of them at once.
var policies = map[Group]policy{
	DeveloperApplicationMutation: {limit: 20, window: time.Minute},
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

	// RetryAfter is how long until the window this request fell in ends, in
	// whole seconds as the database measured it. It is only meaningful when
	// the request was refused.
	RetryAfter time.Duration
}

// Limiter counts requests.
type Limiter struct {
	queries *query.Queries
	key     []byte
}

// Options are what the limiter needs.
type Options struct {
	// Key turns an identity into the value stored. Without it the table would
	// hold user identifiers in clear, which it has no reason to keep.
	Key []byte
}

// New builds the limiter over a database handle.
func New(database query.DBTX, options Options) (*Limiter, error) {
	if len(options.Key) == 0 {
		return nil, errors.New("the limiter needs a key to pseudonymise callers with")
	}

	for group, budget := range policies {
		if budget.limit <= 0 || budget.window < time.Second || budget.window%time.Second != 0 {
			return nil, fmt.Errorf("the budget for %q is not a positive count in a whole number of seconds", group)
		}
	}

	return &Limiter{queries: query.New(database), key: options.Key}, nil
}

// Count records one request against a group and reports whether it may proceed.
//
// The parts identify who is being counted, and must be something the caller has
// proven rather than merely named.
func (l *Limiter) Count(ctx context.Context, group Group, parts ...string) (Decision, error) {
	budget, known := policies[group]
	if !known {
		return Decision{}, fmt.Errorf("there is no limit for %q", group)
	}

	if len(parts) == 0 {
		return Decision{}, errors.New("a limit needs something to count against")
	}

	counted, err := l.queries.CountRequestInWindow(ctx, query.CountRequestInWindowParams{
		BucketKey:     l.bucketKey(group, parts),
		EndpointGroup: string(group),
		WindowSeconds: int64(budget.window / time.Second),
	})
	if err != nil {
		return Decision{}, fmt.Errorf("counting a request: %w", err)
	}

	if counted.Count > budget.limit {
		if counted.RetryAfterSeconds < 1 {
			return Decision{}, errors.New("the database reported no time left in a window it counted against")
		}

		return Decision{
			Allowed:    false,
			RetryAfter: time.Duration(counted.RetryAfterSeconds) * time.Second,
		}, nil
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
