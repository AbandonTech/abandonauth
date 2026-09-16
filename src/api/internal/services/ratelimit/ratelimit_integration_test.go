//go:build integration && !devtools

package ratelimit_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
)

// A budget every test here states independently of the limiter: twenty
// requests a minute for spending a one-time code.
const (
	loginExchangeLimit  = 20
	loginExchangeWindow = time.Minute
)

func newLimiter(t *testing.T, pool *pgxpool.Pool) *ratelimit.Limiter {
	t.Helper()

	limiter, err := ratelimit.New(pool, ratelimit.Options{Key: []byte("placeholder-rate-limit-key")})
	if err != nil {
		t.Fatalf("building the limiter: %v", err)
	}

	return limiter
}

// The window a request falls in is decided by the database, so two instances
// of the service count one client in one bucket whatever their own clocks say.
func TestSeparateLimitersShareOneBudget(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	first := newLimiter(t, pool)
	second := newLimiter(t, pool)

	for attempt := 0; attempt < loginExchangeLimit; attempt++ {
		counting := first
		if attempt%2 == 1 {
			counting = second
		}

		decision, err := counting.Count(t.Context(), ratelimit.LoginExchange, "198.51.100.10")
		if err != nil {
			t.Fatalf("counting attempt %d: %v", attempt, err)
		}

		if !decision.Allowed {
			t.Fatalf("attempt %d was refused inside the budget", attempt)
		}
	}

	decision, err := second.Count(t.Context(), ratelimit.LoginExchange, "198.51.100.10")
	if err != nil {
		t.Fatalf("counting the attempt past the budget: %v", err)
	}

	if decision.Allowed {
		t.Fatal("the attempt past the budget was allowed, so the two limiters counted separately")
	}
}

// A refusal says how long to wait in whole seconds, measured by the database:
// never nothing, and never longer than the window itself.
func TestRefusalWaitsWholePositiveNumberOfSecondsWithinWindow(t *testing.T) {
	t.Parallel()

	limiter := newLimiter(t, testdatabase.NewMigrated(t))

	var decision ratelimit.Decision

	for attempt := 0; attempt <= loginExchangeLimit; attempt++ {
		var err error

		decision, err = limiter.Count(t.Context(), ratelimit.LoginExchange, "198.51.100.11")
		if err != nil {
			t.Fatalf("counting attempt %d: %v", attempt, err)
		}
	}

	if decision.Allowed {
		t.Fatal("the attempt past the budget was allowed")
	}

	if decision.RetryAfter < time.Second {
		t.Errorf("RetryAfter = %v, want at least one second", decision.RetryAfter)
	}

	if decision.RetryAfter > loginExchangeWindow {
		t.Errorf("RetryAfter = %v, want no longer than the %v window", decision.RetryAfter, loginExchangeWindow)
	}

	if decision.RetryAfter%time.Second != 0 {
		t.Errorf("RetryAfter = %v, want whole seconds", decision.RetryAfter)
	}
}

// Two identities are two budgets, and one identity spelled as two parts is not
// the same identity spelled as one.
func TestBudgetsAreKeyedByWholeIdentity(t *testing.T) {
	t.Parallel()

	limiter := newLimiter(t, testdatabase.NewMigrated(t))

	for attempt := 0; attempt <= loginExchangeLimit; attempt++ {
		if _, err := limiter.Count(t.Context(), ratelimit.LoginExchange, "198.51.100.12", "an application"); err != nil {
			t.Fatalf("counting attempt %d: %v", attempt, err)
		}
	}

	others := map[string][]string{
		"another address with the same application": {"198.51.100.13", "an application"},
		"the same address alone":                    {"198.51.100.12"},
		"the same address for another application":  {"198.51.100.12", "another application"},
		"the parts joined into one":                 {"198.51.100.12an application"},
	}

	for name, parts := range others {
		decision, err := limiter.Count(t.Context(), ratelimit.LoginExchange, parts...)
		if err != nil {
			t.Fatalf("counting %s: %v", name, err)
		}

		if !decision.Allowed {
			t.Errorf("%s was refused on another identity's budget", name)
		}
	}
}

// A group the binary carries no budget for cannot be counted, and nothing is
// counted against nobody. Both are refused rather than allowed, so a caller
// that has to count and cannot does not let the request through.
func TestCountingNeedsKnownGroupAndIdentity(t *testing.T) {
	t.Parallel()

	limiter := newLimiter(t, testdatabase.NewMigrated(t))

	if _, err := limiter.Count(t.Context(), ratelimit.Group("no-such-group"), "198.51.100.14"); err == nil {
		t.Error("a group with no budget was counted")
	}

	if _, err := limiter.Count(t.Context(), ratelimit.LoginExchange); err == nil {
		t.Error("a request was counted against nobody")
	}
}

// The limiter cannot be built without a key: the table would otherwise hold
// client addresses in clear.
func TestLimiterNeedsKey(t *testing.T) {
	t.Parallel()

	if _, err := ratelimit.New(nil, ratelimit.Options{}); err == nil {
		t.Error("the limiter was built without a key")
	}
}

// Tidying up removes only windows that have ended. A window still being counted
// is left alone, so nobody gets a fresh budget from a sweep.
func TestTidyingUpRemovesOnlyWindowsThatHaveEnded(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	limiter := newLimiter(t, pool)

	if _, err := limiter.Count(t.Context(), ratelimit.LoginExchange, "198.51.100.15"); err != nil {
		t.Fatalf("counting a request: %v", err)
	}

	removed, err := limiter.Forget(t.Context())
	if err != nil {
		t.Fatalf("tidying up: %v", err)
	}

	if removed != 0 {
		t.Fatalf("tidying up removed %d windows that were still open", removed)
	}

	// The shortest window is a minute, which is too long to wait for, so the
	// one window that exists is moved to a start whose end has passed.
	testdatabase.Execute(t, pool,
		`UPDATE rate_limit_bucket
		 SET window_start = window_start - INTERVAL '1 day',
		     expires_at = expires_at - INTERVAL '1 day'`,
	)

	removed, err = limiter.Forget(t.Context())
	if err != nil {
		t.Fatalf("tidying up: %v", err)
	}

	if removed != 1 {
		t.Errorf("tidying up removed %d windows, want the one that had ended", removed)
	}

	// The identity is counted afresh: its budget is whole again.
	decision, err := limiter.Count(t.Context(), ratelimit.LoginExchange, "198.51.100.15")
	if err != nil {
		t.Fatalf("counting after the window ended: %v", err)
	}

	if !decision.Allowed {
		t.Error("a request in a fresh window was refused")
	}
}
