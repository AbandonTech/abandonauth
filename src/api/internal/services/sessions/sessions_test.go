package sessions_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/sessions"
)

// A session that never ends is not a session. Refusing to build the store at
// all is what stops a missing setting from becoming an unbounded sign-in.
func TestASessionStoreNeedsALifetime(t *testing.T) {
	t.Parallel()

	for name, lifetime := range map[string]time.Duration{
		"no lifetime":            0,
		"a lifetime in the past": -time.Hour,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := sessions.NewStore(nil, sessions.Options{Lifetime: lifetime}); err == nil {
				t.Error("the store was built anyway")
			}
		})
	}
}

// The store keeps the lifetime it was given, because the cookies it sets are
// kept for exactly as long as the session behind them.
func TestASessionStoreKeepsTheLifetimeItWasGiven(t *testing.T) {
	t.Parallel()

	store, err := sessions.NewStore(nil, sessions.Options{Lifetime: 90 * time.Minute})
	if err != nil {
		t.Fatalf("building the store: %v", err)
	}

	if store.Lifetime() != 90*time.Minute {
		t.Errorf("lifetime = %v, want 90m", store.Lifetime())
	}
}

// A session stands for a person. One that stood for nobody would be a signed-in
// browser belonging to no account.
func TestASessionCannotBeCreatedWithoutAPerson(t *testing.T) {
	t.Parallel()

	store, err := sessions.NewStore(nil, sessions.Options{Lifetime: time.Hour})
	if err != nil {
		t.Fatalf("building the store: %v", err)
	}

	if _, err := store.Create(t.Context(), uuid.Nil); err == nil {
		t.Error("a session was created for nobody")
	}
}

// Signing out without a session is not an error: the endpoint answers the same
// way whether or not there was anything to end, so it cannot be used to
// discover which session values exist.
func TestEndingNothingIsNotAFailure(t *testing.T) {
	t.Parallel()

	store, err := sessions.NewStore(nil, sessions.Options{Lifetime: time.Hour})
	if err != nil {
		t.Fatalf("building the store: %v", err)
	}

	if err := store.End(t.Context(), ""); err != nil {
		t.Errorf("ending nothing reported %v", err)
	}
}

// A CSRF token is matched against the session it was issued with. An empty one
// never matches, so a request that sends no token cannot pass the check by
// arriving before the token was read.
func TestAnEmptyCSRFTokenMatchesNothing(t *testing.T) {
	t.Parallel()

	var session sessions.Session

	if session.MatchesCSRFToken("") {
		t.Error("an empty token was accepted")
	}

	if session.MatchesCSRFToken("something-else") {
		t.Error("a token was accepted by a session that was issued none")
	}
}
