package oauth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// verifierKey is the size the verifier cipher requires. Its value is not a
// secret and protects nothing here.
var verifierKey = make([]byte, 32)

func TestOnlyTheProvidersThisServiceOffersAreNamed(t *testing.T) {
	t.Parallel()

	for _, provider := range oauth.Providers {
		parsed, known := oauth.ParseProvider(string(provider))
		if !known || parsed != provider {
			t.Errorf("%q is offered but was not recognised", provider)
		}
	}

	for _, name := range []string{"", "Discord", "facebook", "discord "} {
		if _, known := oauth.ParseProvider(name); known {
			t.Errorf("%q was recognised as a provider", name)
		}
	}
}

// The verifier is held encrypted, so a key the cipher cannot use must stop the
// store being built rather than surface later as a login that cannot complete.
func TestAStoreNeedsAUsableVerifierKey(t *testing.T) {
	t.Parallel()

	for name, key := range map[string][]byte{
		"no key":           nil,
		"too short a key":  make([]byte, 8),
		"an odd-sized key": make([]byte, 17),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := oauth.NewStore(nil, key); err == nil {
				t.Error("the store was built anyway")
			}
		})
	}
}

// A login is always for some application, returning to some address. Without
// both there is nothing for the callback to check the provider's answer against.
func TestALoginNeedsAnApplicationAndACallbackToBegin(t *testing.T) {
	t.Parallel()

	store, err := oauth.NewStore(nil, verifierKey)
	if err != nil {
		t.Fatalf("building the store: %v", err)
	}

	cases := map[string]struct {
		application uuid.UUID
		callback    string
	}{
		"no application": {uuid.Nil, "https://relying.example.test/return"},
		"no callback":    {uuid.New(), ""},
		"neither":        {uuid.Nil, ""},
	}

	for name, given := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := store.Begin(t.Context(), oauth.Discord, given.application, given.callback, "")
			if err == nil {
				t.Error("a login was started anyway")
			}
		})
	}
}

// Presenting nothing is refused the same way as presenting a state value that
// was never issued, so a caller learns nothing from being refused.
func TestALoginCannotBeConsumedWithoutBothHalves(t *testing.T) {
	t.Parallel()

	store, err := oauth.NewStore(nil, verifierKey)
	if err != nil {
		t.Fatalf("building the store: %v", err)
	}

	cases := map[string]struct{ state, binding string }{
		"no state":   {"", "a-binding"},
		"no binding": {"a-state", ""},
		"neither":    {"", ""},
	}

	for name, given := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := store.Consume(t.Context(), oauth.Discord, given.state, given.binding)
			if !errors.Is(err, oauth.ErrNoSuchLogin) {
				t.Errorf("err = %v, want %v", err, oauth.ErrNoSuchLogin)
			}
		})
	}
}

// A one-time code that never expired would be a permanent credential in a query
// string.
func TestOneTimeCodesNeedALifetime(t *testing.T) {
	t.Parallel()

	for name, lifetime := range map[string]time.Duration{
		"no lifetime":            0,
		"a lifetime in the past": -time.Minute,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := oauth.NewExchangeCodes(nil, lifetime); err == nil {
				t.Error("the codes were built anyway")
			}
		})
	}
}

// A code identifies a person to an application. Issued for neither, it would
// be a credential for nobody that some application could still spend.
func TestAOneTimeCodeNeedsAPersonAndAnApplication(t *testing.T) {
	t.Parallel()

	codes, err := oauth.NewExchangeCodes(nil, time.Minute)
	if err != nil {
		t.Fatalf("building the codes: %v", err)
	}

	cases := map[string]struct{ user, application uuid.UUID }{
		"no person":      {uuid.Nil, uuid.New()},
		"no application": {uuid.New(), uuid.Nil},
		"neither":        {uuid.Nil, uuid.Nil},
	}

	for name, given := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := codes.Issue(t.Context(), given.user, given.application, oauth.Discord); err == nil {
				t.Error("a code was issued anyway")
			}
		})
	}
}

// Redeeming nothing is refused the same way as redeeming a code that was never
// issued.
func TestRedeemingNothingIsRefusedLikeAnUnknownCode(t *testing.T) {
	t.Parallel()

	codes, err := oauth.NewExchangeCodes(nil, time.Minute)
	if err != nil {
		t.Fatalf("building the codes: %v", err)
	}

	if _, err := codes.Redeem(t.Context(), "", uuid.New()); !errors.Is(err, oauth.ErrNoSuchCode) {
		t.Errorf("err = %v, want %v", err, oauth.ErrNoSuchCode)
	}
}

// Withdrawing nothing is not a failure, so the endpoint that withdraws a
// credential answers the same way whether or not there was one.
func TestDiscardingNothingIsNotAFailure(t *testing.T) {
	t.Parallel()

	codes, err := oauth.NewExchangeCodes(nil, time.Minute)
	if err != nil {
		t.Fatalf("building the codes: %v", err)
	}

	if err := codes.Discard(t.Context(), ""); err != nil {
		t.Errorf("discarding nothing reported %v", err)
	}
}
