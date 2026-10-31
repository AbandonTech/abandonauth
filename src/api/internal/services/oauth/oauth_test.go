package oauth_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// verifierKey is the size the verifier cipher requires. Its value is not a
// secret and protects nothing here.
var verifierKey = make([]byte, 32)

func TestOnlyProvidersThisServiceOffersAreNamed(t *testing.T) {
	t.Parallel()

	for _, provider := range oauth.Providers {
		parsed, known := oauth.ParseProvider(string(provider))
		if !known || parsed != provider {
			t.Errorf("%q is offered but was not recognised", provider)
		}
	}

	for _, name := range []string{"", "Discord", "Steam", "facebook", "discord ", "steam "} {
		if _, known := oauth.ParseProvider(name); known {
			t.Errorf("%q was recognised as a provider", name)
		}
	}

	if !slices.Equal(oauth.Providers, []oauth.Provider{oauth.Discord, oauth.GitHub, oauth.Google, oauth.Steam}) {
		t.Errorf("providers = %v, want Discord, GitHub, Google and Steam, in that order", oauth.Providers)
	}
}

// acceptingDatabase accepts every write and answers no read, so starting a
// login can be driven without a database.
type acceptingDatabase struct{}

func (acceptingDatabase) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (acceptingDatabase) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("acceptingDatabase answers no read")
}

func (acceptingDatabase) QueryRow(context.Context, string, ...any) pgx.Row {
	return refusingRow{}
}

type refusingRow struct{}

func (refusingRow) Scan(...any) error {
	return errors.New("acceptingDatabase answers no read")
}

// The three OAuth providers are sent a PKCE challenge and Google alone a nonce.
// Steam's OpenID 2.0 sign-in carries neither, so nothing it is sent claims a
// proof this service does not hold.
func TestLoginCarriesProtocolMaterialItsProviderUses(t *testing.T) {
	t.Parallel()

	store, err := oauth.NewStore(acceptingDatabase{}, verifierKey)
	if err != nil {
		t.Fatalf("building the store: %v", err)
	}

	tests := map[oauth.Provider]struct{ challenge, nonce bool }{
		oauth.Discord: {challenge: true},
		oauth.GitHub:  {challenge: true},
		oauth.Google:  {challenge: true, nonce: true},
		oauth.Steam:   {},
	}

	for provider, want := range tests {
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()

			started, err := store.Begin(t.Context(), provider, uuid.New(), "https://relying.example.test/return", "")
			if err != nil {
				t.Fatalf("starting a login: %v", err)
			}

			if started.State == "" || started.BrowserBinding == "" {
				t.Error("the login has no state or no browser binding")
			}

			if (started.Challenge != "") != want.challenge {
				t.Errorf("challenge present = %v, want %v", started.Challenge != "", want.challenge)
			}

			if (started.Nonce != "") != want.nonce {
				t.Errorf("nonce present = %v, want %v", started.Nonce != "", want.nonce)
			}
		})
	}
}

// The verifier is held encrypted, so a key the cipher cannot use must stop the
// store being built rather than surface later as a login that cannot complete.
func TestStoreNeedsUsableVerifierKey(t *testing.T) {
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
func TestLoginNeedsApplicationAndCallbackToBegin(t *testing.T) {
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
func TestLoginCannotBeConsumedWithoutBothHalves(t *testing.T) {
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
func TestOneTimeCodesNeedLifetime(t *testing.T) {
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
func TestOneTimeCodeNeedsPersonAndApplication(t *testing.T) {
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
func TestRedeemingNothingIsRefusedLikeUnknownCode(t *testing.T) {
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
func TestDiscardingNothingDoesNotFail(t *testing.T) {
	t.Parallel()

	codes, err := oauth.NewExchangeCodes(nil, time.Minute)
	if err != nil {
		t.Fatalf("building the codes: %v", err)
	}

	if err := codes.Discard(t.Context(), ""); err != nil {
		t.Errorf("discarding nothing reported %v", err)
	}
}
