//go:build integration && !devtools

package accounts_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// An account is only ever created from an identity a provider vouched for. These
// are the shapes no provider can produce, and none of them creates an account.
//
// No endpoint can present them: the provider clients refuse an incomplete
// identity before this is reached, and a login names a provider this service
// offers or is refused. They are stated here because the account layer is what
// must not create an account from them if that ever changes.
func TestAnIncompleteIdentityCreatesNoAccount(t *testing.T) {
	t.Parallel()

	people := accounts.New(testdatabase.NewMigrated(t))

	unusable := map[string]accounts.Identity{
		"no name": {
			Provider: oauth.Discord, ID: "4815162342", Username: "",
		},
		"no identifier": {
			Provider: oauth.Discord, ID: "", Username: "someone",
		},
		"neither": {
			Provider: oauth.Discord, ID: "", Username: "",
		},
		"a provider this service does not offer": {
			Provider: oauth.Provider("facebook"), ID: "12345", Username: "someone",
		},
	}

	for name, identity := range unusable {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := people.Resolve(t.Context(), identity); !errors.Is(err, accounts.ErrUnusableIdentity) {
				t.Errorf("err = %v, want %v", err, accounts.ErrUnusableIdentity)
			}
		})
	}
}

// An identifier nobody holds names nobody, and is reported as such rather than
// as an empty account.
func TestAnIdentifierNobodyHoldsNamesNobody(t *testing.T) {
	t.Parallel()

	people := accounts.New(testdatabase.NewMigrated(t))

	if _, err := people.Get(t.Context(), uuid.New()); !errors.Is(err, accounts.ErrNoSuchUser) {
		t.Errorf("err = %v, want %v", err, accounts.ErrNoSuchUser)
	}
}

// The account a provider identity resolves to is the one that identifier is
// then found by, and resolving the same identity again is the same person
// rather than a second account.
func TestAnIdentityResolvesToOneAccountThatCanBeFoundAgain(t *testing.T) {
	t.Parallel()

	people := accounts.New(testdatabase.NewMigrated(t))

	identity := accounts.Identity{Provider: oauth.GitHub, ID: "4815162", Username: "someone"}

	created, err := people.Resolve(t.Context(), identity)
	if err != nil {
		t.Fatalf("resolving an identity nobody has used: %v", err)
	}

	again, err := people.Resolve(t.Context(), identity)
	if err != nil {
		t.Fatalf("resolving the same identity again: %v", err)
	}

	if again.ID != created.ID {
		t.Errorf("the same identity resolved to %s and then %s", created.ID, again.ID)
	}

	found, err := people.Get(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("reading back the account that was created: %v", err)
	}

	if found.Username != identity.Username {
		t.Errorf("username = %q, want %q", found.Username, identity.Username)
	}
}
