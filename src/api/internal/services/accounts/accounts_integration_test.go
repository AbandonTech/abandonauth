//go:build integration && !devtools

package accounts_test

import (
	"context"
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
func TestIncompleteIdentityCreatesNoAccount(t *testing.T) {
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
func TestIdentifierNobodyHoldsNamesNobody(t *testing.T) {
	t.Parallel()

	people := accounts.New(testdatabase.NewMigrated(t))

	if _, err := people.Get(t.Context(), uuid.New()); !errors.Is(err, accounts.ErrNoSuchUser) {
		t.Errorf("err = %v, want %v", err, accounts.ErrNoSuchUser)
	}
}

// The account a provider identity resolves to is the one that identifier is
// then found by, and resolving the same identity again is the same person
// rather than a second account.
func TestIdentityResolvesToOneAccountThatCanBeFoundAgain(t *testing.T) {
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

// A Steam ID is the whole unsigned 64-bit range. The same ID is the same person
// whatever name arrives with it, and two IDs are two people.
func TestSteamIdentityResolvesBySteamID(t *testing.T) {
	t.Parallel()

	people := accounts.New(testdatabase.NewMigrated(t))

	for _, id := range []string{"1", "76561197960287930", "18446744073709551615"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()

			created, err := people.Resolve(t.Context(), accounts.Identity{
				Provider: oauth.Steam, ID: id, Username: "steam:" + id,
			})
			if err != nil {
				t.Fatalf("resolving a Steam identity nobody has used: %v", err)
			}

			again, err := people.Resolve(t.Context(), accounts.Identity{
				Provider: oauth.Steam, ID: id, Username: "a different display name",
			})
			if err != nil {
				t.Fatalf("resolving the same Steam identity again: %v", err)
			}

			if again.ID != created.ID {
				t.Errorf("the same Steam ID resolved to %s and then %s", created.ID, again.ID)
			}

			if again.Username != "steam:"+id {
				t.Errorf("username = %q, want the one the account was created with", again.Username)
			}
		})
	}

	first, err := people.Resolve(t.Context(), accounts.Identity{
		Provider: oauth.Steam, ID: "76561197960287931", Username: "steam:76561197960287931",
	})
	if err != nil {
		t.Fatalf("resolving a Steam identity: %v", err)
	}

	second, err := people.Resolve(t.Context(), accounts.Identity{
		Provider: oauth.Steam, ID: "76561197960287932", Username: "steam:76561197960287931",
	})
	if err != nil {
		t.Fatalf("resolving another Steam identity: %v", err)
	}

	if first.ID == second.ID {
		t.Error("two Steam IDs sharing a display name resolved to one account")
	}
}

// A request cancelled while an account is half created leaves nothing behind:
// not the account without its provider identity, and not a lock that would
// stop the same person signing in next time.
func TestCancelledResolutionLeavesNoHalfCreatedAccount(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	people := accounts.New(pool)

	identity := accounts.Identity{Provider: oauth.Discord, ID: "4815162342", Username: "someone"}

	// A transaction holding an uncommitted claim on the same provider identity,
	// which is what the resolution below waits on after it has already written
	// the account row.
	blocker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("beginning the blocking transaction: %v", err)
	}

	var blockerUser uuid.UUID
	if err := blocker.QueryRow(t.Context(),
		`INSERT INTO "User" ("username") VALUES ('the blocker') RETURNING "id"`,
	).Scan(&blockerUser); err != nil {
		t.Fatalf("writing the blocker's account: %v", err)
	}

	if _, err := blocker.Exec(t.Context(),
		`INSERT INTO "DiscordAccount" ("id", "user_id") VALUES (4815162342, $1)`, blockerUser,
	); err != nil {
		t.Fatalf("claiming the provider identity: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())

	resolved := make(chan error, 1)

	go func() {
		_, err := people.Resolve(ctx, identity)
		resolved <- err
	}()

	if err := testdatabase.AwaitLockWaiters(t.Context(), pool, 1); err != nil {
		t.Fatalf("waiting for the resolution to block: %v", err)
	}

	cancel()

	if err := <-resolved; err == nil {
		t.Fatal("a cancelled resolution reported an account")
	}

	if err := blocker.Rollback(t.Context()); err != nil {
		t.Fatalf("releasing the blocking transaction: %v", err)
	}

	var halfCreated int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM "User" WHERE "username" = $1`, identity.Username,
	).Scan(&halfCreated); err != nil {
		t.Fatalf("reading what the cancelled resolution left: %v", err)
	}

	if halfCreated != 0 {
		t.Error("the cancelled resolution left an account nobody can sign in as")
	}

	// The same person can now be resolved: nothing the cancelled request held
	// is still held.
	created, err := people.Resolve(t.Context(), identity)
	if err != nil {
		t.Fatalf("resolving the identity after the cancelled attempt: %v", err)
	}

	if created.Username != identity.Username {
		t.Errorf("username = %q, want %q", created.Username, identity.Username)
	}
}
