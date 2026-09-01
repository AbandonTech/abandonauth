//go:build integration

package web_test

import (
	"net/http"
	"sync"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// An account is keyed on the identifier a provider issued, in that provider's
// own spelling. A provider that answers with something this service cannot
// store as an identifier signs nobody in, rather than creating an account under
// a value that has been quietly coerced.
func TestAPersonAProviderDescribesUnusablyIsNotSignedIn(t *testing.T) {
	t.Parallel()

	unusable := map[string]struct {
		provider oauth.Provider
		identity providertest.Identity
	}{
		"a Discord identifier that is not a number": {
			oauth.Discord, providertest.Identity{ID: "not-a-number", Username: "someone"},
		},
		"a Discord account with no name": {
			oauth.Discord, providertest.Identity{ID: "4815162342", Username: ""},
		},
		"a GitHub identifier below zero": {
			oauth.GitHub, providertest.Identity{ID: "-5", Username: "someone"},
		},
		"a GitHub identifier larger than the column holds": {
			oauth.GitHub, providertest.Identity{ID: "99999999999", Username: "someone"},
		},
		"a GitHub account with no name": {
			oauth.GitHub, providertest.Identity{ID: "12345", Username: ""},
		},
	}

	for what, given := range unusable {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)

			started := service.StartLogin(given.provider, service.Site.ApplicationID, service.Site.CallbackURI)
			response := service.FinishLogin(started, given.identity)

			if response.Cookie(service.SessionCookieName()) != nil {
				t.Error("the browser was signed in")
			}

			service.GET("/me").ExpectStatus(http.StatusForbidden)
		})
	}
}

// Two callbacks arriving at once for the same person who has never signed in
// before produce one account, not two. Whichever insert loses reads the row the
// winner wrote instead of failing or creating a duplicate.
func TestArrivingTwiceAtOnceCreatesOneAccount(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	identity := service.Providers.Someone(oauth.Discord, "someone arriving twice at once")

	// Both logins are started before either is finished, so the two callbacks
	// reach the account lookup together.
	first := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
	second := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	var wait sync.WaitGroup

	wait.Add(2)

	for _, started := range []servertest.Authorization{first, second} {
		go func() {
			defer wait.Done()

			service.FinishLogin(started, identity)
		}()
	}

	wait.Wait()

	// Counted for this person alone: the site registers an owner of its own
	// when the service starts, and that account is not what this is about.
	var people int64
	if err := service.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM "User" WHERE username = $1`, identity.Username).Scan(&people); err != nil {
		t.Fatalf("counting the accounts the callbacks left behind: %v", err)
	}

	if people != 1 {
		t.Errorf("%d accounts exist for one person, want 1", people)
	}
}
