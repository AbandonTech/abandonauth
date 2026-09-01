//go:build integration

package web_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// sweepAll runs every expiry sweep once and reports how many records each
// removed, keyed by what it removes.
func sweepAll(t *testing.T, service *servertest.Service) map[string]int64 {
	t.Helper()

	removed := make(map[string]int64)

	for _, sweep := range service.ExpiredRecordSweeps() {
		count, err := sweep.Forget(t.Context())
		if err != nil {
			t.Fatalf("sweeping %s: %v", sweep.Records, err)
		}

		removed[sweep.Records] = count
	}

	return removed
}

// The safety property the sweeps rest on: they remove only what has expired, so
// a person signed in and a login half-finished are untouched by one running.
func TestTidyingUpLeavesEverythingStillInUse(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.SignInSomeone("someone")

	// A login that has been started and not yet returned from.
	service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	for records, count := range sweepAll(t, service) {
		if count != 0 {
			t.Errorf("tidying up removed %d %s that had not expired", count, records)
		}
	}

	// The strongest statement of the same thing: the browser is still signed in.
	service.GET("/me").ExpectStatus(http.StatusOK)
}

// A one-time code that was never spent does not sit in the database for ever.
func TestTidyingUpRemovesCodesNobodySpent(t *testing.T) {
	t.Parallel()

	// The shortest lifetime the service accepts. The session lifetime is left
	// alone, because signing in is how the application below gets registered.
	service := servertest.New(t, servertest.WithSetting(func(settings *config.Settings) {
		settings.ExchangeCodeSeconds = 1
	}))

	service.SignInSomeone("someone")

	application := service.RegisterApplication("somebody else's", "https://elsewhere.example.test/return")

	// An application that is not the site is answered with a one-time code
	// rather than a session, which is the record this is about.
	started := service.StartLogin(oauth.GitHub, application.ID, application.CallbackURIs[0])
	returned := service.FinishLogin(started, service.Providers.Someone(oauth.GitHub, "someone else")).
		ExpectStatus(http.StatusTemporaryRedirect)

	sentTo, err := url.Parse(returned.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the browser was sent to something that is not a URL: %v", err)
	}

	if sentTo.Query().Get("code") == "" {
		t.Fatal("the application was given no one-time code, so there is none to expire")
	}

	// Expiry is measured by the database, so this waits for it rather than
	// rewriting a row to look old.
	time.Sleep(1100 * time.Millisecond)

	if removed := sweepAll(t, service)["one-time codes"]; removed == 0 {
		t.Error("tidying up removed no one-time codes, though one had expired")
	}
}

// A session nobody signed out of is removed once it has reached its expiry.
func TestTidyingUpRemovesSessionsThatHaveRunOut(t *testing.T) {
	t.Parallel()

	service := servertest.New(t, servertest.WithSetting(func(settings *config.Settings) {
		settings.BrowserSessionSeconds = 1
	}))

	// Signing in is the last thing that happens before the wait, so nothing
	// else has to complete inside the session's lifetime.
	service.SignInSomeone("someone")

	time.Sleep(1100 * time.Millisecond)

	if removed := sweepAll(t, service)["browser sessions"]; removed == 0 {
		t.Error("tidying up removed no browser sessions, though one had expired")
	}

	// The session was already refused by its expiry; it is now also gone.
	service.GET("/me").ExpectStatus(http.StatusForbidden)
}
