//go:build integration

package web_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// registeredCallback is spelled the way an application registered it: a host in
// mixed case, a case-sensitive path, and a query whose escaping the application
// chose. Every byte of it must survive to the redirect the browser follows.
const registeredCallback = "https://App.Example.TEST/Return/Callback?tenant=Acme&next=%2FHome%3Fa%3Db"

// An application matches the redirect it receives against the string it
// registered, so the browser is returned to that string and not to a rewrite of
// it that happens to address the same resource.
func TestACompletedLoginReturnsTheBrowserToTheRegisteredSpelling(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	application := service.RegisterApplication("an application", registeredCallback)

	started := service.StartLogin(oauth.Discord, application.ID, registeredCallback)

	response := service.FinishLogin(started, service.Providers.Someone(oauth.Discord, "someone")).
		ExpectStatus(http.StatusTemporaryRedirect)

	location := response.Header.Get("Location")

	want := registeredCallback + "&code="
	if !strings.HasPrefix(location, want) {
		t.Fatalf("Location = %q, want it to begin with %q", location, want)
	}

	// Exactly one parameter is added. A second would let an application read the
	// wrong one of two values under the same key.
	code := strings.TrimPrefix(location, want)
	if code == "" || strings.ContainsAny(code, "&?#") {
		t.Errorf("the added code is %q, want one encoded value", code)
	}

	query, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the browser was sent to something that is not a URL: %v", err)
	}

	values := query.Query()
	if got := values["next"]; len(got) != 1 || got[0] != "/Home?a=b" {
		t.Errorf("next decoded to %v, want [/Home?a=b]", got)
	}

	if got := values["tenant"]; len(got) != 1 || got[0] != "Acme" {
		t.Errorf("tenant decoded to %v, want [Acme]", got)
	}
}

// Declining at the provider ends the login with nothing to exchange, and the
// browser goes back to the same exact address a completed login would use.
func TestADeclinedLoginReturnsTheBrowserToTheRegisteredSpelling(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	application := service.RegisterApplication("an application", registeredCallback)

	started := service.StartLogin(oauth.Discord, application.ID, registeredCallback)

	service.ReturnFromProvider(oauth.Discord, "", started.State).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(registeredCallback)
}

// A stored callback is re-checked against the policy before a browser is sent
// to it. The registration that stored it passed, but the policy is what decides
// where a browser goes, and it is applied at the moment of the redirect rather
// than trusted from when the row was written.
func TestALoginWhoseStoredCallbackNoLongerPassesEndsWithoutARedirect(t *testing.T) {
	t.Parallel()

	endings := map[string]func(*servertest.Service, servertest.Authorization) *servertest.Response{
		"the person declined at the provider": func(
			service *servertest.Service, started servertest.Authorization,
		) *servertest.Response {
			return service.ReturnFromProvider(oauth.Discord, "", started.State)
		},
		"the person signed in": func(
			service *servertest.Service, started servertest.Authorization,
		) *servertest.Response {
			return service.FinishLogin(started, service.Providers.Someone(oauth.Discord, "someone"))
		},
	}

	for name, ending := range endings {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			service.SignInSomeone("the developer")

			application := service.RegisterApplication("an application", registeredCallback)
			started := service.StartLogin(oauth.Discord, application.ID, registeredCallback)

			// http off the loopback interface is refused, and no registration
			// could have stored it. Nothing but the stored row is changed.
			if _, err := service.Pool.Exec(
				t.Context(),
				`UPDATE oauth_authorization_state SET callback_uri = $1`,
				"http://elsewhere.test/callback",
			); err != nil {
				t.Fatalf("rewriting the stored callback: %v", err)
			}

			response := ending(service, started).ExpectStatus(http.StatusForbidden)

			if location := response.Header.Get("Location"); location != "" {
				t.Errorf("a browser was sent to %q", location)
			}

			if response.Cookie(service.SessionCookieName()) != nil {
				t.Error("a login that could not be returned was given a session")
			}
		})
	}
}

// A callback is registered as one exact string. Another spelling of the same
// address is not that string, and starting a login with it is refused.
func TestALoginCannotBeStartedWithAnotherSpellingOfTheCallback(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	application := service.RegisterApplication("an application", registeredCallback)

	spellings := map[string]string{
		"lower cased throughout": strings.ToLower(registeredCallback),
		"a lower cased host":     "https://app.example.test/Return/Callback?tenant=Acme&next=%2FHome%3Fa%3Db",
		"a trailing slash":       registeredCallback + "/",
		"the query re-encoded":   "https://App.Example.TEST/Return/Callback?tenant=Acme&next=/Home?a=b",
	}

	for name, spelling := range spellings {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service.GET("/ui/discord/authorize?" + url.Values{
				"application_id": {application.ID.String()},
				"callback_uri":   {spelling},
			}.Encode()).ExpectStatus(http.StatusForbidden)
		})
	}
}
