//go:build integration

package web_test

import (
	"net/http"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The entry point reads nothing from the URL. A person arrives at it with a
// session or without one, and either way ends up at the site.
func TestTheEntryPointRedeemsNothingFromTheURL(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	for _, path := range []string{"/ui", "/ui/", "/ui/?code=stolen&authentication=stolen"} {
		response := service.GET(path).
			ExpectStatus(http.StatusTemporaryRedirect).
			ExpectRedirectTo(servertest.SiteOrigin)

		if response.Cookie(service.SessionCookieName()) != nil {
			t.Errorf("%s signed a browser in", path)
		}
	}
}

func TestASignedInBrowserIsSentOnToTheSite(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	service.GET("/ui/").
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(servertest.SiteOrigin)

	if service.CookieValue(service.SessionCookieName()) == "" {
		t.Error("a signed-in browser lost its session by arriving at the entry point")
	}
}

// A session value that means nothing here is cleared, so the browser stops
// sending it.
func TestASessionThisServiceDoesNotKnowIsCleared(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	response := service.GET("/ui/", servertest.Header("Cookie", service.SessionCookieName()+"=not-a-session")).
		ExpectStatus(http.StatusTemporaryRedirect)

	cleared := response.Cookie(service.SessionCookieName())
	if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Errorf("the session cookie was not cleared: %+v", cleared)
	}
}

// A request that changes something has to come from the site and carry the
// token only the site can read. The cookie arriving on its own is not enough:
// another site can cause that.
func TestChangingSomethingNeedsTheSitesOwnConfirmation(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	unconfirmed := map[string]func(*http.Request){
		"with no origin and no token": func(*http.Request) {},
		"with the token but no origin": func(request *http.Request) {
			request.Header.Set("X-CSRF-Token", service.CookieValue(service.CSRFCookieName()))
		},
		"from another site": func(request *http.Request) {
			request.Header.Set("Origin", "https://elsewhere.example.test")
			request.Header.Set("X-CSRF-Token", service.CookieValue(service.CSRFCookieName()))
		},
		"with a token that is not the one in the cookie": func(request *http.Request) {
			request.Header.Set("Origin", servertest.SiteOrigin)
			request.Header.Set("X-CSRF-Token", "not-the-token")
		},
	}

	for name, prepare := range unconfirmed {
		t.Run(name, func(t *testing.T) {
			service.POSTJSON("/developer_application", map[string]string{"name": "unconfirmed"}, prepare).
				ExpectStatus(http.StatusForbidden).
				ExpectDetail("This request could not be confirmed as coming from the AbandonAuth site")
		})
	}

	if names := listedApplications(t, service); len(names) != 0 {
		t.Errorf("an unconfirmed request registered %v", names)
	}
}

// Reading something does not need the token: a request that changes nothing is
// not what the check exists for.
func TestReadingDoesNotNeedTheToken(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	service.GET("/user/applications").ExpectStatus(http.StatusOK)
	service.GET("/me").ExpectStatus(http.StatusOK)
}

// Logging out ends the session here before the cookies are cleared, so a copy
// of the cookie taken beforehand is worth nothing afterwards.
func TestLoggingOutEndsTheSessionForACopiedCookieToo(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	copied := service.CookieValue(service.SessionCookieName())
	if copied == "" {
		t.Fatal("the browser was not signed in")
	}

	response := service.POSTJSON("/ui/logout", nil, service.Protected).ExpectStatus(http.StatusOK)

	for _, name := range []string{service.SessionCookieName(), service.CSRFCookieName()} {
		cleared := response.Cookie(name)
		if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
			t.Errorf("%s was not cleared: %+v", name, cleared)
		}
	}

	service.GET("/me", servertest.Header("Cookie", service.SessionCookieName()+"="+copied)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")

	service.GET("/me").ExpectStatus(http.StatusForbidden)
}

// Logging out changes something, so it is subject to the same confirmation as
// everything else that does.
func TestLoggingOutNeedsTheSitesOwnConfirmation(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	service.POSTJSON("/ui/logout", nil, func(request *http.Request) {
		request.Header.Set("X-CSRF-Token", service.CookieValue(service.CSRFCookieName()))
	}).ExpectStatus(http.StatusForbidden)

	service.GET("/me").ExpectStatus(http.StatusOK)
}

// The token has to be sent even when there is no session, so that a request
// without one is refused for the same reason whether or not it was signed in.
func TestLoggingOutWithoutASessionIsRefused(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/ui/logout", nil, func(request *http.Request) {
		request.Header.Set("Origin", servertest.SiteOrigin)
		request.Header.Set("X-CSRF-Token", "not-a-token")
	}).ExpectStatus(http.StatusForbidden)

	service.POSTJSON("/ui/logout", nil).ExpectRejectedInput("header", "x-csrf-token")
}
