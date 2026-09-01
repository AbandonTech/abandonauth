//go:build integration

package web_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// A request this service cannot answer is refused, and the refusal says only
// that. Nothing is served from a credential, a session or an ownership check
// that could not be verified, and nothing about the failure reaches the caller.
func TestNothingIsAnsweredWhenTheDatabaseCannotBeReached(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	// Everything below is driven as a signed-in person holding real
	// credentials, so what refuses the request is the missing database rather
	// than a missing credential.
	service.SignInSomeone("someone")

	application := service.RegisterApplication("an application", externalCallbackURI)

	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	identifier := application.ID.String()

	// From here the service has no database.
	service.Pool.Close()

	credentials := map[string]string{
		"id":            identifier,
		"refresh_token": application.RefreshToken,
	}

	refusals := map[string]func() *servertest.Response{
		"identifying the signed-in person": func() *servertest.Response {
			return service.GET("/me")
		},
		"listing someone's applications": func() *servertest.Response {
			return service.GET("/user/applications")
		},
		"spending a one-time code": func() *servertest.Response {
			return service.POSTJSON("/login", credentials, servertest.Header("exchange-token", "a-code"))
		},
		"withdrawing a credential": func() *servertest.Response {
			return service.POSTJSON("/burn-token", map[string]string{"token": "a-token"})
		},
		"registering an application": func() *servertest.Response {
			return service.POSTJSON("/developer_application",
				map[string]string{"name": "another"}, service.Protected)
		},
		"authenticating an application": func() *servertest.Response {
			return service.POSTJSON("/developer_application/login", credentials)
		},
		"reading an application": func() *servertest.Response {
			return service.GET("/developer_application/" + identifier)
		},
		"deleting an application": func() *servertest.Response {
			return service.DELETE("/developer_application/"+identifier, service.Protected)
		},
		"replacing an application's credential": func() *servertest.Response {
			return service.PATCHJSON("/developer_application/"+identifier+"/reset_token", nil, service.Protected)
		},
		"replacing an application's callbacks": func() *servertest.Response {
			return service.PATCHJSON("/developer_application/"+identifier+"/callback_uris",
				[]string{externalCallbackURI}, service.Protected)
		},
		"starting a login": func() *servertest.Response {
			return service.GET("/ui/discord/authorize?" + url.Values{
				"application_id": {identifier},
				"callback_uri":   {externalCallbackURI},
			}.Encode())
		},
		"signing out": func() *servertest.Response {
			return service.POSTJSON("/ui/logout", nil, service.Protected)
		},
	}

	for what, drive := range refusals {
		t.Run(what, func(t *testing.T) {
			drive().
				ExpectStatus(http.StatusInternalServerError).
				ExpectDetail("Internal Server Error")
		})
	}

	// Returning from a provider is the one journey that answers with a redirect
	// rather than a body, so it is stated separately: the person is sent back
	// to where they came from and is signed in to nothing.
	t.Run("returning from a provider", func(t *testing.T) {
		returned := service.FinishLogin(started, service.Providers.Someone(oauth.Discord, "someone"))

		if returned.Status == http.StatusOK {
			t.Errorf("a callback the service could not record answered %d", returned.Status)
		}

		if returned.Cookie(service.SessionCookieName()) != nil {
			t.Error("a browser was signed in by a callback the service could not record")
		}
	})
}

// The service refuses a token it cannot check against the database rather than
// accepting it on the strength of its signature alone.
func TestATokenIsNotAcceptedOnItsSignatureAlone(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("someone")

	application := service.RegisterApplication("an application")

	var issued struct {
		Token string `json:"token"`
	}

	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}).ExpectStatus(http.StatusOK).DecodeInto(&issued)

	// The token is genuine and unexpired; only the database is gone.
	service.Pool.Close()

	service.GET("/developer_application/me", servertest.Bearer(issued.Token)).
		ExpectStatus(http.StatusInternalServerError).
		ExpectDetail("Internal Server Error")
}

// Every route the service declares can be looked up by name, which is what lets
// a handler be attached to one and a test name one without repeating its URL.
func TestARouteIsFoundByName(t *testing.T) {
	t.Parallel()

	if _, found := web.Lookup(web.RouteCurrentUser); !found {
		t.Error("a declared route could not be found by its name")
	}

	if _, found := web.Lookup(web.RouteName("no-such-route")); found {
		t.Error("a name no route carries was found anyway")
	}
}

// A login started for an application that is deleted before the person returns
// cannot be completed, and says nothing about why.
func TestALoginForAnApplicationThatIsGoneCannotBeFinished(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the owner")

	application := service.RegisterApplication("an application", externalCallbackURI)

	started := service.StartLogin(oauth.GitHub, application.ID, externalCallbackURI)

	service.DELETE("/developer_application/"+application.ID.String(), service.Protected).
		ExpectStatus(http.StatusOK)

	returned := service.FinishLogin(started, service.Providers.Someone(oauth.GitHub, "someone"))

	if returned.Status == http.StatusTemporaryRedirect {
		if location := returned.Header.Get("Location"); location != "" {
			if sentTo, err := url.Parse(location); err == nil && sentTo.Query().Get("code") != "" {
				t.Error("a one-time code was issued for an application that no longer exists")
			}
		}
	}

	if returned.Cookie(service.SessionCookieName()) != nil {
		t.Error("a browser was signed in through an application that no longer exists")
	}
}

// An application identifier that is well formed but names nothing is refused
// the same way one that belongs to somebody else is.
func TestAnApplicationThatNeverExistedIsRefusedLikeOneSomebodyElseOwns(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("someone")

	service.GET("/developer_application/" + uuid.New().String()).
		ExpectStatus(http.StatusNotFound)
}
