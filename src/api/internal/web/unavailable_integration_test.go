//go:build integration && !devtools

package web_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// A request this service cannot answer is refused, and the refusal says only
// that. Nothing is served from a credential, a session or an ownership check
// that could not be verified, and nothing about the failure reaches the caller.
func TestNothingIsAnsweredWhenDatabaseCannotBeReached(t *testing.T) {
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

// A database that answers but holds no schema is what a service started without
// its deployment's migration finds. Everything presented to it below is genuine
// and was accepted a moment earlier, and still nothing is granted and nothing
// about the database reaches the caller.
func TestNothingIsGrantedWhenSchemaIsEmpty(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("someone")

	application := service.RegisterApplication("an application", externalCallbackURI)
	identifier := application.ID.String()

	credentials := map[string]string{
		"id":            identifier,
		"refresh_token": application.RefreshToken,
	}

	var person, relying struct {
		Token string `json:"token"`
	}

	service.POSTJSON("/login", credentials,
		servertest.Header("exchange-token", signInToApplication(t, service, application, externalCallbackURI)),
	).ExpectStatus(http.StatusOK).DecodeInto(&person)

	service.POSTJSON("/developer_application/login", credentials).
		ExpectStatus(http.StatusOK).DecodeInto(&relying)

	unspent := signInToApplication(t, service, application, externalCallbackURI)

	// Started last, because every login started replaces the browser's binding.
	pending := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	service.GET("/me").ExpectStatus(http.StatusOK)
	service.GET("/me", servertest.Bearer(person.Token)).ExpectStatus(http.StatusOK)
	service.GET("/developer_application/me", servertest.Bearer(relying.Token)).ExpectStatus(http.StatusOK)

	testdatabase.Execute(t, service.Pool, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`)

	// Signing out is last: were it to clear the session cookie, every request
	// after it would be refused for a missing credential instead.
	refusals := []struct {
		what  string
		drive func() *servertest.Response
	}{
		{"identifying the signed-in browser", func() *servertest.Response {
			return service.GET("/me")
		}},
		{"identifying a person by token", func() *servertest.Response {
			return service.GET("/me", servertest.Bearer(person.Token))
		}},
		{"identifying an application by token", func() *servertest.Response {
			return service.GET("/developer_application/me", servertest.Bearer(relying.Token))
		}},
		{"listing someone's applications", func() *servertest.Response {
			return service.GET("/user/applications")
		}},
		{"spending a one-time code", func() *servertest.Response {
			return service.POSTJSON("/login", credentials, servertest.Header("exchange-token", unspent))
		}},
		{"withdrawing a genuine token", func() *servertest.Response {
			return service.POSTJSON("/burn-token", map[string]string{"token": person.Token})
		}},
		{"authenticating an application", func() *servertest.Response {
			return service.POSTJSON("/developer_application/login", credentials)
		}},
		{"reading an application", func() *servertest.Response {
			return service.GET("/developer_application/" + identifier)
		}},
		{"registering an application", func() *servertest.Response {
			return service.POSTJSON("/developer_application",
				map[string]string{"name": "another"}, service.Protected)
		}},
		{"replacing an application's credential", func() *servertest.Response {
			return service.PATCHJSON("/developer_application/"+identifier+"/reset_token", nil, service.Protected)
		}},
		{"replacing an application's callbacks", func() *servertest.Response {
			return service.PATCHJSON("/developer_application/"+identifier+"/callback_uris",
				[]string{externalCallbackURI}, service.Protected)
		}},
		{"deleting an application", func() *servertest.Response {
			return service.DELETE("/developer_application/"+identifier, service.Protected)
		}},
		{"starting a login", func() *servertest.Response {
			return service.GET("/ui/discord/authorize?" + url.Values{
				"application_id": {identifier},
				"callback_uri":   {externalCallbackURI},
			}.Encode())
		}},
		{"signing out", func() *servertest.Response {
			return service.POSTJSON("/ui/logout", nil, service.Protected)
		}},
	}

	for _, refusal := range refusals {
		t.Run(refusal.what, func(t *testing.T) {
			response := refusal.drive().
				ExpectStatus(http.StatusInternalServerError).
				ExpectDetail("Internal Server Error")

			expectNoDatabaseDetail(t, response)

			if cookie := response.Cookie(service.SessionCookieName()); cookie != nil && cookie.Value != "" {
				t.Error("a session cookie was set by a request the service could not check")
			}
		})
	}

	t.Run("returning from a provider", func(t *testing.T) {
		returned := service.FinishLogin(pending, service.Providers.Someone(oauth.Discord, "someone"))

		if returned.Status == http.StatusOK || returned.Status == http.StatusTemporaryRedirect {
			t.Errorf("a callback the service could not check answered %d", returned.Status)
		}

		if returned.Cookie(service.SessionCookieName()) != nil {
			t.Error("a browser was signed in by a callback the service could not check")
		}

		expectNoDatabaseDetail(t, returned)
	})

	// The route root reads nothing, so it still answers: the refusals above are
	// the database's, not a service that stopped.
	service.GET("/").ExpectStatus(http.StatusTemporaryRedirect)
}

// expectNoDatabaseDetail fails the test if a response names anything the
// database said.
func expectNoDatabaseDetail(t *testing.T, response *servertest.Response) {
	t.Helper()

	body := strings.ToLower(string(response.Body))

	for _, detail := range []string{"relation", "does not exist", "sqlstate", "auth_epoch", "schema"} {
		if strings.Contains(body, detail) {
			t.Errorf("the response carries database detail %q: %s", detail, response.Body)
		}
	}
}

// The service refuses a token it cannot check against the database rather than
// accepting it on the strength of its signature alone.
func TestTokenIsNotAcceptedOnItsSignatureAlone(t *testing.T) {
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

// A login started for an application that is deleted before the person returns
// cannot be completed, and says nothing about why.
func TestLoginForApplicationThatIsGoneCannotBeFinished(t *testing.T) {
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
func TestApplicationThatNeverExistedIsRefusedLikeOneSomebodyElseOwns(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("someone")

	service.GET("/developer_application/" + uuid.New().String()).
		ExpectStatus(http.StatusNotFound)
}
