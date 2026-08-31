//go:build integration

package web_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// Where each provider is asked to sign a person in. A test that let the service
// name its own destination would not notice it naming somewhere else.
var providerAuthorizationEndpoints = map[oauth.Provider]string{
	oauth.Discord: "https://discord.com/oauth2/authorize",
	oauth.GitHub:  "https://github.com/login/oauth/authorize",
	oauth.Google:  "https://accounts.google.com/o/oauth2/v2/auth",
}

// A login sends the browser to the provider's own published address, carrying
// an opaque state and a challenge the provider cannot reverse.
func TestALoginIsStartedAtTheProvidersOwnAddress(t *testing.T) {
	t.Parallel()

	for provider, endpoint := range providerAuthorizationEndpoints {
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			started := service.StartLogin(provider, service.Site.ApplicationID, service.Site.CallbackURI)

			sentTo, err := url.Parse(started.AuthorizationURL)
			if err != nil {
				t.Fatalf("the browser was sent to something that is not a URL: %v", err)
			}

			if before, _, _ := strings.Cut(started.AuthorizationURL, "?"); before != endpoint {
				t.Errorf("the browser was sent to %q, want %q", before, endpoint)
			}

			query := sentTo.Query()

			if query.Get("response_type") != "code" {
				t.Errorf("response_type = %q", query.Get("response_type"))
			}

			if query.Get("code_challenge_method") != "S256" {
				t.Errorf("code_challenge_method = %q, want S256", query.Get("code_challenge_method"))
			}

			if len(query.Get("code_challenge")) < 32 {
				t.Errorf("code_challenge = %q, want a digest", query.Get("code_challenge"))
			}

			if len(query.Get("state")) < 32 {
				t.Errorf("state = %q, want an unguessable value", query.Get("state"))
			}

			if provider == oauth.Google && len(query.Get("nonce")) < 32 {
				t.Errorf("nonce = %q, want an unguessable value", query.Get("nonce"))
			}
		})
	}
}

// The state alone is not authority to finish a login: the browser that started
// it is given a cookie that no other site can read or send.
func TestStartingALoginBindsItToTheBrowser(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	binding := started.Response.Cookie(service.LoginCookieName())
	if binding == nil {
		t.Fatalf("no %s cookie was set", service.LoginCookieName())
	}

	if !strings.HasPrefix(binding.Name, "__Host-") {
		t.Errorf("cookie name = %q, want the __Host- prefix over TLS", binding.Name)
	}

	if !binding.HttpOnly || !binding.Secure || binding.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie attributes = %+v, want HttpOnly, Secure and SameSite=Lax", binding)
	}

	if binding.Path != "/" || binding.Domain != "" {
		t.Errorf("cookie scope = path %q domain %q, want the whole host and no domain", binding.Path, binding.Domain)
	}

	if binding.MaxAge != int(oauth.StateLifetime.Seconds()) {
		t.Errorf("cookie Max-Age = %d, want %v", binding.MaxAge, oauth.StateLifetime)
	}

	if binding.Value == started.State {
		t.Error("the cookie is the state value, so the state alone would be enough to finish the login")
	}
}

// A login may only name a callback the application registered, and being told
// no says nothing about which of the two was wrong.
func TestALoginOnlyNamesARegisteredCallback(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	refusals := map[string]string{
		"a callback the application did not register":  "https://elsewhere.example.test/callback",
		"a callback that is nearly the registered one": service.Site.CallbackURI + "?extra=1",
		"no callback at all":                           "",
	}

	for name, callback := range refusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := service.GET("/ui/discord/authorize?" + url.Values{
				"application_id": {service.Site.ApplicationID.String()},
				"callback_uri":   {callback},
			}.Encode())

			response.ExpectStatus(http.StatusForbidden).
				ExpectDetail("Invalid application ID or callback_uri")
		})
	}
}

// An application nobody registered is refused in the same words as a callback
// that was not registered, so the endpoint does not say which applications
// exist.
func TestALoginForAnUnknownApplicationIsRefusedTheSameWay(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/ui/discord/authorize?" + url.Values{
		"application_id": {uuid.New().String()},
		"callback_uri":   {service.Site.CallbackURI},
	}.Encode()).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid application ID or callback_uri")
}

// The providers a person may sign in with are fixed. Anything else is refused
// as an input, before an application or a callback is read.
func TestALoginNamesAProviderThisServiceOffers(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/ui/somewhere-else/authorize?"+url.Values{
		"application_id": {service.Site.ApplicationID.String()},
		"callback_uri":   {service.Site.CallbackURI},
	}.Encode()).
		ExpectRejectedInput("path", "provider")
}

func TestALoginNeedsAnApplicationAndACallback(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/ui/discord/authorize").
		ExpectRejectedInput("query", "application_id").
		ExpectRejectedInput("query", "callback_uri")

	service.GET("/ui/discord/authorize?application_id=not-an-identifier&callback_uri=x").
		ExpectRejectedInput("query", "application_id")
}

// Two logins started from the same browser are independent. Finishing the
// second must not make the first impossible to finish, which is what a person
// with two tabs open does.
func TestTwoLoginsFromOneBrowserAreIndependent(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	first := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
	second := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	if first.State == second.State {
		t.Fatal("two logins were given the same state")
	}

	service.FinishLogin(second, service.Providers.Someone(oauth.Discord, "the second tab")).
		ExpectStatus(http.StatusTemporaryRedirect)

	service.FinishLogin(first, service.Providers.Someone(oauth.Discord, "the first tab")).
		ExpectStatus(http.StatusTemporaryRedirect)
}

// Every way of arriving at a callback without the login this service started
// gets the same answer, so a caller cannot tell which of them it was.
func TestALoginThisServiceDidNotStartCannotBeFinished(t *testing.T) {
	t.Parallel()

	refusals := map[string]func(service *servertest.Service) *servertest.Response{
		"a state value that was never issued": func(service *servertest.Service) *servertest.Response {
			return service.ReturnFromProvider(oauth.Discord, "an-authorization-code", "a-state-value")
		},
		"no state value at all": func(service *servertest.Service) *servertest.Response {
			return service.ReturnFromProvider(oauth.Discord, "an-authorization-code", "")
		},
		"a state value that has already been spent": func(service *servertest.Service) *servertest.Response {
			started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
			service.FinishLogin(started, service.Providers.Someone(oauth.Discord, "someone")).
				ExpectStatus(http.StatusTemporaryRedirect)

			return service.ReturnFromProvider(oauth.Discord, "another-code", started.State)
		},
		"a state value in a browser that did not start the login": func(
			service *servertest.Service,
		) *servertest.Response {
			started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
			service.Forget(service.LoginCookieName())

			return service.ReturnFromProvider(oauth.Discord, "an-authorization-code", started.State)
		},
		"a state value started with another provider": func(service *servertest.Service) *servertest.Response {
			started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

			return service.ReturnFromProvider(oauth.GitHub, "an-authorization-code", started.State)
		},
	}

	for name, attempt := range refusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)

			attempt(service).
				ExpectStatus(http.StatusForbidden).
				ExpectDetail("This login could not be matched to one that was started here")
		})
	}
}

// A person who declines at the provider comes back without a code. There is
// nothing to exchange, so they are simply returned to where they came from.
func TestALoginTheProviderDidNotCompleteReturnsTheBrowser(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	response := service.ReturnFromProvider(oauth.Discord, "", started.State).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(service.Site.CallbackURI)

	if response.Cookie(service.SessionCookieName()) != nil {
		t.Error("a browser that never signed in was given a session")
	}
}

// The authorization code has to be one the provider issued for this login, and
// the exchange has to prove possession of the verifier behind the challenge.
func TestALoginTheProviderRefusesDoesNotSignAnybodyIn(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	response := service.ReturnFromProvider(oauth.Discord, "not-a-code-the-provider-issued", started.State).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("This login could not be matched to one that was started here")

	if response.Cookie(service.SessionCookieName()) != nil {
		t.Error("a refused login was given a session")
	}
}
