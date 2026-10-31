//go:build integration && !devtools

package web_test

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// Where each provider is asked to sign a person in. A test that let the service
// name its own destination would not notice it naming somewhere else.
var providerAuthorizationEndpoints = map[oauth.Provider]string{
	oauth.Discord: "https://discord.com/oauth2/authorize",
	oauth.GitHub:  "https://github.com/login/oauth/authorize",
	oauth.Google:  "https://accounts.google.com/o/oauth2/v2/auth",
	oauth.Steam:   "https://steamcommunity.com/openid/login",
}

// A login sends the browser to the provider's own published address, carrying
// an opaque state. An OAuth provider is also sent a challenge it cannot
// reverse; Steam is sent the exact OpenID 2.0 request, with the state inside
// the address it is to return the browser to.
func TestLoginIsStartedAtProvidersOwnAddress(t *testing.T) {
	t.Parallel()

	if len(providerAuthorizationEndpoints) != len(oauth.Providers) {
		t.Fatalf("%d providers are offered and %d have a stated address", len(oauth.Providers), len(providerAuthorizationEndpoints))
	}

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

			if len(started.State) < 32 {
				t.Errorf("state = %q, want an unguessable value", started.State)
			}

			if provider == oauth.Steam {
				expectSteamAuthorizationRequest(t, sentTo.Query(), started.State)

				return
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

			if provider == oauth.Google && len(query.Get("nonce")) < 32 {
				t.Errorf("nonce = %q, want an unguessable value", query.Get("nonce"))
			}
		})
	}
}

// expectSteamAuthorizationRequest requires exactly the OpenID 2.0 request this
// service makes of Steam: identifier selection, the site's root as the realm,
// and a return address that is the configured callback with the state
// appended. Nothing an OAuth provider is sent, and no secret, is among it.
func expectSteamAuthorizationRequest(t *testing.T, query url.Values, state string) {
	t.Helper()

	want := map[string]string{
		"openid.ns":         "http://specs.openid.net/auth/2.0",
		"openid.mode":       "checkid_setup",
		"openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
		"openid.identity":   "http://specs.openid.net/auth/2.0/identifier_select",
		"openid.realm":      servertest.SiteOrigin + "/",
		"openid.return_to":  servertest.SiteOrigin + "/api/ui/steam-callback?" + url.Values{"state": {state}}.Encode(),
	}

	if len(query) != len(want) {
		t.Errorf("Steam was sent %d parameters, want exactly %d", len(query), len(want))
	}

	for name, value := range want {
		if sent := query[name]; len(sent) != 1 || sent[0] != value {
			t.Errorf("%s = %q, want %q", name, sent, value)
		}
	}
}

// The state alone is not authority to finish a login: the browser that started
// it is given a cookie that no other site can read or send.
func TestStartingLoginBindsItToBrowser(t *testing.T) {
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
func TestLoginOnlyNamesRegisteredCallback(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	refusals := map[string]string{
		"a callback the application did not register":  "https://elsewhere.example.test/callback",
		"a callback that is nearly the registered one": service.Site.CallbackURI + "?extra=1",
		"no callback at all":                           "",
		"the site's origin without the API's path":     servertest.SiteOrigin + "/ui",
		"the API's origin rather than the site's":      servertest.APIOrigin + "/api/ui",
	}

	for name, callback := range refusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := service.GET("/ui/discord/authorize?" + url.Values{
				"application_id": {service.Site.ApplicationID.String()},
				"callback_uri":   {callback},
			}.Encode())

			response.ExpectStatus(http.StatusForbidden).
				ExpectDetail("Invalid application ID or callback URI")
		})
	}

	// The positive control: the one spelling the site registered is accepted,
	// so the refusals above are refusals of the callback and not of everything.
	service.GET("/ui/discord/authorize?" + url.Values{
		"application_id": {service.Site.ApplicationID.String()},
		"callback_uri":   {service.Site.CallbackURI},
	}.Encode()).ExpectStatus(http.StatusTemporaryRedirect)
}

// A callback target spelled a way this service does not serve reaches nothing
// and does not spend the login it names.
func TestCallbackSpelledAnotherWaySpendsNoLogin(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	query := "?" + url.Values{
		"code":  {"a-code-the-provider-never-issued"},
		"state": {started.State},
	}.Encode()

	spellings := []string{
		"/ui/discord-callback",
		"/api//ui/discord-callback",
		"/api/ui/../ui/discord-callback",
		"/api/ui/%2e%2e/ui/discord-callback",
		"/api/ui%2fdiscord-callback",
		"/api/ui/discord-callback/",
	}

	for _, target := range spellings {
		service.AtExactTarget(http.MethodGet, target+query).
			ExpectStatus(http.StatusNotFound)
	}

	service.FinishLogin(
		started,
		service.Providers.Someone(oauth.Discord, "the person who really came back"),
	).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(service.Site.CallbackURI)
}

// The same holds for Steam's callback, carrying a genuine assertion: no other
// spelling spends the login or asks Steam anything, and the assertion still
// finishes the login at the one address that is served.
func TestSteamCallbackSpelledAnotherWaySpendsNoLogin(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)

	assertion := service.Providers.Issue(oauth.Steam, providertest.Grant{
		Identity: service.Providers.Someone(oauth.Steam, "the person who really came back"),
		ReturnTo: started.ReturnTo,
	})

	query := "?" + url.Values{"state": {started.State}}.Encode() + "&" + assertion

	for _, target := range []string{
		"/ui/steam-callback",
		"/api//ui/steam-callback",
		"/api/ui/../ui/steam-callback",
		"/api/ui/%2e%2e/ui/steam-callback",
		"/api/ui%2fsteam-callback",
		"/api/ui/steam%2Dcallback",
		"/api/ui/steam-callback/",
	} {
		service.AtExactTarget(http.MethodGet, target+query).
			ExpectStatus(http.StatusNotFound)
	}

	expectSteamAskedNothing(t, service)

	service.ReturnFromProvider(oauth.Steam, assertion, started.State).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(service.Site.CallbackURI)
}

// An application nobody registered is refused with the same response as a
// callback that was not registered, so the endpoint does not say which
// applications exist.
func TestLoginForUnknownApplicationIsRefusedSameWay(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	unknown := service.GET("/ui/discord/authorize?" + url.Values{
		"application_id": {uuid.New().String()},
		"callback_uri":   {service.Site.CallbackURI},
	}.Encode()).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid application ID or callback URI")

	unregistered := service.GET("/ui/discord/authorize?" + url.Values{
		"application_id": {service.Site.ApplicationID.String()},
		"callback_uri":   {"https://elsewhere.example.test/callback"},
	}.Encode()).ExpectStatus(http.StatusForbidden)

	if !bytes.Equal(unknown.Body, unregistered.Body) {
		t.Errorf("an unknown application was refused as %s, an unregistered callback as %s",
			unknown.Body, unregistered.Body)
	}
}

// signInValidationFailure is the whole body of every refused callback once it
// has begun consuming login state.
const signInValidationFailure = `{"detail":"Sign-in validation failed"}` + "\n"

// expectSignInValidationFailed requires the one callback refusal: the same
// status and bytes, no redirect, and no session.
func expectSignInValidationFailed(t *testing.T, service *servertest.Service, response *servertest.Response) {
	t.Helper()

	response.ExpectStatus(http.StatusForbidden)

	if string(response.Body) != signInValidationFailure {
		t.Errorf("body = %s, want %s", response.Body, signInValidationFailure)
	}

	if response.Header.Get("Location") != "" {
		t.Error("a refused callback returned the browser somewhere")
	}

	if response.Cookie(service.SessionCookieName()) != nil {
		t.Error("a refused callback gave the browser a session")
	}
}

// The providers a person may sign in with are fixed. Anything else is refused
// as an input, before an application or a callback is read.
func TestLoginNamesProviderThisServiceOffers(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/ui/somewhere-else/authorize?"+url.Values{
		"application_id": {service.Site.ApplicationID.String()},
		"callback_uri":   {service.Site.CallbackURI},
	}.Encode()).
		ExpectRejectedInput("path", "provider")
}

func TestLoginNeedsApplicationAndCallback(t *testing.T) {
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
func TestLoginThisServiceDidNotStartCannotBeFinished(t *testing.T) {
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

			expectSignInValidationFailed(t, service, attempt(service))
		})
	}
}

// Once login state has been consumed, a provider that refuses the exchange, a
// provider identity that is incomplete and one this service cannot store are
// answered exactly as an unknown state is.
func TestCallbackValidationFailuresAreIndistinguishable(t *testing.T) {
	t.Parallel()

	failures := map[string]func(service *servertest.Service) *servertest.Response{
		"an authorization code the provider refuses": func(service *servertest.Service) *servertest.Response {
			started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

			return service.ReturnFromProvider(oauth.Discord, "not-a-code-the-provider-issued", started.State)
		},
		"a provider identity with no name": func(service *servertest.Service) *servertest.Response {
			started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

			return service.FinishLogin(started, providertest.Identity{ID: "4815162342", Username: ""})
		},
		"a provider identifier this service cannot store": func(service *servertest.Service) *servertest.Response {
			started := service.StartLogin(oauth.GitHub, service.Site.ApplicationID, service.Site.CallbackURI)

			return service.FinishLogin(started, providertest.Identity{ID: "-5", Username: "someone"})
		},
		"an unknown state": func(service *servertest.Service) *servertest.Response {
			return service.ReturnFromProvider(oauth.Discord, "an-authorization-code", "a-state-value")
		},
		"an assertion Steam does not verify": func(service *servertest.Service) *servertest.Response {
			started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
			assertion := service.Providers.Issue(oauth.Steam, providertest.Grant{
				Identity: service.Providers.Someone(oauth.Steam, "someone"),
				ReturnTo: started.ReturnTo,
			})

			return service.ReturnFromProvider(oauth.Steam,
				strings.Replace(assertion, "openid.sig=", "openid.sig=x", 1), started.State)
		},
		"a Steam callback that is not an assertion": func(service *servertest.Service) *servertest.Response {
			started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)

			return service.ReturnFromProvider(oauth.Steam, "openid.mode=id_res", started.State)
		},
	}

	for name, attempt := range failures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)

			expectSignInValidationFailed(t, service, attempt(service))
		})
	}
}

// A person who declines at the provider comes back without a code. There is
// nothing to exchange, so they are simply returned to where they came from and
// nobody is signed in.
//
// The login is spent all the same. Coming back a second time with a code the
// provider really would honour finds no login at all, so a declined attempt
// cannot be picked up later by whoever saw the state travel past.
func TestLoginNotCompletedByProviderIsOverForGood(t *testing.T) {
	t.Parallel()

	for _, provider := range oauth.Providers {
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			started := service.StartLogin(provider, service.Site.ApplicationID, service.Site.CallbackURI)

			declined := service.ReturnFromProvider(provider, "", started.State).
				ExpectStatus(http.StatusTemporaryRedirect).
				ExpectRedirectTo(service.Site.CallbackURI)

			if declined.Cookie(service.SessionCookieName()) != nil {
				t.Error("a browser that never signed in was given a session")
			}

			code := service.Providers.Issue(provider, providertest.Grant{
				Identity:  service.Providers.Someone(provider, "the person who declined"),
				Challenge: started.Challenge,
				Nonce:     started.Nonce,
				ReturnTo:  started.ReturnTo,
			})

			expectSignInValidationFailed(t, service, service.ReturnFromProvider(provider, code, started.State))
		})
	}
}

// returnAddress is the whole address a browser comes back from the provider to,
// carrying a fresh answer the provider would honour for the person: an
// authorization code, or for Steam a signed assertion.
func returnAddress(service *servertest.Service, started servertest.Authorization, person providertest.Identity) string {
	answer := service.Providers.Issue(started.Provider, providertest.Grant{
		Identity:  person,
		Challenge: started.Challenge,
		Nonce:     started.Nonce,
		ReturnTo:  started.ReturnTo,
	})

	address := service.EndpointURL(servertest.CallbackPath(started.Provider)) + "?"

	if started.Provider == oauth.Steam {
		return address + url.Values{"state": {started.State}}.Encode() + "&" + answer
	}

	return address + url.Values{"code": {answer}, "state": {started.State}}.Encode()
}

// boundCallback prepares a request to an address carrying the browser's login
// binding, as the browser that started the login would send it.
func boundCallback(t *testing.T, service *servertest.Service, address string) *http.Request {
	t.Helper()

	binding := service.CookieValue(service.LoginCookieName())
	if binding == "" {
		t.Fatal("the browser was given nothing that ties the login to it")
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, address, nil)
	if err != nil {
		t.Fatalf("preparing a callback request: %v", err)
	}

	request.AddCookie(&http.Cookie{Name: service.LoginCookieName(), Value: binding})

	return request
}

// A state value completes one login. Two callbacks arriving together with the
// same state, from the same browser, are not two sign-ins.
//
// Each carries an answer of its own that the provider would honour, so nothing
// on the provider's side can be what refuses the second: only the login state
// can. The site's own application is used, so a completed login ends in a
// session rather than in a code travelling in a URL.
func TestOneLoginStateCompletesAtMostOnce(t *testing.T) {
	t.Parallel()

	for _, provider := range []oauth.Provider{oauth.Discord, oauth.Steam} {
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()

			expectOneOfTwoCallbacksCompletes(t, provider)
		})
	}
}

func expectOneOfTwoCallbacksCompletes(t *testing.T, provider oauth.Provider) {
	t.Helper()

	service := servertest.New(t)
	started := service.StartLogin(provider, service.Site.ApplicationID, service.Site.CallbackURI)

	person := service.Providers.Someone(provider, "a person coming back twice at once")
	requests := make([]*http.Request, 0, 2)

	for range 2 {
		requests = append(requests, boundCallback(t, service, returnAddress(service, started, person)))
	}

	var completed, refused, signedIn int

	for _, answer := range concurrently(t, requests...) {
		switch answer.status {
		case http.StatusTemporaryRedirect:
			completed++

			if answer.location != service.Site.CallbackURI {
				t.Error("a completed login returned the browser somewhere it did not start")
			}

			if answer.cookie(service.SessionCookieName()) != nil {
				signedIn++
			}
		case http.StatusForbidden:
			refused++

			if string(answer.body) != signInValidationFailure {
				t.Error("a callback was refused with something other than the sign-in validation failure")
			}

			if answer.location != "" || answer.cookie(service.SessionCookieName()) != nil {
				t.Error("a refused callback returned the browser somewhere or gave it a session")
			}
		default:
			t.Errorf("a callback answered %d", answer.status)
		}
	}

	if completed != 1 || refused != 1 {
		t.Errorf("%d callbacks completed and %d were refused, want one of each", completed, refused)
	}

	if signedIn != 1 {
		t.Errorf("%d browsers were signed in, want one", signedIn)
	}

	if asked := service.Providers.SteamVerifications(); provider == oauth.Steam && asked != 1 {
		t.Errorf("Steam was asked to verify %d assertions for one login, want one", asked)
	}
}

// The authorization code has to be one the provider issued for this login, and
// the exchange has to prove possession of the verifier behind the challenge.
func TestLoginRefusedByProviderSignsNobodyIn(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

	expectSignInValidationFailed(t, service,
		service.ReturnFromProvider(oauth.Discord, "not-a-code-the-provider-issued", started.State))
}

// steamReturnTo is the address Steam is asked to return a browser to for a
// login state, which is what it signs into its assertion.
func steamReturnTo(state string) string {
	return servertest.SiteOrigin + "/api/ui/steam-callback?" + url.Values{"state": {state}}.Encode()
}

// expectSteamAskedNothing requires that no request to verify an assertion has
// left for Steam.
func expectSteamAskedNothing(t *testing.T, service *servertest.Service) {
	t.Helper()

	if asked := service.Providers.SteamVerifications(); asked != 0 {
		t.Errorf("Steam was asked to verify %d assertions, want none", asked)
	}
}

// A signed assertion is worth nothing without the login it was returned for:
// state never issued, already spent, held by another browser or started with
// another provider is refused as every other state is, and Steam is not asked.
func TestSteamLoginThisServiceDidNotStartCannotBeFinished(t *testing.T) {
	t.Parallel()

	refusals := map[string]func(service *servertest.Service) *servertest.Response{
		"a state value that was never issued": func(service *servertest.Service) *servertest.Response {
			const never = "a-state-value-this-service-never-issued"

			assertion := service.Providers.Issue(oauth.Steam, providertest.Grant{
				Identity: service.Providers.Someone(oauth.Steam, "someone"),
				ReturnTo: steamReturnTo(never),
			})

			return service.ReturnFromProvider(oauth.Steam, assertion, never)
		},
		"a state value in a browser that did not start the login": func(
			service *servertest.Service,
		) *servertest.Response {
			started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
			service.Forget(service.LoginCookieName())

			return service.FinishLogin(started, service.Providers.Someone(oauth.Steam, "someone"))
		},
		"a state value started with another provider": func(service *servertest.Service) *servertest.Response {
			started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)

			assertion := service.Providers.Issue(oauth.Steam, providertest.Grant{
				Identity: service.Providers.Someone(oauth.Steam, "someone"),
				ReturnTo: steamReturnTo(started.State),
			})

			return service.ReturnFromProvider(oauth.Steam, assertion, started.State)
		},
	}

	for name, attempt := range refusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)

			expectSignInValidationFailed(t, service, attempt(service))
			expectSteamAskedNothing(t, service)
		})
	}

	t.Run("a Steam state value at another provider's callback", func(t *testing.T) {
		t.Parallel()

		service := servertest.New(t)
		started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)

		expectSignInValidationFailed(t, service,
			service.ReturnFromProvider(oauth.Discord, "an-authorization-code", started.State))
	})

	t.Run("a state value that has already been spent", func(t *testing.T) {
		t.Parallel()

		service := servertest.New(t)
		started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
		person := service.Providers.Someone(oauth.Steam, "someone")

		assertion := service.Providers.Issue(oauth.Steam, providertest.Grant{Identity: person, ReturnTo: started.ReturnTo})

		service.ReturnFromProvider(oauth.Steam, assertion, started.State).
			ExpectStatus(http.StatusTemporaryRedirect).
			ExpectRedirectTo(service.Site.CallbackURI)

		expectSignInValidationFailed(t, service, service.ReturnFromProvider(oauth.Steam, assertion, started.State))
		expectSignInValidationFailed(t, service, service.FinishLogin(started, person))

		if asked := service.Providers.SteamVerifications(); asked != 1 {
			t.Errorf("Steam was asked to verify %d assertions, want only the first", asked)
		}
	})
}

// Steam signs the address it returns a browser to, and that address carries
// the login's state, so an assertion returned for one login cannot finish
// another. Presenting it so spends neither login.
func TestSteamAssertionCannotBeMovedToAnotherLogin(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	first := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
	second := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)

	assertion := service.Providers.Issue(oauth.Steam, providertest.Grant{
		Identity: service.Providers.Someone(oauth.Steam, "the person who signed in first"),
		ReturnTo: first.ReturnTo,
	})

	expectSignInValidationFailed(t, service, service.ReturnFromProvider(oauth.Steam, assertion, second.State))
	expectSteamAskedNothing(t, service)

	service.ReturnFromProvider(oauth.Steam, assertion, first.State).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(service.Site.CallbackURI)

	service.FinishLogin(second, service.Providers.Someone(oauth.Steam, "the person who signed in second")).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(service.Site.CallbackURI)
}

// A callback whose shape alone is wrong is refused before the login is looked
// at: it spends no login and asks Steam nothing, so the person who really
// returns with that state can still finish.
func TestMalformedSteamCallbackSpendsNoLoginAndAsksSteamNothing(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
	person := service.Providers.Someone(oauth.Steam, "the person who really returns")

	assertion := service.Providers.Issue(oauth.Steam, providertest.Grant{Identity: person, ReturnTo: started.ReturnTo})
	state := url.Values{"state": {started.State}}.Encode()

	altered := func(change func(url.Values)) string {
		fields, err := url.ParseQuery(assertion)
		if err != nil {
			t.Fatalf("reading the assertion: %v", err)
		}

		change(fields)

		return state + "&" + fields.Encode()
	}

	malformed := map[string]string{
		"a repeated state":     state + "&" + state + "&" + assertion,
		"a repeated mode":      state + "&" + assertion + "&openid.mode=id_res",
		"a repeated signature": state + "&" + assertion + "&openid.sig=placeholder",
		"malformed encoding":   state + "&" + assertion + "&openid.sig=%zz",
		"no signature":         altered(func(fields url.Values) { fields.Del("openid.sig") }),
		"an empty association handle": altered(func(fields url.Values) {
			fields.Set("openid.assoc_handle", "")
		}),
		"an unsigned return address": altered(func(fields url.Values) {
			fields.Set("openid.signed", "op_endpoint,claimed_id,identity,response_nonce,assoc_handle")
		}),
		"another provider endpoint": altered(func(fields url.Values) {
			fields.Set("openid.op_endpoint", "https://steam.example.test/openid/login")
		}),
		"an identity other than the claimed one": altered(func(fields url.Values) {
			fields.Set("openid.identity", "https://steamcommunity.com/openid/id/76561197960265729")
		}),
		"a stale nonce": altered(func(fields url.Values) {
			fields.Set("openid.response_nonce", time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)+"placeholder")
		}),
		"no state": assertion,
	}

	for name, query := range malformed {
		response := service.GET(servertest.CallbackPath(oauth.Steam) + "?" + query)

		if response.Status != http.StatusForbidden || string(response.Body) != signInValidationFailure {
			t.Errorf("%s: answered %d %s, want the sign-in validation failure", name, response.Status, response.Body)
		}
	}

	expectSteamAskedNothing(t, service)

	service.ReturnFromProvider(oauth.Steam, assertion, started.State).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(service.Site.CallbackURI)

	if asked := service.Providers.SteamVerifications(); asked != 1 {
		t.Errorf("Steam was asked to verify %d assertions, want only the genuine one", asked)
	}
}

// An assertion that is well formed but that Steam did not sign as presented
// spends the login it names, after exactly one question to Steam, and cannot
// be retried: not even with the genuine assertion for the same login.
func TestAssertionSteamRefusesSpendsLogin(t *testing.T) {
	t.Parallel()

	forgeries := map[string]func(url.Values){
		"a signature Steam did not make": func(fields url.Values) {
			fields.Set("openid.sig", "cGxhY2Vob2xkZXItc2lnbmF0dXJl")
		},
		"another person's Steam ID": func(fields url.Values) {
			fields.Set("openid.claimed_id", "https://steamcommunity.com/openid/id/76561197960265729")
			fields.Set("openid.identity", "https://steamcommunity.com/openid/id/76561197960265729")
		},
	}

	for name, forge := range forgeries {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
			person := service.Providers.Someone(oauth.Steam, "someone")

			genuine := service.Providers.Issue(oauth.Steam, providertest.Grant{Identity: person, ReturnTo: started.ReturnTo})

			fields, err := url.ParseQuery(genuine)
			if err != nil {
				t.Fatalf("reading the assertion: %v", err)
			}

			forge(fields)

			expectSignInValidationFailed(t, service, service.ReturnFromProvider(oauth.Steam, fields.Encode(), started.State))

			if asked := service.Providers.SteamVerifications(); asked != 1 {
				t.Errorf("Steam was asked to verify %d assertions, want one", asked)
			}

			expectSignInValidationFailed(t, service, service.ReturnFromProvider(oauth.Steam, genuine, started.State))

			if asked := service.Providers.SteamVerifications(); asked != 1 {
				t.Errorf("Steam was asked to verify %d assertions, want only the first", asked)
			}

			var steamAccounts int
			if err := service.Pool.QueryRow(t.Context(), `SELECT count(*) FROM "SteamAccount"`).Scan(&steamAccounts); err != nil {
				t.Fatalf("counting Steam accounts: %v", err)
			}

			if steamAccounts != 0 {
				t.Errorf("%d Steam accounts were created by a refused assertion", steamAccounts)
			}

			written := service.Logs.String()
			for what, value := range map[string]string{
				"the login state":      started.State,
				"the signature":        fields.Get("openid.sig"),
				"the response nonce":   fields.Get("openid.response_nonce"),
				"the claimed Steam ID": fields.Get("openid.claimed_id"),
			} {
				if strings.Contains(written, value) {
					t.Errorf("%s reached the log", what)
				}
			}
		})
	}
}
