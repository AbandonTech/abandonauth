//go:build integration && !devtools

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
func TestCompletedLoginReturnsBrowserToRegisteredSpelling(t *testing.T) {
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
func TestDeclinedLoginReturnsBrowserToRegisteredSpelling(t *testing.T) {
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
// than trusted from when the row was written. Whether the provider declined or
// authenticated the user, the refusal is the one sign-in validation failure and
// no exchange code is issued.
func TestLoginWhoseStoredCallbackNoLongerPassesEndsWithoutRedirect(t *testing.T) {
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

			expectSignInValidationFailed(t, service, ending(service, started))

			var codes int64
			if err := service.Pool.QueryRow(t.Context(),
				`SELECT count(*) FROM oauth_exchange_code`).Scan(&codes); err != nil {
				t.Fatalf("counting the exchange codes the callback left behind: %v", err)
			}

			if codes != 0 {
				t.Errorf("%d exchange codes were issued for a login that could not be returned", codes)
			}
		})
	}
}

// A callback is registered as one exact string. Another spelling of the same
// address is not that string, and starting a login with it is refused.
func TestLoginCannotBeStartedWithAnotherSpellingOfCallback(t *testing.T) {
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

// A public client is returned to the exact redirect it began with, every
// registered byte kept and the response parameters appended once each, so a
// value registered in the template's query can never be read as a response.
func TestPublicClientIsReturnedToItsExactRedirect(t *testing.T) {
	t.Parallel()

	const template = "http://127.0.0.1/Return/Callback?tenant=Acme&next=%2FHome%3Fa%3Db"

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	client := service.InstalledClient(service.RegisterPublicClient("an installed application", template))
	pending := client.Pending(template, 49152, "openid")

	if pending.RedirectURI != "http://127.0.0.1:49152/Return/Callback?tenant=Acme&next=%2FHome%3Fa%3Db" {
		t.Fatalf("the test's redirect is %q", pending.RedirectURI)
	}

	handle := client.ReachConsent(pending, oauth.Discord, service.Providers.Someone(oauth.Discord, "someone"))
	returned := service.AllowConsent(handle).ExpectStatus(http.StatusSeeOther)

	location := returned.Header.Get("Location")
	prefix := pending.RedirectURI + "&code="

	code, rest, found := strings.Cut(strings.TrimPrefix(location, prefix), "&state=")
	if !strings.HasPrefix(location, prefix) || !found {
		t.Fatalf("Location = %q, want the exact redirect with the code appended", location)
	}

	if rest != pending.State+"&iss="+url.QueryEscape(servertest.OpenIDIssuer) {
		t.Errorf("the state and issuer were appended as %q", rest)
	}

	if len(code) != 43 || strings.ContainsAny(code, "&?#%") {
		t.Errorf("the code is %q, want one encoded value", code)
	}

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the browser was sent to something that is not a URL: %v", err)
	}

	if values := parsed.Query(); values.Get("next") != "/Home?a=b" || len(values["code"]) != 1 || len(values["state"]) != 1 {
		t.Errorf("the redirect decodes to %v", values)
	}

	if _, err := pending.Read(location, servertest.OpenIDIssuer); err != nil {
		t.Errorf("the client could not read its own answer: %v", err)
	}
}

// The test client's listener accepts only an unambiguous answer to its own
// pending authorization.
func TestInstalledClientRefusesAmbiguousOrUnsolicitedAnswers(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	pending := client.Pending(ipv4Template, 49152, "openid")
	other := client.Pending(ipv4Template, 49152, "openid")

	issuer := url.QueryEscape(servertest.OpenIDIssuer)
	answer := pending.RedirectURI + "?code=c&state=" + pending.State + "&iss=" + issuer

	if _, err := pending.Read(answer, servertest.OpenIDIssuer); err != nil {
		t.Fatalf("a genuine answer was refused: %v", err)
	}

	for name, location := range map[string]string{
		"a repeated code":       answer + "&code=d",
		"a repeated state":      answer + "&state=" + pending.State,
		"a repeated issuer":     answer + "&iss=" + issuer,
		"a code and an error":   answer + "&error=access_denied",
		"no state":              pending.RedirectURI + "?code=c&iss=" + issuer,
		"no issuer":             pending.RedirectURI + "?code=c&state=" + pending.State,
		"another issuer":        pending.RedirectURI + "?code=c&state=" + pending.State + "&iss=https%3A%2F%2Fevil.test",
		"another path":          "http://127.0.0.1:49152/other?code=c&state=" + pending.State + "&iss=" + issuer,
		"another port":          "http://127.0.0.1:49153/oauth/callback?code=c&state=" + pending.State + "&iss=" + issuer,
		"another authorization": pending.RedirectURI + "?code=c&state=" + other.State + "&iss=" + issuer,
		"malformed encoding":    answer + "&x=%zz",
		"nothing":               pending.RedirectURI,
	} {
		if _, err := pending.Read(location, servertest.OpenIDIssuer); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// Two authorizations in flight at once: each code is bound to its own
	// verifier and redirect, so swapping any one of them redeems nothing.
	first := client.Pending(ipv4Template, 50001, "openid")
	second := client.Pending(ipv4Template, 50002, "openid")

	firstCode := client.SignIn(first, oauth.Discord, "someone")
	secondCode := client.SignIn(second, oauth.Discord, "someone else")

	swapped := first
	swapped.Verifier = second.Verifier
	expectOAuthError(t, client.Exchange(swapped, firstCode), http.StatusBadRequest, "invalid_grant")

	swapped = first
	swapped.RedirectURI = second.RedirectURI
	expectOAuthError(t, client.Exchange(swapped, firstCode), http.StatusBadRequest, "invalid_grant")
	expectOAuthError(t, client.Exchange(first, secondCode), http.StatusBadRequest, "invalid_grant")

	client.Exchange(first, firstCode).ExpectStatus(http.StatusOK)
	client.Exchange(second, secondCode).ExpectStatus(http.StatusOK)
}
