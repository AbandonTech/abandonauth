//go:build integration && !devtools

package web_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// externalCallbackURI is where an application that is not the site is returned
// to when someone signs in to it.
const externalCallbackURI = "https://relying.example.test/return"

// A person is recognised by the identifier their provider issued, and their
// account is created the first time they arrive with it.
func TestSigningInWithAProviderCreatesAnAccount(t *testing.T) {
	t.Parallel()

	for _, provider := range oauth.Providers {
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			identity := service.Providers.Someone(provider, "someone with a "+string(provider)+" account")

			started := service.StartLogin(provider, service.Site.ApplicationID, service.Site.CallbackURI)
			service.FinishLogin(started, identity).
				ExpectStatus(http.StatusTemporaryRedirect).
				ExpectRedirectTo(service.Site.CallbackURI)

			var person struct {
				ID       string `json:"id"`
				Username string `json:"username"`
			}

			service.GET("/me").ExpectStatus(http.StatusOK).DecodeInto(&person)

			if person.Username != identity.Username {
				t.Errorf("signed in as %q, want %q", person.Username, identity.Username)
			}
		})
	}
}

// The provider's identifier is what an account belongs to. Signing in again
// with it is the same person, and a display name says nothing.
func TestAProviderAccountBelongsToOnePerson(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	identity := service.Providers.Someone(oauth.Discord, "the same person")

	service.SignIn(identity)
	first := currentPerson(t, service)

	renamed := identity
	renamed.Username = "the same person, renamed at the provider"

	service.SignIn(renamed)
	second := currentPerson(t, service)

	if first != second {
		t.Errorf("the same provider account signed in as %q and then as %q", first, second)
	}
}

// Two provider accounts are two people, whatever they call themselves.
func TestTwoProviderAccountsAreTwoPeople(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.SignIn(service.Providers.Someone(oauth.Discord, "an ambiguous name"))
	first := currentPerson(t, service)

	service.SignIn(service.Providers.Someone(oauth.Discord, "an ambiguous name"))
	second := currentPerson(t, service)

	if first == second {
		t.Error("two provider accounts sharing a display name signed in as one person")
	}
}

// A person who signs in to the site is signed in here, and nothing that could
// sign anyone in travels in the URL.
func TestTheSitesOwnLoginPutsNothingInTheURL(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	response := service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	if response.Header.Get("Location") != service.Site.CallbackURI {
		t.Errorf("the browser was returned to %q with something added", response.Header.Get("Location"))
	}

	session := response.Cookie(service.SessionCookieName())
	if session == nil || session.Value == "" {
		t.Fatal("the browser was not signed in")
	}

	if !session.HttpOnly {
		t.Error("the session cookie can be read by script")
	}

	token := response.Cookie(service.CSRFCookieName())
	if token == nil || token.Value == "" {
		t.Fatal("the browser was given no token to confirm its own requests with")
	}

	if token.HttpOnly {
		t.Error("the site cannot read the token it has to send back")
	}
}

// An application that is not the site collects a one-time code, which means
// nothing until the application spends it from its own server.
func TestAnApplicationsLoginEndsInAOneTimeCode(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	person := service.Providers.Someone(oauth.Discord, "someone signing in to it")

	started := service.StartLogin(oauth.Discord, application.ID, externalCallbackURI)
	response := service.FinishLogin(started, person).ExpectStatus(http.StatusTemporaryRedirect)

	returnedTo, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the browser was returned to something that is not a URL: %v", err)
	}

	code := returnedTo.Query().Get("code")
	if code == "" {
		t.Fatal("the application was given no code to spend")
	}

	if response.Cookie(service.SessionCookieName()) != nil {
		t.Error("signing in to another application signed the browser in here")
	}

	var granted struct {
		Token string `json:"token"`
	}

	service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusOK).DecodeInto(&granted)

	var identified struct {
		Username string `json:"username"`
	}

	service.GET("/me", servertest.Bearer(granted.Token)).ExpectStatus(http.StatusOK).DecodeInto(&identified)

	if identified.Username != person.Username {
		t.Errorf("the token identifies %q, want %q", identified.Username, person.Username)
	}
}

// Google returns its result under the key applications already read, and it is
// the same opaque one-time code every other provider produces.
func TestSigningInWithGoogleReturnsUnderTheIdentityKey(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)

	started := service.StartLogin(oauth.Google, application.ID, externalCallbackURI)
	response := service.FinishLogin(started, service.Providers.Someone(oauth.Google, "someone")).
		ExpectStatus(http.StatusTemporaryRedirect)

	returnedTo, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the browser was returned to something that is not a URL: %v", err)
	}

	if returnedTo.Query().Get("authentication") == "" {
		t.Errorf("the browser was returned to %q, without an authentication value", returnedTo)
	}

	if returnedTo.Query().Get("code") != "" {
		t.Error("Google's result was also returned under the code key")
	}
}

// The query an application registered its callback with is its own. The result
// is added to it and nothing else about it changes.
func TestTheRegisteredCallbacksOwnQueryIsKept(t *testing.T) {
	t.Parallel()

	const callback = "https://relying.example.test/return?theme=dark&next=%2Fwelcome"

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", callback)

	started := service.StartLogin(oauth.Discord, application.ID, callback)
	response := service.FinishLogin(started, service.Providers.Someone(oauth.Discord, "someone")).
		ExpectStatus(http.StatusTemporaryRedirect)

	returnedTo, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the browser was returned to something that is not a URL: %v", err)
	}

	if returnedTo.Query().Get("theme") != "dark" || returnedTo.Query().Get("next") != "/welcome" {
		t.Errorf("the browser was returned to %q, which is not the registered callback with a result added", returnedTo)
	}

	if returnedTo.Query().Get("code") == "" {
		t.Errorf("the browser was returned to %q, without a code", returnedTo)
	}
}

// A code is spent once. The second attempt is refused in the same words as one
// that never existed.
func TestAOneTimeCodeIsSpentOnce(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	credentials := map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}

	service.POSTJSON("/login", credentials, servertest.Header("exchange-token", code)).
		ExpectStatus(http.StatusOK)

	service.POSTJSON("/login", credentials, servertest.Header("exchange-token", code)).
		ExpectStatus(http.StatusUnauthorized).
		ExpectDetail("Token is not valid.")

	service.POSTJSON("/login", credentials, servertest.Header("exchange-token", "a-code-that-never-existed")).
		ExpectStatus(http.StatusUnauthorized).
		ExpectDetail("Token is not valid.")
}

// A code buys one token. Two requests from the application it was issued to,
// arriving together with the same code, are not two sign-ins.
func TestOneOneTimeCodeIsSpentAtMostOnce(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	credentials, err := json.Marshal(map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	})
	if err != nil {
		t.Fatalf("preparing the application's credentials: %v", err)
	}

	requests := make([]*http.Request, 0, 2)

	for range 2 {
		request, err := http.NewRequestWithContext(
			t.Context(), http.MethodPost, service.EndpointURL("/login"), bytes.NewReader(credentials),
		)
		if err != nil {
			t.Fatalf("preparing a request to spend the code: %v", err)
		}

		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("exchange-token", code)

		requests = append(requests, request)
	}

	var granted, refused int

	for _, answer := range atTheSameMoment(t, requests...) {
		switch answer.status {
		case http.StatusOK:
			granted++

			var issued struct {
				Token string `json:"token"`
			}

			if err := json.Unmarshal(answer.body, &issued); err != nil || issued.Token == "" {
				t.Error("a request that spent the code was given nothing to identify anyone with")
			}
		case http.StatusUnauthorized:
			refused++

			var failed struct {
				Detail string `json:"detail"`
			}

			switch err := json.Unmarshal(answer.body, &failed); {
			case err != nil:
				t.Error("a refused request did not answer in this service's failure shape")
			case failed.Detail != "Token is not valid.":
				t.Error("a request was refused for something other than the code being unusable")
			}
		default:
			t.Errorf("spending a code answered %d", answer.status)
		}
	}

	if granted != 1 || refused != 1 {
		t.Errorf("%d requests were given a token and %d were refused, want one of each", granted, refused)
	}
}

// A target spelled a way this service does not serve reaches nothing. It spends
// neither the one-time code it carries nor the budget that protects spending
// one, so the address it is refused at cannot be used to wear either of them
// down before the application that owns the code arrives.
func TestAnExchangeSpelledAnotherWaySpendsNeitherTheCodeNorItsBudget(t *testing.T) {
	t.Parallel()

	service := servertest.New(t, servertest.WithSteadyClock())
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	budget, known := ratelimit.PolicyFor(ratelimit.LoginExchange)
	if !known {
		t.Fatal("spending a one-time code has no budget")
	}

	spellings := []string{
		"/login",
		"/api//login",
		"/api/../api/login",
		"/api/%6cogin",
		"/api/login/",
		"/api/ui/../login",
	}

	for attempt := int64(0); attempt <= budget.Limit; attempt++ {
		target := spellings[attempt%int64(len(spellings))]

		service.AtExactTarget(http.MethodPost, target,
			servertest.Header("exchange-token", code),
			asClient("198.51.100.40"),
		).ExpectStatus(http.StatusNotFound)
	}

	service.POSTJSON("/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}, servertest.Header("exchange-token", code), asClient("198.51.100.40")).
		ExpectStatus(http.StatusOK)
}

// A code belongs to the application the person was signing in to. Another
// application holding it cannot learn who they are.
func TestAOneTimeCodeIsSpentByTheApplicationItWasIssuedTo(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	intended := service.RegisterApplication("the application signed in to", externalCallbackURI)
	other := service.RegisterApplication("another application", "https://another.example.test/return")

	code := signInToApplication(t, service, intended, externalCallbackURI)

	service.POSTJSON("/login",
		map[string]string{"id": other.ID.String(), "refresh_token": other.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusUnauthorized).ExpectDetail("Token is not valid.")

	service.POSTJSON("/login",
		map[string]string{"id": intended.ID.String(), "refresh_token": intended.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusOK)
}

// A provider that answers without a name for the person describes somebody this
// service cannot record, and nobody is signed in.
func TestAPersonAProviderCannotNameIsNotSignedIn(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
	response := service.FinishLogin(started, providertest.Identity{ID: "4242424242", Username: ""}).
		ExpectStatus(http.StatusForbidden)

	if response.Cookie(service.SessionCookieName()) != nil {
		t.Error("a person the provider could not name was signed in")
	}
}

// Nothing a provider sign-in handles reaches the log: not the authorization
// code, not the state, and not the session the browser was given.
func TestSigningInWritesNoCredentialToTheLog(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
	response := service.FinishLogin(started, service.Providers.Someone(oauth.Discord, "a person"))

	session := response.Cookie(service.SessionCookieName())
	if session == nil {
		t.Fatal("the browser was not signed in")
	}

	written := service.Logs.String()

	for name, value := range map[string]string{
		"the state value":   started.State,
		"the session value": session.Value,
	} {
		if value != "" && strings.Contains(written, value) {
			t.Errorf("%s reached the log", name)
		}
	}
}

func currentPerson(t *testing.T, service *servertest.Service) string {
	t.Helper()

	var person struct {
		ID string `json:"id"`
	}

	service.GET("/me").ExpectStatus(http.StatusOK).DecodeInto(&person)

	return person.ID
}

// signInToApplication signs a new person in to an application and returns the
// code the browser was sent back with.
func signInToApplication(
	t *testing.T, service *servertest.Service, application servertest.Application, callback string,
) string {
	t.Helper()

	started := service.StartLogin(oauth.Discord, application.ID, callback)
	response := service.FinishLogin(started, service.Providers.Someone(oauth.Discord, "someone signing in")).
		ExpectStatus(http.StatusTemporaryRedirect)

	returnedTo, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the browser was returned to something that is not a URL: %v", err)
	}

	code := returnedTo.Query().Get("code")
	if code == "" {
		t.Fatal("the application was given no code to spend")
	}

	return code
}
