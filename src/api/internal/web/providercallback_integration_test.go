//go:build integration && !devtools

package web_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// externalCallbackURI is where an application that is not the site is returned
// to when someone signs in to it.
const externalCallbackURI = "https://relying.example.test/return"

// A person is recognised by the identifier their provider issued, and their
// account is created the first time they arrive with it.
func TestSigningInWithProviderCreatesAccount(t *testing.T) {
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

			// Steam tells this service nothing but the Steam ID, so that is
			// what the account is named after.
			want := identity.Username
			if provider == oauth.Steam {
				want = "steam:" + identity.ID
			}

			if person.Username != want {
				t.Errorf("signed in as %q, want %q", person.Username, want)
			}
		})
	}
}

// A Steam account is the canonical Steam ID, across the whole unsigned 64-bit
// range. The account is named for it once, signing in again with it is the
// same person, and the public description of a person gains nothing.
func TestSteamAccountIsNamedForItsSteamIDAndFoundByIt(t *testing.T) {
	t.Parallel()

	for _, steamID := range []string{"76561197960287930", "18446744073709551615"} {
		t.Run(steamID, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			identity := providertest.Identity{ID: steamID, Username: "a name Steam never sends"}

			started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
			service.FinishLogin(started, identity).
				ExpectStatus(http.StatusTemporaryRedirect).
				ExpectRedirectTo(service.Site.CallbackURI)

			var described map[string]any

			service.GET("/me").ExpectStatus(http.StatusOK).DecodeInto(&described)

			if len(described) != 2 || described["username"] != "steam:"+steamID || described["id"] == "" {
				t.Errorf("/me = %v, want exactly an id and the username steam:%s", described, steamID)
			}

			var held int
			if err := service.Pool.QueryRow(t.Context(),
				`SELECT count(*) FROM "SteamAccount" WHERE "id" = $1 AND "user_id"::text = $2`, steamID, described["id"],
			).Scan(&held); err != nil {
				t.Fatalf("reading the Steam account: %v", err)
			}

			if held != 1 {
				t.Error("the person is not held as the account for their Steam ID")
			}

			again := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
			service.FinishLogin(again, identity).ExpectStatus(http.StatusTemporaryRedirect)

			if second := currentPerson(t, service); second != described["id"] {
				t.Errorf("the same Steam ID signed in as %v and then as %s", described["id"], second)
			}
		})
	}
}

// An application that is not the site gets the same one-time code from a Steam
// sign-in as from any other, under the code key, spendable by it alone.
func TestSteamSignInToApplicationEndsInOneTimeCode(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	other := service.RegisterApplication("another application", "https://another.example.test/return")
	person := service.Providers.Someone(oauth.Steam, "someone signing in with Steam")

	started := service.StartLogin(oauth.Steam, application.ID, externalCallbackURI)
	response := service.FinishLogin(started, person).ExpectStatus(http.StatusTemporaryRedirect)

	if response.Cookie(service.SessionCookieName()) != nil {
		t.Error("signing in to another application with Steam signed the browser in here")
	}

	location := response.Header.Get("Location")

	code, found := strings.CutPrefix(location, externalCallbackURI+"?code=")
	if !found || code == "" || strings.ContainsAny(code, "&?#") {
		t.Fatal("the browser was not returned to the exact callback with only a code appended")
	}

	code, err := url.QueryUnescape(code)
	if err != nil {
		t.Fatalf("the code is not query-encoded: %v", err)
	}

	service.POSTJSON("/login",
		map[string]string{"id": other.ID.String(), "refresh_token": other.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusUnauthorized).ExpectDetail("Invalid exchange code")

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

	if identified.Username != "steam:"+person.ID {
		t.Errorf("the token identifies %q, want the Steam account", identified.Username)
	}
}

// Nothing a Steam sign-in handles reaches the log: not the state, the
// assertion's signature or nonce, and not the session the browser was given.
func TestSigningInWithSteamWritesNoCredentialToLog(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	started := service.StartLogin(oauth.Steam, service.Site.ApplicationID, service.Site.CallbackURI)
	assertion := service.Providers.Issue(oauth.Steam, providertest.Grant{
		Identity: service.Providers.Someone(oauth.Steam, "a person"),
		ReturnTo: started.ReturnTo,
	})

	response := service.ReturnFromProvider(oauth.Steam, assertion, started.State).
		ExpectStatus(http.StatusTemporaryRedirect)

	session := response.Cookie(service.SessionCookieName())
	if session == nil {
		t.Fatal("the browser was not signed in")
	}

	fields, err := url.ParseQuery(assertion)
	if err != nil {
		t.Fatalf("reading the assertion: %v", err)
	}

	written := service.Logs.String()

	for name, value := range map[string]string{
		"the state value":        started.State,
		"the signature":          fields.Get("openid.sig"),
		"the response nonce":     fields.Get("openid.response_nonce"),
		"the association":        fields.Get("openid.assoc_handle"),
		"the session value":      session.Value,
		"the claimed identifier": fields.Get("openid.claimed_id"),
	} {
		if value != "" && strings.Contains(written, value) {
			t.Errorf("%s reached the log", name)
		}
	}
}

// The provider's identifier is what an account belongs to. Signing in again
// with it is the same person, and a display name says nothing.
func TestProviderAccountBelongsToOnePerson(t *testing.T) {
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
func TestSitesOwnLoginPutsNothingInURL(t *testing.T) {
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
func TestApplicationsLoginEndsInOneTimeCode(t *testing.T) {
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
func TestSigningInWithGoogleReturnsUnderIdentityKey(t *testing.T) {
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
func TestRegisteredCallbacksOwnQueryIsKept(t *testing.T) {
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

// A code is spent once. The second attempt is refused with the same response
// as one that never existed.
func TestOneTimeCodeIsSpentOnce(t *testing.T) {
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

	replayed := service.POSTJSON("/login", credentials, servertest.Header("exchange-token", code)).
		ExpectStatus(http.StatusUnauthorized).
		ExpectDetail("Invalid exchange code")

	unknown := service.POSTJSON("/login", credentials, servertest.Header("exchange-token", "a-code-that-never-existed")).
		ExpectStatus(http.StatusUnauthorized).
		ExpectDetail("Invalid exchange code")

	if !bytes.Equal(replayed.Body, unknown.Body) {
		t.Errorf("a spent code was refused as %s, an unknown one as %s", replayed.Body, unknown.Body)
	}
}

// A code that has outlived its lifetime is refused with the same response as
// one that never existed.
func TestExpiredOneTimeCodeIsRefusedAsUnknown(t *testing.T) {
	t.Parallel()

	// The shortest lifetime the service accepts.
	service := servertest.New(t, servertest.WithSetting(func(settings *config.Settings) {
		settings.ExchangeCodeSeconds = 1
	}))
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	credentials := map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}

	// Expiry is measured by the database, so this waits for it rather than
	// rewriting a row to look old.
	time.Sleep(1100 * time.Millisecond)

	expired := service.POSTJSON("/login", credentials, servertest.Header("exchange-token", code)).
		ExpectStatus(http.StatusUnauthorized).
		ExpectDetail("Invalid exchange code")

	unknown := service.POSTJSON("/login", credentials, servertest.Header("exchange-token", "a-code-that-never-existed")).
		ExpectStatus(http.StatusUnauthorized)

	if !bytes.Equal(expired.Body, unknown.Body) {
		t.Errorf("an expired code was refused as %s, an unknown one as %s", expired.Body, unknown.Body)
	}
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

	for _, answer := range concurrently(t, requests...) {
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
			case failed.Detail != "Invalid exchange code":
				t.Error("a request was refused for something other than the exchange code being invalid")
			}
		default:
			t.Errorf("spending a code answered %d", answer.status)
		}
	}

	if granted != 1 || refused != 1 {
		t.Errorf("%d requests were given a token and %d were refused, want one of each", granted, refused)
	}
}

// A target spelled a way this service does not serve reaches nothing and does
// not spend the one-time code it carries before the application that owns the
// code arrives.
func TestExchangeSpelledAnotherWaySpendsNoCode(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	spellings := []string{
		"/login",
		"/api//login",
		"/api/../api/login",
		"/api/%6cogin",
		"/api/login/",
		"/api/ui/../login",
	}

	for _, target := range spellings {
		service.AtExactTarget(http.MethodPost, target, servertest.Header("exchange-token", code)).
			ExpectStatus(http.StatusNotFound)
	}

	service.POSTJSON("/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}, servertest.Header("exchange-token", code)).
		ExpectStatus(http.StatusOK)
}

// A code belongs to the application the person was signing in to. Another
// application holding it cannot learn who they are.
func TestOneTimeCodeIsSpentByApplicationItWasIssuedTo(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	intended := service.RegisterApplication("the application signed in to", externalCallbackURI)
	other := service.RegisterApplication("another application", "https://another.example.test/return")

	code := signInToApplication(t, service, intended, externalCallbackURI)

	misdirected := service.POSTJSON("/login",
		map[string]string{"id": other.ID.String(), "refresh_token": other.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusUnauthorized).ExpectDetail("Invalid exchange code")

	unknown := service.POSTJSON("/login",
		map[string]string{"id": other.ID.String(), "refresh_token": other.RefreshToken},
		servertest.Header("exchange-token", "a-code-that-never-existed"),
	).ExpectStatus(http.StatusUnauthorized)

	if !bytes.Equal(misdirected.Body, unknown.Body) {
		t.Errorf("another application's code was refused as %s, an unknown one as %s", misdirected.Body, unknown.Body)
	}

	service.POSTJSON("/login",
		map[string]string{"id": intended.ID.String(), "refresh_token": intended.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusOK)
}

// A provider identity without a name is incomplete, so this service cannot
// record it, and the callback is refused like any other validation failure.
func TestPersonUnnamedByProviderIsNotSignedIn(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
	expectSignInValidationFailed(t, service,
		service.FinishLogin(started, providertest.Identity{ID: "4242424242", Username: ""}))
}

// Nothing a provider sign-in handles reaches the log: not the authorization
// code, not the state, and not the session the browser was given.
func TestSigningInWritesNoCredentialToLog(t *testing.T) {
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
