package servertest

import (
	"net/http"
	"net/url"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
)

// Authorization is a login that has been started and is waiting for the person
// to come back from the provider.
type Authorization struct {
	// Provider is who the browser was sent to.
	Provider oauth.Provider

	// AuthorizationURL is where the browser was sent, unparsed, so a test can
	// assert the whole address.
	AuthorizationURL string

	// State is the opaque value the provider will return unchanged.
	State string

	// Challenge is the PKCE challenge the provider was given.
	Challenge string

	// Nonce ties an identity token to this login, for the provider that issues
	// one.
	Nonce string

	// Response is what the authorize endpoint answered, for the tests that
	// assert the redirect and the cookie it set.
	Response *Response
}

// CallbackPath is the endpoint a provider returns a browser to.
func CallbackPath(provider oauth.Provider) string {
	switch provider {
	case oauth.Discord:
		return "/ui/discord-callback"
	case oauth.GitHub:
		return "/ui/github-callback"
	case oauth.Google:
		return "/google"
	default:
		return ""
	}
}

// StartLogin asks the service to begin a login and reads what it told the
// provider.
func (s *Service) StartLogin(provider oauth.Provider, applicationID uuid.UUID, callbackURI string) Authorization {
	s.t.Helper()

	response := s.GET("/ui/" + string(provider) + "/authorize?" + url.Values{
		"application_id": {applicationID.String()},
		"callback_uri":   {callbackURI},
	}.Encode())

	response.ExpectStatus(http.StatusTemporaryRedirect)

	sentTo := response.Header.Get("Location")

	address, err := url.Parse(sentTo)
	if err != nil {
		s.t.Fatalf("the browser was sent to something that is not a URL: %v", err)
	}

	return Authorization{
		Provider:         provider,
		AuthorizationURL: sentTo,
		State:            address.Query().Get("state"),
		Challenge:        address.Query().Get("code_challenge"),
		Nonce:            address.Query().Get("nonce"),
		Response:         response,
	}
}

// FinishLogin returns from the provider with an authorization code for a
// person, as the browser does.
func (s *Service) FinishLogin(
	authorization Authorization, identity providertest.Identity, adjust ...func(*http.Request),
) *Response {
	s.t.Helper()

	code := s.Providers.Issue(authorization.Provider, providertest.Grant{
		Identity:  identity,
		Challenge: authorization.Challenge,
		Nonce:     authorization.Nonce,
	})

	return s.ReturnFromProvider(authorization.Provider, code, authorization.State, adjust...)
}

// ReturnFromProvider calls a provider callback with whatever a test wants the
// browser to be carrying.
func (s *Service) ReturnFromProvider(
	provider oauth.Provider, code, state string, adjust ...func(*http.Request),
) *Response {
	s.t.Helper()

	query := url.Values{"state": {state}}
	if code != "" {
		query.Set("code", code)
	}

	return s.GET(CallbackPath(provider)+"?"+query.Encode(), adjust...)
}

// SignIn signs a browser in to the site itself, the way a person does, and
// leaves the session and CSRF cookies in the client's jar.
func (s *Service) SignIn(identity providertest.Identity) *Response {
	s.t.Helper()

	authorization := s.StartLogin(oauth.Discord, s.Site.ApplicationID, s.Site.CallbackURI)

	return s.FinishLogin(authorization, identity).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(s.Site.CallbackURI)
}

// SignInSomeone signs in a person nobody else has signed in as, and returns who
// they turned out to be.
func (s *Service) SignInSomeone(username string) providertest.Identity {
	s.t.Helper()

	identity := s.Providers.Someone(oauth.Discord, username)
	s.SignIn(identity)

	return identity
}

// Protected sends the CSRF token the site holds, which is what a request that
// changes something has to carry alongside the session cookie.
func (s *Service) Protected(request *http.Request) {
	s.t.Helper()

	request.Header.Set("Origin", s.Config.Site.String())

	if token := s.CookieValue(s.CSRFCookieName()); token != "" {
		request.Header.Set("X-CSRF-Token", token)
	}
}

// CookieValue returns a cookie the client is holding for this service.
func (s *Service) CookieValue(name string) string {
	s.t.Helper()

	address, err := url.Parse(s.server.URL)
	if err != nil {
		s.t.Fatalf("the test server has no address: %v", err)
	}

	for _, cookie := range s.client.Jar.Cookies(address) {
		if cookie.Name == name {
			return cookie.Value
		}
	}

	return ""
}

// Forget drops a cookie the client is holding, for the tests that describe a
// browser that no longer has one.
func (s *Service) Forget(name string) {
	s.t.Helper()

	address, err := url.Parse(s.server.URL)
	if err != nil {
		s.t.Fatalf("the test server has no address: %v", err)
	}

	s.client.Jar.SetCookies(address, []*http.Cookie{{Name: name, Value: "", MaxAge: -1}})
}
