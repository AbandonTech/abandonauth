package web

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers"
	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// What a caller is told when a login cannot be started or finished. Every way
// of getting it wrong receives the same words, so a caller cannot use the
// difference to find out which application, callback or login exists.
const (
	detailUnknownApplicationOrCallback = "Invalid application ID or callback_uri"
	detailNoSuchLogin                  = "This login could not be matched to one that was started here"
)

// Query keys a completed login is returned under. They are what applications
// already read, and a callback may not already use one.
const (
	exchangeCodeQueryKey = "code"
	identityQueryKey     = "authentication"
)

// providerAuthorize starts a login with a provider.
//
// The application and the exact callback are checked here, before anything is
// stored, and are then held by this service until the provider returns. What
// travels through the browser is an opaque value that means nothing on its own.
//
// @Summary     Start a login with an OAuth provider
// @Description Start an OAuth login with the named provider.
// @Description
// @Description Checks that the callback URI is registered to the developer application, binds the attempt to the calling browser, and redirects to the provider's authorization endpoint. The browser must return to the matching provider callback for the login to complete.
// @Produce     json
// @Param       provider       path string true "The provider to sign in with" Enums(discord, github, google)
// @Param       application_id query string true "The application the person is signing in to" format(uuid)
// @Param       callback_uri   query string true "Exactly one of the URIs the application registered"
// @Success     307 "Redirect to the provider's authorization endpoint"
// @Failure     403 {object} response.Failed "The application or callback is not registered"
// @Failure     422 {object} response.Invalidated
// @Failure     429 {object} response.Failed "Too many attempts"
// @Router      /ui/{provider}/authorize [get].
func (s *Server) providerAuthorize() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		given := inputs.New(request)
		wanted := readProviderLoginInputs(given)

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		if !s.withinLimit(writer, request, ratelimit.ProviderCallback, s.clientAddress(request)) {
			return
		}

		registered, err := s.applications.CallbackIsRegistered(
			request.Context(), wanted.applicationID, wanted.callbackURI,
		)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		if !registered {
			response.Error(writer, http.StatusForbidden, detailUnknownApplicationOrCallback)

			return
		}

		started, err := s.logins.Begin(
			request.Context(), wanted.provider, wanted.applicationID, wanted.callbackURI,
			cookieValue(request, s.LoginCookieName()),
		)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		s.bindLoginToBrowser(writer, started.BrowserBinding)
		response.Redirect(writer, http.StatusTemporaryRedirect, s.authorizationURL(wanted.provider, started))
	})
}

// providerLoginInputs is what starting a login names: who to sign in with, for
// which application, and where the person is to be returned.
type providerLoginInputs struct {
	provider      oauth.Provider
	applicationID uuid.UUID
	callbackURI   string
}

// readProviderLoginInputs reads all three, refusing a provider this service does
// not offer as an input rather than looking anything up for it.
func readProviderLoginInputs(given *inputs.Inputs) providerLoginInputs {
	provider, known := oauth.ParseProvider(given.PathString("provider"))
	if !known {
		given.Refuse(response.Failure{
			Location: []any{"path", "provider"},
			Message:  "Input should be 'discord', 'github' or 'google'",
			Type:     "enum",
		})
	}

	return providerLoginInputs{
		provider:      provider,
		applicationID: given.QueryUUID("application_id"),
		callbackURI:   given.Query("callback_uri"),
	}
}

func (s *Server) authorizationURL(provider oauth.Provider, started oauth.Start) string {
	switch provider {
	case oauth.Discord:
		return s.discord.AuthorizationURL(started.State, started.Challenge)
	case oauth.GitHub:
		return s.github.AuthorizationURL(started.State, started.Challenge)
	case oauth.Google:
		return s.google.AuthorizationURL(started.State, started.Challenge, started.Nonce)
	default:
		return ""
	}
}

// resumeLogin reads the state and the browser's cookie and spends the login
// they name.
//
// It answers the request itself on every failure, always with the same words:
// a state that was never issued, that has expired, that has already been used,
// that belongs to another browser and that was started with another provider
// are indistinguishable from outside.
func (s *Server) resumeLogin(
	writer http.ResponseWriter, request *http.Request, provider oauth.Provider,
) (oauth.Login, string, bool) {
	if !s.withinLimit(writer, request, ratelimit.ProviderCallback, s.clientAddress(request)) {
		return oauth.Login{}, "", false
	}

	state := request.URL.Query().Get("state")
	binding := cookieValue(request, s.LoginCookieName())

	login, err := s.logins.Consume(request.Context(), provider, state, binding)
	if errors.Is(err, oauth.ErrNoSuchLogin) {
		response.Error(writer, http.StatusForbidden, detailNoSuchLogin)

		return oauth.Login{}, "", false
	}

	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return oauth.Login{}, "", false
	}

	return login, request.URL.Query().Get(exchangeCodeQueryKey), true
}

// completeLogin returns the browser to where the login said it should go.
//
// A login the site itself started ends in a session: the browser is signed in
// here, and nothing that could sign it in is put in a URL. A login another
// application started ends in a one-time code that only that application can
// spend.
func (s *Server) completeLogin(
	writer http.ResponseWriter,
	request *http.Request,
	login oauth.Login,
	identity accounts.Identity,
	responseKey string,
) {
	callback, err := urlpolicy.ParseCallbackURI(login.CallbackURI)
	if err != nil {
		// The URI was accepted when it was registered. If it is no longer one
		// this service will return a browser to, the login ends here.
		response.Error(writer, http.StatusForbidden, detailUnknownApplicationOrCallback)

		return
	}

	person, err := s.accounts.Resolve(request.Context(), identity)
	if errors.Is(err, accounts.ErrUnusableIdentity) {
		response.Error(writer, http.StatusForbidden, detailUnknownApplicationOrCallback)

		return
	}

	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return
	}

	if login.ApplicationID == s.config.InternalApplicationID {
		s.signInBrowser(writer, request, person.ID, callback.String())

		return
	}

	code, err := s.codes.Issue(request.Context(), person.ID, login.ApplicationID, login.Provider)
	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return
	}

	response.Redirect(
		writer, http.StatusTemporaryRedirect, callback.WithResponseParameter(responseKey, code),
	)
}

// signInBrowser gives the browser a session and sends it on to the site.
func (s *Server) signInBrowser(
	writer http.ResponseWriter, request *http.Request, userID uuid.UUID, destination string,
) {
	issued, err := s.sessions.Create(request.Context(), userID)
	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return
	}

	s.startSession(writer, issued)
	response.Redirect(writer, http.StatusTemporaryRedirect, destination)
}

// refuseProvider answers a login the provider did not complete. The provider's
// own words are not repeated: they can quote the code that was sent.
func (s *Server) refuseProvider(writer http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, providers.ErrProviderRefused) || errors.Is(err, providers.ErrUnusableIdentity) {
		s.logger.Warn().
			Str("request_id", requestIDOf(request)).
			Msg("a provider did not complete a sign-in")
		response.Error(writer, http.StatusForbidden, detailNoSuchLogin)

		return
	}

	s.refuseUnavailable(writer, request, err)
}
