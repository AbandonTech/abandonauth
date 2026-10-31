package web

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// What a caller is told when a login cannot be started or finished. At start,
// an unknown application and an unregistered callback share one detail. Once a
// callback begins consuming login state, every failure shares the other:
// unknown, expired, replayed, browser-mismatched or provider-mismatched state,
// a provider refusal, an incomplete identity and a stored callback that no
// longer passes policy are indistinguishable.
const (
	detailUnknownApplicationOrCallback = "Invalid application ID or callback URI"
	detailSignInValidationFailed       = "Sign-in validation failed"
)

// messageUnknownProvider is the input refusal message for a provider path
// value this service does not offer.
const messageUnknownProvider = "Input must be discord, github, google, or steam"

// providerAuthorize starts a login with a provider.
//
// The application and the exact callback are checked here, before anything is
// stored, and are then held by this service until the provider returns. What
// travels through the browser is an opaque value that means nothing on its own.
func (s *Server) providerAuthorize() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		given := inputs.New(request)
		wanted := readProviderLoginInputs(given)

		if !given.OK() {
			response.Invalid(writer, given.Failures())

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
			Message:  messageUnknownProvider,
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
	case oauth.Steam:
		return s.steam.AuthorizationURL(started.State)
	default:
		return ""
	}
}

// resumeLogin reads the state and the browser's cookie and spends the login
// they name, returning the authorization code the provider sent back.
func (s *Server) resumeLogin(
	writer http.ResponseWriter, request *http.Request, provider oauth.Provider,
) (oauth.Login, string, bool) {
	login, consumed := s.consumeLogin(writer, request, provider, request.URL.Query().Get("state"))
	if !consumed {
		return oauth.Login{}, "", false
	}

	return login, request.URL.Query().Get(urlpolicy.ExchangeCodeQueryKey), true
}

// consumeLogin spends the login a state and the browser's cookie name.
//
// It answers the request itself on every failure, always with the same detail:
// a state that was never issued, that has expired, that has already been used,
// that is bound to another browser and that was started with another provider
// are indistinguishable from outside.
func (s *Server) consumeLogin(
	writer http.ResponseWriter, request *http.Request, provider oauth.Provider, state string,
) (oauth.Login, bool) {
	binding := cookieValue(request, s.LoginCookieName())

	login, err := s.logins.Consume(request.Context(), provider, state, binding)
	if errors.Is(err, oauth.ErrNoSuchLogin) {
		response.Error(writer, http.StatusForbidden, detailSignInValidationFailed)

		return oauth.Login{}, false
	}

	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return oauth.Login{}, false
	}

	return login, true
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
		response.Error(writer, http.StatusForbidden, detailSignInValidationFailed)

		return
	}

	person, err := s.accounts.Resolve(request.Context(), identity)
	if errors.Is(err, accounts.ErrUnusableIdentity) {
		response.Error(writer, http.StatusForbidden, detailSignInValidationFailed)

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

// refuseProvider answers a login the provider did not authenticate. Neither
// the provider's response nor the internal reason is repeated or logged: either
// can quote the code that was sent or a token claim.
func (s *Server) refuseProvider(writer http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, providers.ErrProviderRefused) || errors.Is(err, providers.ErrUnusableIdentity) {
		s.logger.Warn().
			Str("request_id", requestIDOf(request)).
			Msg("a provider did not complete a sign-in")
		response.Error(writer, http.StatusForbidden, detailSignInValidationFailed)

		return
	}

	s.refuseUnavailable(writer, request, err)
}
