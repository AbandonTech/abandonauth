package web

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// What the authorization page's API answers when it refuses. Every refusal of
// one kind carries the same words, so none says which check failed.
const (
	detailAuthorizationRequestUnavailable = "Authorization request unavailable"
	detailAuthorizationRequestForbidden   = "Authorization request forbidden"
)

// authorizationPagePath is where the site shows a pending authorization. The
// handle travels after it in the fragment, which a browser never sends to a
// server or puts in a referrer.
const authorizationPagePath = "/authorize#request="

// expiresAtLayout is the UTC instant in whole seconds with a trailing Z.
const expiresAtLayout = "2006-01-02T15:04:05Z"

// The authorization request's parameters. Anything else is ignored.
const (
	parameterResponseType        = "response_type"
	parameterClientID            = "client_id"
	parameterRedirectURI         = "redirect_uri"
	parameterScope               = "scope"
	parameterState               = "state"
	parameterNonce               = "nonce"
	parameterCodeChallenge       = "code_challenge"
	parameterCodeChallengeMethod = "code_challenge_method"
	parameterResponseMode        = "response_mode"
)

var authorizationParameters = []string{
	parameterResponseType, parameterClientID, parameterRedirectURI, parameterScope, parameterState,
	parameterNonce, parameterCodeChallenge, parameterCodeChallengeMethod, parameterResponseMode,
}

var (
	canonicalClientID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	clientRandomValue = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
)

// nativeAuthorizationRequest is an authorization request as read, before any
// of it is looked up.
type nativeAuthorizationRequest struct {
	clientID    uuid.UUID
	redirectURI string

	// clientState is the client's state when exactly one syntactically valid
	// one was given, and empty otherwise; only then is it echoed.
	clientState string

	// refusal is the OAuth error the client is to be redirected with once the
	// client and the redirect are proven, or empty when nothing else is wrong.
	refusal string

	scopes        oidc.Scopes
	nonce         string
	codeChallenge string
}

// readNativeAuthorizationRequest reads an authorization request from its
// query. It reports false when the client or the redirect cannot be read,
// which is refused without a redirect; every other fault is recorded as the
// refusal to redirect with once those two are proven.
func readNativeAuthorizationRequest(request *http.Request) (nativeAuthorizationRequest, bool) {
	parameters, err := inputs.OAuthQuery(request, authorizationParameters)
	if err != nil {
		return nativeAuthorizationRequest{}, false
	}

	clientID, readable := readClientID(parameters)
	if !readable {
		return nativeAuthorizationRequest{}, false
	}

	redirectURI, count := parameters.Lookup(parameterRedirectURI)
	if count != 1 || redirectURI == "" || len(redirectURI) > urlpolicy.MaxNativeRedirectBytes {
		return nativeAuthorizationRequest{}, false
	}

	read := nativeAuthorizationRequest{clientID: clientID, redirectURI: redirectURI}

	if state, count := parameters.Lookup(parameterState); count == 1 && clientRandomValue.MatchString(state) {
		read.clientState = state
	}

	read.refusal = read.readRemaining(parameters)

	return read, true
}

// readRemaining reads everything but the client and the redirect, and returns
// the OAuth error the first fault earns.
func (r *nativeAuthorizationRequest) readRemaining(parameters inputs.OAuthParameters) string {
	for _, name := range []string{
		parameterResponseType, parameterScope, parameterState, parameterNonce,
		parameterCodeChallenge, parameterCodeChallengeMethod,
	} {
		if value, count := parameters.Lookup(name); count != 1 || value == "" {
			return response.OAuthInvalidRequest
		}
	}

	nonce, _ := parameters.Lookup(parameterNonce)
	challenge, _ := parameters.Lookup(parameterCodeChallenge)
	method, _ := parameters.Lookup(parameterCodeChallengeMethod)

	if r.clientState == "" || !clientRandomValue.MatchString(nonce) || !credentials.IsOpaqueValue(challenge) ||
		method != "S256" {
		return response.OAuthInvalidRequest
	}

	if mode, count := parameters.Lookup(parameterResponseMode); count > 1 || (count == 1 && mode != "query") {
		return response.OAuthInvalidRequest
	}

	if responseType, _ := parameters.Lookup(parameterResponseType); responseType != "code" {
		return response.OAuthUnsupportedResponseType
	}

	scope, _ := parameters.Lookup(parameterScope)

	scopes, err := oidc.ParseScopes(scope)
	if errors.Is(err, oidc.ErrMalformedScope) {
		return response.OAuthInvalidRequest
	}

	if err != nil {
		return response.OAuthInvalidScope
	}

	r.scopes = scopes
	r.nonce = nonce
	r.codeChallenge = challenge

	return ""
}

// readClientID reads a client identifier given exactly once in its canonical
// lower-case spelling.
func readClientID(parameters inputs.OAuthParameters) (uuid.UUID, bool) {
	value, count := parameters.Lookup(parameterClientID)
	if count != 1 || !canonicalClientID.MatchString(value) {
		return uuid.Nil, false
	}

	return uuid.MustParse(value), true
}

// nativeAuthorize begins a public client's authorization.
//
// The client and the redirect are proven before the redirect is used for
// anything, so no refusal is ever sent to an address the client did not
// register. The browser is then sent to the site's authorization page with an
// opaque handle in the fragment, never to a provider: the person chooses.
func (s *Server) nativeAuthorize() http.Handler {
	return withPublicProtocolAdmission(s.admission, refuseAuthorizationOverload, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			response.AuthorizationPage(writer)
			response.NoStore(writer)

			read, readable := readNativeAuthorizationRequest(request)
			if !readable {
				response.OAuthError(writer, http.StatusBadRequest, response.OAuthInvalidRequest)

				return
			}

			redirect, proven := s.provenRedirect(writer, request, read)
			if !proven {
				return
			}

			if read.refusal != "" {
				s.returnToClient(writer, redirect, read.clientState, read.refusal)

				return
			}

			begun, err := s.authorizations.Begin(request.Context(), oauth.AuthorizationRequest{
				ApplicationID: read.clientID,
				RedirectURI:   redirect,
				Scopes:        read.scopes,
				ClientState:   read.clientState,
				ClientNonce:   read.nonce,
				CodeChallenge: read.codeChallenge,
				HeldBinding:   s.nativeBinding(request),
			})
			if errors.Is(err, oauth.ErrAuthorizationCapacity) {
				s.returnToClient(writer, redirect, read.clientState, response.OAuthTemporarilyUnavailable)

				return
			}

			if err != nil {
				s.logPublicProtocolFailure(request)
				s.returnToClient(writer, redirect, read.clientState, response.OAuthServerError)

				return
			}

			s.bindAuthorizationToBrowser(writer, begun.BrowserBinding)
			response.OAuthRedirect(writer, s.config.Site.String()+authorizationPagePath+begun.PageHandle)
		}))
}

// provenRedirect establishes that the client is a registered public client and
// the redirect one of its templates with a port added, answering the request
// itself when either is not.
func (s *Server) provenRedirect(
	writer http.ResponseWriter, request *http.Request, read nativeAuthorizationRequest,
) (string, bool) {
	client, err := s.applications.PublicClient(request.Context(), read.clientID)
	if errors.Is(err, applications.ErrNoSuchApplication) {
		response.OAuthError(writer, http.StatusBadRequest, response.OAuthInvalidRequest)

		return "", false
	}

	if err != nil {
		s.logPublicProtocolFailure(request)
		response.OAuthError(writer, http.StatusInternalServerError, response.OAuthServerError)

		return "", false
	}

	redirect, matched, err := s.applications.NativeRedirect(request.Context(), client, read.redirectURI)
	if err != nil {
		s.logPublicProtocolFailure(request)
		response.OAuthError(writer, http.StatusInternalServerError, response.OAuthServerError)

		return "", false
	}

	if !matched {
		response.OAuthError(writer, http.StatusBadRequest, response.OAuthInvalidRequest)

		return "", false
	}

	return redirect, true
}

// returnToClient sends the browser to a proven redirect with an OAuth error,
// the client's state when it gave a valid one, and this issuer.
func (s *Server) returnToClient(writer http.ResponseWriter, redirect, clientState, code string) {
	parameters := [][2]string{{"error", code}}
	if clientState != "" {
		parameters = append(parameters, [2]string{"state", clientState})
	}

	parameters = append(parameters, [2]string{"iss", s.issuer.Identifier()})

	response.AuthorizationPage(writer)
	response.OAuthRedirect(writer, urlpolicy.NativeAuthorizationResponse(redirect, parameters...))
}

// returnCodeToClient sends the browser to a proven redirect with its code.
func (s *Server) returnCodeToClient(writer http.ResponseWriter, redirect, clientState, code string) {
	response.AuthorizationPage(writer)
	response.OAuthRedirect(writer, urlpolicy.NativeAuthorizationResponse(redirect,
		[2]string{"code", code}, [2]string{"state", clientState}, [2]string{"iss", s.issuer.Identifier()},
	))
}

// readAuthorizationPageHandle reads the page handle from the path. Only an
// opaque value of the exact length a handle has is looked up.
func readAuthorizationPageHandle(request *http.Request) (string, bool) {
	handle := request.PathValue("request")

	return handle, credentials.IsOpaqueValue(handle)
}

// readProviderSelection reads the handle and the provider the person chose.
func readProviderSelection(request *http.Request) (string, oauth.Provider, bool) {
	handle, readable := readAuthorizationPageHandle(request)
	provider, known := oauth.ParseProvider(request.PathValue("provider"))

	return handle, provider, readable && known
}

// nativeAuthorizationView answers what the authorization page shows, and only
// to the browser the authorization is bound to. Reading changes nothing.
func (s *Server) nativeAuthorizationView() http.Handler {
	return withPublicProtocolAdmission(s.admission, refusePageOverload, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			response.AuthorizationPage(writer)

			handle, readable := readAuthorizationPageHandle(request)
			if !readable {
				response.Error(writer, http.StatusNotFound, detailAuthorizationRequestUnavailable)

				return
			}

			pending, err := s.authorizations.View(request.Context(), handle, s.nativeBinding(request))
			if errors.Is(err, oauth.ErrNoSuchAuthorization) {
				response.Error(writer, http.StatusNotFound, detailAuthorizationRequestUnavailable)

				return
			}

			if err != nil {
				s.refusePageFailure(writer, request)

				return
			}

			providers := make([]string, 0, len(oauth.Providers))
			for _, provider := range oauth.Providers {
				providers = append(providers, string(provider))
			}

			response.JSON(writer, http.StatusOK, models.PendingAuthorizationDto{
				ApplicationName: pending.ApplicationName,
				Scopes:          pending.Scopes.Names(),
				ExpiresAt:       pending.ExpiresAt.UTC().Truncate(time.Second).Format(expiresAtLayout),
				Providers:       providers,
			})
		}))
}

// nativeProviderSelection spends a pending authorization on the provider the
// person chose and sends the browser there.
func (s *Server) nativeProviderSelection() http.Handler {
	return withPublicProtocolAdmission(s.admission, refusePageOverload, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			response.AuthorizationPage(writer)

			if !s.fromSiteOnly(request) {
				response.Error(writer, http.StatusForbidden, detailAuthorizationRequestForbidden)

				return
			}

			handle, provider, readable := readProviderSelection(request)
			if !readable {
				response.Error(writer, http.StatusNotFound, detailAuthorizationRequestUnavailable)

				return
			}

			started, err := s.authorizations.BeginProvider(
				request.Context(), handle, s.nativeBinding(request), provider,
			)
			if errors.Is(err, oauth.ErrNoSuchAuthorization) {
				response.Error(writer, http.StatusNotFound, detailAuthorizationRequestUnavailable)

				return
			}

			if err != nil {
				s.refusePageFailure(writer, request)

				return
			}

			response.OAuthRedirect(writer, s.authorizationURL(provider, started))
		}))
}

// cancelNativeAuthorization spends a pending authorization without a sign-in
// and tells the client the person declined.
func (s *Server) cancelNativeAuthorization() http.Handler {
	return withPublicProtocolAdmission(s.admission, refusePageOverload, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			response.AuthorizationPage(writer)

			if !s.fromSiteOnly(request) {
				response.Error(writer, http.StatusForbidden, detailAuthorizationRequestForbidden)

				return
			}

			handle, readable := readAuthorizationPageHandle(request)
			if !readable {
				response.Error(writer, http.StatusNotFound, detailAuthorizationRequestUnavailable)

				return
			}

			cancelled, err := s.authorizations.Cancel(request.Context(), handle, s.nativeBinding(request))
			if errors.Is(err, oauth.ErrNoSuchAuthorization) {
				response.Error(writer, http.StatusNotFound, detailAuthorizationRequestUnavailable)

				return
			}

			if err != nil {
				s.refusePageFailure(writer, request)

				return
			}

			s.returnToClient(writer, cancelled.RedirectURI, cancelled.ClientState, response.OAuthAccessDenied)
		}))
}

// fromSiteOnly reports whether a request carried exactly one Origin header,
// naming exactly the site.
func (s *Server) fromSiteOnly(request *http.Request) bool {
	origins := request.Header.Values(originHeader)

	return len(origins) == 1 && s.config.Site.MatchesHeader(origins[0])
}

// refusePageFailure answers an authorization page request that could not be
// completed, saying nothing about why.
func (s *Server) refusePageFailure(writer http.ResponseWriter, request *http.Request) {
	s.logPublicProtocolFailure(request)
	response.Error(writer, http.StatusInternalServerError, detailUnavailable)
}

// logPublicProtocolFailure records that a public-client request failed, and
// nothing else: the request and the error can both carry a credential.
func (s *Server) logPublicProtocolFailure(request *http.Request) {
	s.logger.Error().
		Str("request_id", requestIDOf(request)).
		Msg("a public-client request could not be answered")
}
