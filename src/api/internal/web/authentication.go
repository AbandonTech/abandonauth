package web

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/sessions"
	"github.com/abandontech/abandonauth/src/api/internal/services/tokens"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// Headers a caller authenticates or protects a request with.
const (
	authorizationHeader = "Authorization"
	bearerScheme        = "Bearer"

	// CSRFHeader carries the value the site copied out of the token cookie. A
	// site on another origin can cause a cookie to be sent but cannot read one,
	// so only this service's own site can set it correctly.
	CSRFHeader = "X-CSRF-Token"

	// ExchangeTokenHeader carries the one-time code an application spends for
	// an access token.
	ExchangeTokenHeader = "exchange-token"

	originHeader = "Origin"
)

// What a caller is told when it is not allowed through. The wording is the same
// whoever they are: nothing here says whether a token, an account or an
// application exists.
const (
	detailNotAuthenticated  = "Not authenticated"
	detailInvalidCredential = "Invalid authentication credentials"
	detailInvalidToken      = "Invalid token format"
	detailExpiredToken      = "Token has expired"
	detailMissingScope      = "JWT lacks the required scope to access this endpoint."
	detailUnsafeRequest     = "This request could not be confirmed as coming from the AbandonAuth site"
	detailUnavailable       = "Internal Server Error"
)

// Caller is the person a request was made by.
type Caller struct {
	UserID uuid.UUID

	// FromBrowser reports that the caller proved itself with a session cookie
	// rather than a token, which is what makes a request subject to the
	// cross-site checks.
	FromBrowser bool

	// SessionValue is the cookie the session was found by, so a request that
	// ends the session can delete exactly it.
	SessionValue string
}

// audiencePolicy says which applications a person's token may have been issued
// to for a route to accept it.
type audiencePolicy int

const (
	// audienceInternal accepts only a token issued to the AbandonAuth site
	// itself. A token an application holds must not manage its owner's account.
	audienceInternal audiencePolicy = iota
	// audienceRegisteredApplication accepts a token issued to any application
	// that still exists.
	audienceRegisteredApplication
)

// requireUser authenticates the person behind a request, by access token or by
// browser session, and answers the request itself when it cannot.
func (s *Server) requireUser(
	writer http.ResponseWriter, request *http.Request, scope string, policy audiencePolicy,
) (Caller, bool) {
	presented, wellFormed := bearerCredential(request)

	switch {
	case presented != "":
		if !wellFormed {
			response.Error(writer, http.StatusForbidden, detailInvalidCredential)

			return Caller{}, false
		}

		return s.callerFromToken(writer, request, presented, scope, policy)
	case cookieValue(request, s.SessionCookieName()) != "":
		return s.callerFromSession(writer, request)
	default:
		response.Error(writer, http.StatusForbidden, detailNotAuthenticated)

		return Caller{}, false
	}
}

func (s *Server) callerFromToken(
	writer http.ResponseWriter, request *http.Request, presented, scope string, policy audiencePolicy,
) (Caller, bool) {
	token, ok := s.acceptToken(request.Context(), writer, presented)
	if !ok {
		return Caller{}, false
	}

	if token.Class != tokens.UserAccess {
		response.Error(writer, http.StatusForbidden, detailInvalidToken)

		return Caller{}, false
	}

	if !token.HasScope(scope) {
		response.Error(writer, http.StatusForbidden, detailMissingScope)

		return Caller{}, false
	}

	if !s.audienceAccepted(request.Context(), writer, token.Audience, policy) {
		return Caller{}, false
	}

	if _, err := s.accounts.Get(request.Context(), token.Subject); err != nil {
		s.refusePrincipal(writer, request, err)

		return Caller{}, false
	}

	return Caller{UserID: token.Subject}, true
}

func (s *Server) callerFromSession(writer http.ResponseWriter, request *http.Request) (Caller, bool) {
	value := cookieValue(request, s.SessionCookieName())

	session, err := s.sessions.Lookup(request.Context(), value)
	if errors.Is(err, sessions.ErrNoSuchSession) {
		s.endSession(writer)
		response.Error(writer, http.StatusForbidden, detailNotAuthenticated)

		return Caller{}, false
	}

	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return Caller{}, false
	}

	if changesState(request.Method) && !s.confirmedBySite(request, session) {
		response.Error(writer, http.StatusForbidden, detailUnsafeRequest)

		return Caller{}, false
	}

	return Caller{UserID: session.UserID, FromBrowser: true, SessionValue: value}, true
}

// requireApplication authenticates a developer application by its own access
// token.
func (s *Server) requireApplication(
	writer http.ResponseWriter, request *http.Request,
) (applications.Application, bool) {
	presented, wellFormed := bearerCredential(request)

	if presented == "" {
		response.Error(writer, http.StatusForbidden, detailNotAuthenticated)

		return applications.Application{}, false
	}

	if !wellFormed {
		response.Error(writer, http.StatusForbidden, detailInvalidCredential)

		return applications.Application{}, false
	}

	token, ok := s.acceptToken(request.Context(), writer, presented)
	if !ok {
		return applications.Application{}, false
	}

	application, err := s.applicationBehind(request.Context(), token)
	if err != nil {
		s.refusePrincipal(writer, request, err)

		return applications.Application{}, false
	}

	return application, true
}

// applicationBehind returns the application a token speaks for, provided the
// token is of that class, was issued to this service, and was issued against
// the credential the application holds now.
func (s *Server) applicationBehind(
	ctx context.Context, token tokens.Token,
) (applications.Application, error) {
	if token.Class != tokens.DeveloperApplicationAccess ||
		token.Audience != s.config.InternalApplicationID ||
		!token.HasScope(tokens.ScopeAbandonauth) ||
		!token.HasScope(tokens.ScopeIdentify) {
		return applications.Application{}, applications.ErrNoSuchApplication
	}

	application, err := s.applications.Get(ctx, token.Subject)
	if err != nil {
		return applications.Application{}, err
	}

	if application.CredentialVersion != token.CredentialVersion {
		return applications.Application{}, applications.ErrNoSuchApplication
	}

	return application, nil
}

// acceptToken verifies a token and that the authority behind it still stands.
func (s *Server) acceptToken(
	ctx context.Context, writer http.ResponseWriter, presented string,
) (tokens.Token, bool) {
	token, err := s.signer.Verify(presented)
	if errors.Is(err, tokens.ErrExpired) {
		response.Error(writer, http.StatusForbidden, detailExpiredToken)

		return tokens.Token{}, false
	}

	if err != nil {
		response.Error(writer, http.StatusForbidden, detailInvalidToken)

		return tokens.Token{}, false
	}

	current, err := s.authority.Current(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("the current authority could not be read")
		response.Error(writer, http.StatusInternalServerError, detailUnavailable)

		return tokens.Token{}, false
	}

	if token.AuthEpoch != current {
		response.Error(writer, http.StatusForbidden, detailInvalidToken)

		return tokens.Token{}, false
	}

	withdrawn, err := s.authority.IsWithdrawn(ctx, token.ID)
	if err != nil {
		s.logger.Error().Err(err).Msg("whether a token was withdrawn could not be read")
		response.Error(writer, http.StatusInternalServerError, detailUnavailable)

		return tokens.Token{}, false
	}

	if withdrawn {
		response.Error(writer, http.StatusForbidden, detailInvalidToken)

		return tokens.Token{}, false
	}

	return token, true
}

func (s *Server) audienceAccepted(
	ctx context.Context, writer http.ResponseWriter, audience uuid.UUID, policy audiencePolicy,
) bool {
	if policy == audienceInternal {
		if audience != s.config.InternalApplicationID {
			response.Error(writer, http.StatusForbidden, detailInvalidToken)

			return false
		}

		return true
	}

	_, err := s.applications.Get(ctx, audience)
	if errors.Is(err, applications.ErrNoSuchApplication) {
		response.Error(writer, http.StatusForbidden, detailInvalidToken)

		return false
	}

	if err != nil {
		s.logger.Error().Err(err).Msg("the application a token names could not be read")
		response.Error(writer, http.StatusInternalServerError, detailUnavailable)

		return false
	}

	return true
}

// confirmedBySite reports whether a state-changing request really came from the
// site rather than from a page that merely caused the cookie to be sent.
//
// Both checks are needed: the origin says who made the request, and the token
// proves the maker could read a cookie, which only this origin can.
func (s *Server) confirmedBySite(request *http.Request, session sessions.Session) bool {
	if !s.config.Site.MatchesHeader(request.Header.Get(originHeader)) {
		return false
	}

	presented := request.Header.Get(CSRFHeader)
	fromCookie := cookieValue(request, s.CSRFCookieName())

	if presented == "" || fromCookie == "" {
		return false
	}

	if !credentials.Equal([]byte(presented), []byte(fromCookie)) {
		return false
	}

	return session.MatchesCSRFToken(presented)
}

// refusePrincipal answers a request whose credential was good but whose account
// or application is gone, without saying which of the two happened.
func (s *Server) refusePrincipal(writer http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, accounts.ErrNoSuchUser) || errors.Is(err, applications.ErrNoSuchApplication) {
		response.Error(writer, http.StatusForbidden, detailInvalidToken)

		return
	}

	s.refuseUnavailable(writer, request, err)
}

func (s *Server) refuseUnavailable(writer http.ResponseWriter, request *http.Request, err error) {
	s.logger.Error().
		Str("request_id", requestIDOf(request)).
		Err(err).
		Msg("a request could not be answered")

	response.Error(writer, http.StatusInternalServerError, detailUnavailable)
}

// bearerCredential returns the credential in the Authorization header and
// whether the header was well formed. An absent header is not malformed; a
// header that names another scheme is.
func bearerCredential(request *http.Request) (string, bool) {
	header := strings.TrimSpace(request.Header.Get(authorizationHeader))
	if header == "" {
		return "", true
	}

	scheme, credential, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) {
		return header, false
	}

	credential = strings.TrimSpace(credential)
	if credential == "" {
		return header, false
	}

	return credential, true
}

func changesState(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}
