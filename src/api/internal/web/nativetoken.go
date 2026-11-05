package web

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// The two grants the token endpoint redeems.
const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
)

// The token request's members. The client authentication members are read only
// so that presenting one can be refused: this endpoint authenticates no
// client.
const (
	parameterGrantType           = "grant_type"
	parameterCode                = "code"
	parameterCodeVerifier        = "code_verifier"
	parameterRefreshToken        = "refresh_token"
	parameterClientSecret        = "client_secret"
	parameterClientAssertion     = "client_assertion"
	parameterClientAssertionType = "client_assertion_type"
)

var tokenParameters = []string{
	parameterGrantType, parameterClientID, parameterCode, parameterRedirectURI, parameterCodeVerifier,
	parameterRefreshToken, parameterScope, parameterClientSecret, parameterClientAssertion,
	parameterClientAssertionType,
}

// accessTokenLifetimeSeconds is what every token response states as the access
// token's life.
const accessTokenLifetimeSeconds = int64(oidc.AccessTokenLifetime / time.Second)

var (
	opaqueCredential = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	codeVerifier     = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// nativeTokenRequest is a token request as read, before any of it is looked up.
type nativeTokenRequest struct {
	grant    string
	clientID uuid.UUID

	code         string
	redirectURI  string
	codeVerifier string

	refreshToken string

	// scopes is nil when a refresh keeps its grant.
	scopes *oidc.Scopes
}

// readNativeTokenRequest reads a token request and returns the OAuth error its
// first fault earns, or the empty string.
func readNativeTokenRequest(request *http.Request) (nativeTokenRequest, string) {
	if len(request.Header.Values(authorizationHeader)) != 0 {
		return nativeTokenRequest{}, response.OAuthInvalidRequest
	}

	parameters, err := inputs.OAuthForm(request, tokenParameters)
	if err != nil {
		return nativeTokenRequest{}, response.OAuthInvalidRequest
	}

	for _, authentication := range []string{parameterClientSecret, parameterClientAssertion, parameterClientAssertionType} {
		if parameters.Has(authentication) {
			return nativeTokenRequest{}, response.OAuthInvalidRequest
		}
	}

	grant, count := parameters.Lookup(parameterGrantType)
	if count != 1 || grant == "" {
		return nativeTokenRequest{}, response.OAuthInvalidRequest
	}

	clientID, readable := readClientID(parameters)

	switch grant {
	case grantAuthorizationCode:
		read, refusal := readCodeGrant(parameters)
		if refusal == "" && !readable {
			refusal = response.OAuthInvalidRequest
		}

		read.clientID = clientID

		return read, refusal
	case grantRefreshToken:
		read, refusal := readRefreshGrant(parameters)
		if refusal == "" && !readable {
			refusal = response.OAuthInvalidRequest
		}

		read.clientID = clientID

		return read, refusal
	default:
		return nativeTokenRequest{}, response.OAuthUnsupportedGrantType
	}
}

// readCodeGrant reads exactly the members an authorization code grant has.
func readCodeGrant(parameters inputs.OAuthParameters) (nativeTokenRequest, string) {
	if parameters.Has(parameterRefreshToken) || parameters.Has(parameterScope) {
		return nativeTokenRequest{}, response.OAuthInvalidRequest
	}

	code, codeCount := parameters.Lookup(parameterCode)
	redirectURI, redirectCount := parameters.Lookup(parameterRedirectURI)
	verifier, verifierCount := parameters.Lookup(parameterCodeVerifier)

	if codeCount != 1 || redirectCount != 1 || verifierCount != 1 || !opaqueCredential.MatchString(code) ||
		redirectURI == "" || len(redirectURI) > urlpolicy.MaxNativeRedirectBytes ||
		!codeVerifier.MatchString(verifier) {
		return nativeTokenRequest{}, response.OAuthInvalidRequest
	}

	return nativeTokenRequest{
		grant: grantAuthorizationCode, code: code, redirectURI: redirectURI, codeVerifier: verifier,
	}, ""
}

// readRefreshGrant reads exactly the members a refresh grant has.
func readRefreshGrant(parameters inputs.OAuthParameters) (nativeTokenRequest, string) {
	if parameters.Has(parameterCode) || parameters.Has(parameterRedirectURI) || parameters.Has(parameterCodeVerifier) {
		return nativeTokenRequest{}, response.OAuthInvalidRequest
	}

	token, count := parameters.Lookup(parameterRefreshToken)
	if count != 1 || !opaqueCredential.MatchString(token) {
		return nativeTokenRequest{}, response.OAuthInvalidRequest
	}

	read := nativeTokenRequest{grant: grantRefreshToken, refreshToken: token}

	scope, scopeCount := parameters.Lookup(parameterScope)
	if scopeCount > 1 {
		return nativeTokenRequest{}, response.OAuthInvalidRequest
	}

	if scopeCount == 1 {
		scopes, err := oidc.ParseScopes(scope)
		if errors.Is(err, oidc.ErrMalformedScope) {
			return nativeTokenRequest{}, response.OAuthInvalidRequest
		}

		if err != nil {
			return nativeTokenRequest{}, response.OAuthInvalidScope
		}

		read.scopes = &scopes
	}

	return read, ""
}

// nativeToken redeems an authorization code or rotates a refresh token for a
// public client. Nothing it answers may be cached.
func (s *Server) nativeToken() http.Handler {
	return withPublicProtocolAdmission(s.admission, refuseOAuthOverload, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			response.NoStore(writer)

			read, refusal := readNativeTokenRequest(request)
			if refusal != "" {
				response.OAuthError(writer, http.StatusBadRequest, refusal)

				return
			}

			if _, err := s.applications.PublicClient(request.Context(), read.clientID); err != nil {
				if errors.Is(err, applications.ErrNoSuchApplication) {
					response.OAuthError(writer, http.StatusBadRequest, response.OAuthInvalidClient)

					return
				}

				s.refuseOAuthFailure(writer, request)

				return
			}

			var (
				issued oauth.IssuedTokens
				err    error
			)

			if read.grant == grantAuthorizationCode {
				issued, err = s.nativeCodes.Redeem(request.Context(), oauth.Redemption{
					ClientID:    read.clientID,
					Code:        read.code,
					RedirectURI: read.redirectURI,
					Verifier:    read.codeVerifier,
				}, s.signGrant)
			} else {
				issued, err = s.refreshTokens.Rotate(request.Context(), oauth.Refresh{
					ClientID: read.clientID,
					Token:    read.refreshToken,
					Scopes:   read.scopes,
				}, s.signGrant)
			}

			switch {
			case errors.Is(err, oauth.ErrInvalidGrant):
				response.OAuthError(writer, http.StatusBadRequest, response.OAuthInvalidGrant)
			case errors.Is(err, oauth.ErrScopeNotGranted):
				response.OAuthError(writer, http.StatusBadRequest, response.OAuthInvalidScope)
			case err != nil:
				s.refuseOAuthFailure(writer, request)
			default:
				response.JSON(writer, http.StatusOK, models.TokenSetDto{
					AccessToken:           issued.AccessToken,
					TokenType:             "Bearer",
					ExpiresIn:             accessTokenLifetimeSeconds,
					IDToken:               issued.IDToken,
					Scope:                 issued.Scopes.String(),
					RefreshToken:          issued.RefreshToken,
					RefreshTokenExpiresIn: issued.RefreshExpiresIn,
				})
			}
		}))
}

// signGrant signs the access and ID tokens for a grant, both naming the user
// by their AbandonAuth identifier. The username is released only under profile.
func (s *Server) signGrant(grant oauth.Grant) (oauth.SignedTokens, error) {
	accessToken, _, err := s.issuer.IssueAccessToken(oidc.Access{
		Subject: grant.UserID, ClientID: grant.ClientID, Scopes: grant.Scopes, AuthEpoch: grant.AuthEpoch,
	})
	if err != nil {
		return oauth.SignedTokens{}, err
	}

	identity := oidc.Identity{
		Subject: grant.UserID, ClientID: grant.ClientID, AuthTime: grant.AuthTime, Nonce: grant.Nonce,
	}

	if grant.Scopes.Has(oidc.ScopeProfile) {
		username := grant.Username
		identity.Username = &username
	}

	idToken, err := s.issuer.IssueIDToken(identity)
	if err != nil {
		return oauth.SignedTokens{}, err
	}

	return oauth.SignedTokens{AccessToken: accessToken, IDToken: idToken}, nil
}

// refuseOAuthFailure answers an OAuth request that could not be completed,
// saying nothing about why.
func (s *Server) refuseOAuthFailure(writer http.ResponseWriter, request *http.Request) {
	s.logPublicProtocolFailure(request)
	response.OAuthError(writer, http.StatusInternalServerError, response.OAuthServerError)
}
