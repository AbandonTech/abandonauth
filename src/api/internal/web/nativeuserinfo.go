package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// readOIDCAccessToken reads the access token from exactly one Authorization
// header using the Bearer scheme. A longer token than any this service signs
// is refused before it is decoded.
func readOIDCAccessToken(request *http.Request) (string, bool) {
	headers := request.Header.Values(authorizationHeader)
	if len(headers) != 1 {
		return "", false
	}

	scheme, token, found := strings.Cut(headers[0], " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) || token == "" || len(token) > oidc.MaxTokenBytes ||
		strings.ContainsAny(token, " \t") {
		return "", false
	}

	return token, true
}

// nativeUserInfo describes the person an OIDC access token was issued for, to
// the client it was issued to.
//
// The signature, the claims and the lifetime are checked first; then, under
// the shared authority lock, the client, the person, the subject, the epoch
// and revocation, so a token withdrawn here stops working here at once.
func (s *Server) nativeUserInfo() http.Handler {
	return withPublicProtocolAdmission(s.admission, refuseOAuthOverload, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			response.NoStore(writer)

			token, readable := readOIDCAccessToken(request)
			if !readable {
				refuseAccessToken(writer)

				return
			}

			claims, err := s.accessTokens.Verify(token)
			if err != nil {
				refuseAccessToken(writer)

				return
			}

			scopes, err := oidc.ParseScopes(claims.Scope)
			if err != nil || !scopes.Has(oidc.ScopeOpenID) {
				response.BearerError(writer, http.StatusForbidden,
					response.OAuthInsufficientScope, response.InsufficientScopeChallenge)

				return
			}

			holder, err := s.subjects.Holder(request.Context(),
				uuid.MustParse(claims.ClientID), claims.Subject, claims.Identifier(), uuid.MustParse(claims.AuthEpoch))
			if errors.Is(err, oauth.ErrAccessNotGranted) {
				refuseAccessToken(writer)

				return
			}

			if err != nil {
				s.refuseOAuthFailure(writer, request)

				return
			}

			released := models.UserInfoDto{Subject: claims.Subject}
			if scopes.Has(oidc.ScopeProfile) {
				released.PreferredUsername = &holder.Username
			}

			response.JSON(writer, http.StatusOK, released)
		}))
}

// refuseAccessToken answers a missing or unaccepted access token with the
// fixed challenge, quoting nothing.
func refuseAccessToken(writer http.ResponseWriter) {
	response.BearerError(writer, http.StatusUnauthorized, response.OAuthInvalidToken, response.InvalidTokenChallenge)
}
