package web

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// parameterToken is the revocation request's token member. token_type_hint is
// deliberately not read at all, so no hint can select or suppress a lookup.
const parameterToken = "token"

var revocationParameters = []string{parameterClientID, parameterToken}

// nativeRevocationRequest is a revocation request as read.
type nativeRevocationRequest struct {
	clientID uuid.UUID
	token    string
}

// readNativeRevocationRequest reads the client and the token, each exactly
// once.
func readNativeRevocationRequest(request *http.Request) (nativeRevocationRequest, bool) {
	parameters, err := inputs.OAuthForm(request, revocationParameters)
	if err != nil {
		return nativeRevocationRequest{}, false
	}

	clientID, readable := readClientID(parameters)
	if !readable {
		return nativeRevocationRequest{}, false
	}

	token, count := parameters.Lookup(parameterToken)
	if count != 1 || token == "" || len(token) > oidc.MaxTokenBytes {
		return nativeRevocationRequest{}, false
	}

	return nativeRevocationRequest{clientID: clientID, token: token}, true
}

// nativeRevocation revokes a public client's refresh token or OIDC access
// token. Both classes are always checked, and every well-formed request that
// revokes nothing is answered exactly as one that does.
func (s *Server) nativeRevocation() http.Handler {
	return withPublicProtocolAdmission(s.admission, refuseOAuthOverload, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			response.NoStore(writer)

			read, readable := readNativeRevocationRequest(request)
			if !readable {
				response.OAuthError(writer, http.StatusBadRequest, response.OAuthInvalidRequest)

				return
			}

			if _, err := s.applications.PublicClient(request.Context(), read.clientID); err != nil {
				if errors.Is(err, applications.ErrNoSuchApplication) {
					response.Empty(writer, http.StatusOK)

					return
				}

				s.refuseOAuthFailure(writer, request)

				return
			}

			if err := s.refreshTokens.Revoke(request.Context(), read.clientID, read.token); err != nil {
				s.refuseOAuthFailure(writer, request)

				return
			}

			err := s.revokeAccessToken(request, read)
			if errors.Is(err, oauth.ErrRevocationCapacity) {
				response.OAuthError(writer, http.StatusServiceUnavailable, response.OAuthTemporarilyUnavailable)

				return
			}

			if err != nil {
				s.refuseOAuthFailure(writer, request)

				return
			}

			response.Empty(writer, http.StatusOK)
		}))
}

// revokeAccessToken records a genuine, unexpired access token of this client as
// revoked. Anything else revokes nothing and is not an error.
func (s *Server) revokeAccessToken(request *http.Request, read nativeRevocationRequest) error {
	claims, err := s.accessTokens.Verify(read.token)
	if err != nil || claims.ClientID != read.clientID.String() {
		return nil
	}

	return s.clientUsers.RevokeAccessToken(request.Context(), oauth.AccessRevocation{
		ClientID:  read.clientID,
		UserID:    claims.SubjectIdentifier(),
		TokenID:   claims.Identifier(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	})
}
