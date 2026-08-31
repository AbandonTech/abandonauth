package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// burnToken withdraws a credential before it would have expired.
//
// A one-time code is removed and an access token is recorded as refused for the
// rest of its life. The answer is the same whether the value was withdrawn,
// was already gone, or never existed, so the endpoint cannot be used to
// discover which credentials are outstanding.
//
// @Summary     Burn Jwt
// @Description Invalidate the given JWT.
// @Description
// @Description Attempts to delete the given token. Returns 200 response regardless of if the token existed.
// @Accept      json
// @Param       token body models.JwtDto true "The credential to withdraw"
// @Success     200 "The credential is no longer accepted"
// @Failure     422 {object} response.Invalidated
// @Failure     429 {object} response.Failed "Too many attempts"
// @Router      /burn-token [post].
func (s *Server) burnToken() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.withinLimit(writer, request, ratelimit.BurnToken, s.clientAddress(request)) {
			return
		}

		given := inputs.New(request)
		given.DecodeObjectBody()
		presented := given.BodyString("token")

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		if err := s.codes.Discard(request.Context(), presented); err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		// A value that is not a token this service issued needs nothing further:
		// there is no identifier to record, and saying so would tell the caller
		// what it was holding.
		if token, err := s.signer.Verify(presented); err == nil {
			if err := s.authority.Withdraw(request.Context(), token.ID, token.ExpiresAt); err != nil {
				s.refuseUnavailable(writer, request, err)

				return
			}
		}

		response.Empty(writer, http.StatusOK)
	})
}
