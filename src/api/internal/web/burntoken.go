package web

import (
	"net/http"

	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// readWithdrawnCredential reads the credential a caller asks to have withdrawn.
// It is required, and is any value the caller is holding rather than a shape
// this service checks.
func readWithdrawnCredential(given *inputs.Inputs) string {
	given.DecodeObjectBody()

	return given.BodyString("token")
}

// burnToken withdraws a credential before it would have expired.
//
// A one-time code is removed and an access token is recorded as refused for the
// rest of its life. The answer is the same whether the value was withdrawn,
// was already gone, or never existed, so the endpoint cannot be used to
// discover which credentials are outstanding.
func (s *Server) burnToken() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		given := inputs.New(request)
		presented := readWithdrawnCredential(given)

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
