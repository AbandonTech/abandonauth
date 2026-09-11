package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/services/tokens"
	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// currentUser tells an application who the person behind a token is.
//
// Any application's token is accepted, as long as the application still exists:
// identifying the person is the whole purpose of the token it was given.
//
// @Summary     Current User Information
// @Description Get information about the user from a jwt token.
// @Produce     json
// @Success     200 {object} models.UserDto
// @Failure     403 {object} response.Failed "The credential was missing, refused or expired"
// @Security    JWTBearer
// @Router      /api/me [get].
func (s *Server) currentUser() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		caller, allowed := s.requireUser(writer, request, tokens.ScopeIdentify, audienceRegisteredApplication)
		if !allowed {
			return
		}

		person, err := s.accounts.Get(request.Context(), caller.UserID)
		if err != nil {
			s.refusePrincipal(writer, request, err)

			return
		}

		response.JSON(writer, http.StatusOK, models.UserDto{
			ID:       person.ID.String(),
			Username: person.Username,
		})
	})
}
