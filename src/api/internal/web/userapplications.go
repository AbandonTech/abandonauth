package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/services/tokens"
	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// userApplications lists the developer applications a person owns.
//
// Only a credential for the AbandonAuth site itself is accepted. A token an
// application was given to identify its user must not also be able to read what
// else that person has registered.
//
// @Summary     List all developer applications owned by the current user.
// @Description List all developer applications owned by the authenticated user.
// @Produce     json
// @Success     200 {array}  models.DeveloperApplicationDto
// @Failure     403 {object} response.Failed "The credential was missing, refused or expired"
// @Security    JWTBearer
// @Router      /api/user/applications [get].
func (s *Server) userApplications() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		caller, allowed := s.requireUser(writer, request, tokens.ScopeAbandonauth, audienceInternal)
		if !allowed {
			return
		}

		owned, err := s.applications.ListByOwner(request.Context(), caller.UserID)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		listed := make([]models.DeveloperApplicationDto, 0, len(owned))
		for _, application := range owned {
			listed = append(listed, describeApplication(application))
		}

		response.JSON(writer, http.StatusOK, listed)
	})
}
