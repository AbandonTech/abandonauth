package web

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
	"github.com/abandontech/abandonauth/src/api/internal/services/tokens"
	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// detailUnsafeCallback is the answer to a callback URI this service would not
// return a browser to. It says which position in the submitted list was
// refused and why, and never repeats the URI.
const detailUnsafeCallback = "One of the callback URIs is not a URI this service will return a browser to"

// readApplicationName reads the name a new application is registered under.
func readApplicationName(given *inputs.Inputs) string {
	given.DecodeObjectBody()

	return given.BodyString("name")
}

// applicationCredentials are what an application authenticates itself with.
type applicationCredentials struct {
	applicationID uuid.UUID
	refreshToken  string
}

// readApplicationCredentials reads an application's own credentials, both of
// which are required.
func readApplicationCredentials(given *inputs.Inputs) applicationCredentials {
	given.DecodeObjectBody()

	return applicationCredentials{
		applicationID: given.BodyUUID("id"),
		refreshToken:  given.BodyString("refresh_token"),
	}
}

// readApplicationIdentifier reads the application a path names.
func readApplicationIdentifier(given *inputs.Inputs) uuid.UUID {
	return given.PathUUID("application_id")
}

// readSubmittedCallbackURIs reads the complete set of URIs an application may be
// returned to. The body is the list itself, and an empty list is the way an
// application says it has no callbacks.
func readSubmittedCallbackURIs(given *inputs.Inputs) []string {
	return given.DecodeStringArrayBody()
}

// describeApplication is the published shape of an application.
func describeApplication(application applications.Application) models.DeveloperApplicationDto {
	return models.DeveloperApplicationDto{
		ID:      application.ID.String(),
		Name:    application.Name,
		OwnerID: application.OwnerID.String(),
	}
}

// createApplication registers an application owned by the caller and returns
// its refresh token, which cannot be read again.
func (s *Server) createApplication() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		caller, allowed := s.requireUser(writer, request, tokens.ScopeAbandonauth, audienceInternal)
		if !allowed {
			return
		}

		given := inputs.New(request)
		name := readApplicationName(given)

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		if !s.withinLimit(
			writer, request, ratelimit.DeveloperApplicationMutation, caller.UserID.String(),
		) {
			return
		}

		created, token, err := s.applications.Create(request.Context(), caller.UserID, name)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		response.JSON(writer, http.StatusOK, models.CreateDeveloperApplicationDto{
			ID:      created.ID.String(),
			Name:    created.Name,
			OwnerID: created.OwnerID.String(),
			Token:   token,
		})
	})
}

// applicationLogin exchanges an application's refresh token for its own access
// token.
func (s *Server) applicationLogin() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		given := inputs.New(request)
		presented := readApplicationCredentials(given)

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		application, err := s.applications.Authenticate(
			request.Context(), presented.applicationID, presented.refreshToken,
		)
		if errors.Is(err, applications.ErrInvalidCredential) {
			response.Error(writer, http.StatusUnauthorized, detailApplicationRejected)

			return
		}

		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		epoch, err := s.authority.Current(request.Context())
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		token, _, err := s.signer.IssueDeveloperApplicationAccess(
			application.ID, epoch, application.CredentialVersion,
		)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		response.JSON(writer, http.StatusOK, models.JwtDto{Token: token})
	})
}

// currentApplication tells an application what this service knows about it.
func (s *Server) currentApplication() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		application, allowed := s.requireApplication(writer, request)
		if !allowed {
			return
		}

		response.JSON(writer, http.StatusOK, describeApplication(application))
	})
}

// getApplication returns one of the caller's applications and the URIs it may
// be returned to.
func (s *Server) getApplication() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		application, _, ok := s.callerApplication(writer, request)
		if !ok {
			return
		}

		uris, err := s.applications.CallbackURIs(request.Context(), application.ID)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		response.JSON(writer, http.StatusOK, models.DeveloperApplicationWithCallbackURIDto{
			ID:           application.ID.String(),
			Name:         application.Name,
			OwnerID:      application.OwnerID.String(),
			CallbackUris: uris,
		})
	})
}

// deleteApplication removes one of the caller's applications, and with it every
// callback, login in progress and one-time code that referred to it.
func (s *Server) deleteApplication() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		application, caller, ok := s.callerApplication(writer, request)
		if !ok {
			return
		}

		if !s.withinLimit(
			writer, request, ratelimit.DeveloperApplicationMutation, caller.UserID.String(),
		) {
			return
		}

		deleted, err := s.applications.Delete(request.Context(), application.ID)
		if errors.Is(err, applications.ErrNoSuchApplication) {
			response.NotFound(writer)

			return
		}

		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		response.JSON(writer, http.StatusOK, describeApplication(deleted))
	})
}

// resetApplicationCredential issues a new refresh token and refuses every
// access token issued against the one it replaces.
func (s *Server) resetApplicationCredential() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		application, caller, ok := s.callerApplication(writer, request)
		if !ok {
			return
		}

		if !s.withinLimit(
			writer, request, ratelimit.DeveloperApplicationMutation, caller.UserID.String(),
		) {
			return
		}

		updated, token, err := s.applications.ReplaceCredential(request.Context(), application.ID)
		if errors.Is(err, applications.ErrNoSuchApplication) {
			response.NotFound(writer)

			return
		}

		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		response.JSON(writer, http.StatusOK, models.CreateDeveloperApplicationDto{
			ID:      updated.ID.String(),
			Name:    updated.Name,
			OwnerID: updated.OwnerID.String(),
			Token:   token,
		})
	})
}

// replaceCallbackURIs makes the set of URIs an application may be returned to
// exactly the one submitted.
func (s *Server) replaceCallbackURIs() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		application, caller, ok := s.callerApplication(writer, request)
		if !ok {
			return
		}

		given := inputs.New(request)
		uris := readSubmittedCallbackURIs(given)

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		if !s.withinLimit(
			writer, request, ratelimit.DeveloperApplicationMutation, caller.UserID.String(),
		) {
			return
		}

		err := s.applications.ReplaceCallbackURIs(request.Context(), application.ID, uris)

		var unsafe applications.UnsafeCallbackError
		if errors.As(err, &unsafe) {
			response.Error(writer, http.StatusBadRequest, detailUnsafeCallback)

			return
		}

		// Owned a moment ago and gone by the time its row could be locked is
		// the same answer as never owned.
		if errors.Is(err, applications.ErrNoSuchApplication) {
			response.NotFound(writer)

			return
		}

		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		response.JSON(writer, http.StatusOK, describeApplication(application))
	})
}

// callerApplication authenticates the person, reads the application from the
// path, and returns it only when they own it.
func (s *Server) callerApplication(
	writer http.ResponseWriter, request *http.Request,
) (applications.Application, Caller, bool) {
	caller, allowed := s.requireUser(writer, request, tokens.ScopeAbandonauth, audienceInternal)
	if !allowed {
		return applications.Application{}, Caller{}, false
	}

	given := inputs.New(request)
	applicationID := readApplicationIdentifier(given)

	if !given.OK() {
		response.Invalid(writer, given.Failures())

		return applications.Application{}, Caller{}, false
	}

	application, err := s.applications.OwnedBy(request.Context(), applicationID, caller.UserID)
	if errors.Is(err, applications.ErrNoSuchApplication) {
		response.NotFound(writer)

		return applications.Application{}, Caller{}, false
	}

	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return applications.Application{}, Caller{}, false
	}

	return application, caller, true
}
