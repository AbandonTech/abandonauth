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
//
// @Summary     Register a developer application and receive its refresh token
// @Description Register a developer application owned by the signed-in person.
// @Description
// @Description The answer carries the application's refresh token, which is shown only here: it is stored as a hash and cannot be read back. It stays valid until it is replaced through the reset_token endpoint.
// @Tags        Developer Applications
// @Accept      json
// @Produce     json
// @Param       application body     models.DeveloperApplicationName true "The name of the application"
// @Success     200         {object} models.CreateDeveloperApplicationDto
// @Failure     403         {object} response.Failed "The credential was missing, refused or expired"
// @Failure     422         {object} response.Invalidated
// @Failure     429         {object} response.Failed "Too many attempts"
// @Security    JWTBearer
// @Router      /api/developer_application [post].
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
//
// @Summary     Exchange a developer application's refresh token for a short-lived access token
// @Description Authenticate a developer application with its refresh token.
// @Description
// @Description The answer is an access token that speaks for the application itself and expires after fifteen minutes. A refresh token that is not the application's, or an application that does not exist, is refused with the same 401.
// @Tags        Developer Applications
// @Accept      json
// @Produce     json
// @Param       login_data body     models.LoginDeveloperApplicationDto true "The application's credentials"
// @Success     200        {object} models.JwtDto
// @Failure     401        {object} response.Failed "The credentials were not accepted"
// @Failure     422        {object} response.Invalidated
// @Failure     429        {object} response.Failed "Too many attempts"
// @Router      /api/developer_application/login [post].
func (s *Server) applicationLogin() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		given := inputs.New(request)
		presented := readApplicationCredentials(given)

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		// Counted against the caller and the application together. The
		// identifier is public, so counting against it alone would let anyone
		// lock a real application out of its own sign-in.
		if !s.withinLimit(
			writer, request, ratelimit.DeveloperApplicationLogin,
			s.clientAddress(request), presented.applicationID.String(),
		) {
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
//
// @Summary     Identify the developer application behind an access token
// @Description Describe the developer application an access token speaks for.
// @Tags        Developer Applications
// @Produce     json
// @Success     200 {object} models.DeveloperApplicationDto
// @Failure     403 {object} response.Failed "The credential was missing, refused or expired"
// @Security    JWTBearer
// @Router      /api/developer_application/me [get].
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
//
// @Summary     Describe one of the signed-in person's developer applications
// @Description Describe a developer application and the callback URIs it may be returned to, if the signed-in person owns it. An application somebody else owns is answered as one that does not exist.
// @Tags        Developer Applications
// @Produce     json
// @Param       application_id path     string true "The application's identifier" format(uuid)
// @Success     200            {object} models.DeveloperApplicationWithCallbackURIDto
// @Failure     403            {object} response.Failed "The credential was missing, refused or expired"
// @Failure     404            {object} response.Failed "No such application"
// @Failure     422            {object} response.Invalidated
// @Security    JWTBearer
// @Router      /api/developer_application/{application_id} [get].
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
//
// @Summary     Delete one of the signed-in person's developer applications
// @Description Delete a developer application the signed-in person owns, with its callback URIs, its logins in progress and its unspent one-time codes. An application somebody else owns is answered as one that does not exist.
// @Tags        Developer Applications
// @Produce     json
// @Param       application_id path     string true "The application's identifier" format(uuid)
// @Success     200            {object} models.DeveloperApplicationDto
// @Failure     403            {object} response.Failed "The credential was missing, refused or expired"
// @Failure     404            {object} response.Failed "No such application"
// @Failure     422            {object} response.Invalidated
// @Failure     429            {object} response.Failed "Too many attempts"
// @Security    JWTBearer
// @Router      /api/developer_application/{application_id} [delete].
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
//
// @Summary     Replace a developer application's refresh token
// @Description Issue a new refresh token for a developer application the signed-in person owns.
// @Description
// @Description The replaced refresh token stops authenticating the application at once, and every access token issued against it is refused from then on. The new token is shown only in this answer.
// @Tags        Developer Applications
// @Produce     json
// @Param       application_id path     string true "The application's identifier" format(uuid)
// @Success     200            {object} models.CreateDeveloperApplicationDto
// @Failure     403            {object} response.Failed "The credential was missing, refused or expired"
// @Failure     404            {object} response.Failed "No such application"
// @Failure     422            {object} response.Invalidated
// @Failure     429            {object} response.Failed "Too many attempts"
// @Security    JWTBearer
// @Router      /api/developer_application/{application_id}/reset_token [patch].
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
//
// @Summary     Replace a developer application's callback URIs
// @Description Make the set of callback URIs a developer application may be returned to exactly the set submitted.
// @Description
// @Description URIs not yet registered are added, URIs registered but not submitted are removed, and URIs in both are kept as they are. A URI is matched by its exact spelling. The set is replaced whole or not at all: one URI this service would not return a browser to leaves the application with the set it had. Replacements of one application's set run one after the other.
// @Tags        Developer Applications
// @Accept      json
// @Produce     json
// @Param       application_id path     string   true "The application's identifier" format(uuid)
// @Param       callback_uris  body     []string true "The complete set of callback URIs"
// @Success     200            {object} models.DeveloperApplicationDto
// @Failure     400            {object} response.Failed "One of the URIs is not acceptable"
// @Failure     403            {object} response.Failed "The credential was missing, refused or expired"
// @Failure     404            {object} response.Failed "No such application"
// @Failure     422            {object} response.Invalidated
// @Failure     429            {object} response.Failed "Too many attempts"
// @Security    JWTBearer
// @Router      /api/developer_application/{application_id}/callback_uris [patch].
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
