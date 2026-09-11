package web

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// What a client is told when a one-time code cannot be spent. It is the same
// whether the code never existed, has expired, has already been spent, or was
// issued to a different application.
const detailUnusableCode = "Token is not valid."

// detailApplicationRejected is the answer to an application whose own
// credentials were not accepted.
const detailApplicationRejected = "Invalid username or refresh token"

// detailNoApplicationCredential is the answer to a request that did not say
// which application is collecting the token.
const detailNoApplicationCredential = "Either a developer application JWT must be given in headers " +
	"or the developer application credentials must be passed in the request body"

// login spends a one-time code for an access token that identifies the person
// who signed in.
//
// The application collecting the token must prove who it is, either with its
// own access token or with its credentials, and the code must be one that was
// issued to that application. Spending it is a single delete, so the second
// attempt on a code fails whether it arrives a minute later or at the same
// instant on another worker.
//
// @Summary     Exchange a temporary AbandonAuth token for a permanent user token.
// @Description Log in the user, using a one-time code issued by a provider callback.
// @Description
// @Description The application collecting the token must prove who it is, and the code must be one that was issued to that application.
// @Accept      json
// @Produce     json
// @Param       exchange-token header   string                              true  "The one-time code to spend"
// @Param       login_data     body     models.LoginDeveloperApplicationDto false "The application's own credentials"
// @Success     200            {object} models.JwtDto
// @Failure     401            {object} response.Failed "The code could not be spent"
// @Failure     403            {object} response.Failed "The application was not accepted"
// @Failure     422            {object} response.Invalidated
// @Failure     429            {object} response.Failed "Too many attempts"
// @Security    JWTBearer
// @Router      /api/login [post].
func (s *Server) login() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.withinLimit(writer, request, ratelimit.LoginExchange, s.clientAddress(request)) {
			return
		}

		given := inputs.New(request)
		presented := readLoginInputs(given)

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		application, identified := s.collectingApplication(
			writer, request, presented.credentialsGiven, presented.applicationID, presented.refreshToken,
		)
		if !identified {
			return
		}

		spent, err := s.codes.Redeem(request.Context(), presented.code, application.ID)
		if errors.Is(err, oauth.ErrNoSuchCode) {
			response.Error(writer, http.StatusUnauthorized, detailUnusableCode)

			return
		}

		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		s.issueUserAccess(writer, request, spent.UserID, application.ID)
	})
}

// loginInputs is what a client sends to spend a one-time code.
type loginInputs struct {
	code string

	// credentialsGiven records that a body arrived at all, which is what
	// separates an application relying on its access token from one that sent
	// credentials this service must then accept or refuse.
	credentialsGiven bool

	applicationID uuid.UUID
	refreshToken  string
}

// readLoginInputs reads the one-time code and the optional credentials of the
// application collecting the token. Both credential members are required once a
// body is present.
func readLoginInputs(given *inputs.Inputs) loginInputs {
	presented := loginInputs{code: given.Header(ExchangeTokenHeader)}

	presented.credentialsGiven = given.DecodeOptionalObjectBody()
	if presented.credentialsGiven {
		presented.applicationID = given.BodyUUID("id")
		presented.refreshToken = given.BodyString("refresh_token")
	}

	return presented
}

// collectingApplication establishes which application is spending the code.
//
// A token in the header takes precedence, as it did before credentials could be
// sent in the body at all; a header that is present and not accepted is a
// refusal rather than a fallback to the body.
func (s *Server) collectingApplication(
	writer http.ResponseWriter,
	request *http.Request,
	credentialsGiven bool,
	applicationID uuid.UUID,
	refreshToken string,
) (applications.Application, bool) {
	if request.Header.Get(authorizationHeader) != "" {
		return s.requireApplication(writer, request)
	}

	if !credentialsGiven {
		response.Error(writer, http.StatusUnauthorized, detailNoApplicationCredential)

		return applications.Application{}, false
	}

	application, err := s.applications.Authenticate(request.Context(), applicationID, refreshToken)
	if errors.Is(err, applications.ErrInvalidCredential) {
		response.Error(writer, http.StatusForbidden, detailApplicationRejected)

		return applications.Application{}, false
	}

	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return applications.Application{}, false
	}

	return application, true
}

// issueUserAccess signs and returns the token that identifies a person to one
// application.
func (s *Server) issueUserAccess(
	writer http.ResponseWriter, request *http.Request, userID, applicationID uuid.UUID,
) {
	epoch, err := s.authority.Current(request.Context())
	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return
	}

	token, _, err := s.signer.IssueUserAccess(userID, applicationID, epoch)
	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return
	}

	response.JSON(writer, http.StatusOK, models.JwtDto{Token: token})
}
