package web

import (
	"errors"
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/services/sessions"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// siteEntry is where a browser lands after signing in here.
//
// It reads nothing from the URL. The session was created by the callback that
// verified the login, so there is no credential in this request to redeem and
// none that could be replayed into one. A browser without a session is sent to
// the site anyway, where it is offered the sign-in again.
func (s *Server) siteEntry() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := cookieValue(request, s.SessionCookieName())

		if value != "" {
			if _, err := s.sessions.Lookup(request.Context(), value); errors.Is(err, sessions.ErrNoSuchSession) {
				s.endSession(writer)
			}
		}

		response.Redirect(writer, http.StatusTemporaryRedirect, s.config.Site.String())
	})
}

// logout ends a browser's session.
//
// The row is deleted before the cookies are cleared, so a copy of the cookie
// taken beforehand is refused by every worker from that moment; clearing the
// cookies first would leave a working session in the hands of whoever kept one.
//
// @Summary     Log out of the browser session
// @Description End the browser session.
// @Description
// @Description Deletes the session on the server before clearing the session and CSRF cookies, so a copy of the cookie taken before logout is not usable afterwards. The request must carry the value of the CSRF cookie in the X-CSRF-Token header and originate from the AbandonAuth site.
// @Produce     json
// @Param       X-CSRF-Token header string true "The value of the CSRF cookie"
// @Success     200 "The session was ended and the cookies were cleared"
// @Failure     403 {object} response.Failed "Missing or invalid session, origin, or CSRF token"
// @Failure     422 {object} response.Invalidated
// @Router      /ui/logout [post].
func (s *Server) logout() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		given := inputs.New(request)
		given.Header(CSRFHeader)

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		caller, allowed := s.callerFromSession(writer, request)
		if !allowed {
			return
		}

		if err := s.sessions.End(request.Context(), caller.SessionValue); err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		s.endSession(writer)
		response.Empty(writer, http.StatusOK)
	})
}
