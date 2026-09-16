package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// discordCallback finishes a login that was started with Discord.
//
// @Summary     Finish a login with Discord
// @Description The address Discord returns the browser to after a login started at the authorize endpoint.
// @Description
// @Description The state must belong to a login this service started for this browser. A login the site itself started ends in a browser session; any other ends in a one-time code appended to the application's registered callback under the key "code". A browser returned without a code is sent to the callback with nothing appended.
// @Produce     json
// @Param       code  query string false "The authorization code Discord issued"
// @Param       state query string true  "The value this service put in the authorization request"
// @Success     307 "Redirect to the application's registered callback"
// @Failure     403 {object} response.Failed "The login could not be matched or completed"
// @Failure     429 {object} response.Failed "Too many attempts"
// @Router      /api/ui/discord-callback [get].
func (s *Server) discordCallback() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		login, code, resumed := s.resumeLogin(writer, request, oauth.Discord)
		if !resumed {
			return
		}

		if code == "" {
			s.abandonLogin(writer, login)

			return
		}

		identity, err := s.discord.Identify(request.Context(), code, login.Verifier)
		if err != nil {
			s.refuseProvider(writer, request, err)

			return
		}

		s.completeLogin(writer, request, login, identity, urlpolicy.ExchangeCodeQueryKey)
	})
}

// githubCallback finishes a login that was started with GitHub.
//
// @Summary     Finish a login with GitHub
// @Description The address GitHub returns the browser to after a login started at the authorize endpoint.
// @Description
// @Description The state must belong to a login this service started for this browser. A login the site itself started ends in a browser session; any other ends in a one-time code appended to the application's registered callback under the key "code". A browser returned without a code is sent to the callback with nothing appended.
// @Produce     json
// @Param       code  query string false "The authorization code GitHub issued"
// @Param       state query string true  "The value this service put in the authorization request"
// @Success     307 "Redirect to the application's registered callback"
// @Failure     403 {object} response.Failed "The login could not be matched or completed"
// @Failure     429 {object} response.Failed "Too many attempts"
// @Router      /api/ui/github-callback [get].
func (s *Server) githubCallback() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		login, code, resumed := s.resumeLogin(writer, request, oauth.GitHub)
		if !resumed {
			return
		}

		if code == "" {
			s.abandonLogin(writer, login)

			return
		}

		identity, err := s.github.Identify(request.Context(), code, login.Verifier)
		if err != nil {
			s.refuseProvider(writer, request, err)

			return
		}

		s.completeLogin(writer, request, login, identity, urlpolicy.ExchangeCodeQueryKey)
	})
}

// googleCallback finishes a login that was started with Google.
//
// The identity token Google returns is the whole answer: it is verified against
// Google's published keys, this service's own client identifier, and the value
// that ties it to this login, before the person it names is looked up.
//
// @Summary     Finish a login with Google
// @Description The address Google returns the browser to after a login started at the authorize endpoint.
// @Description
// @Description The state must belong to a login this service started for this browser, and the identity token Google issues is verified in full before anyone is signed in. A login the site itself started ends in a browser session; any other ends in a one-time code appended to the application's registered callback under the key "authentication". A browser returned without a code is sent to the callback with nothing appended.
// @Tags        Google
// @Produce     json
// @Param       code  query string false "The authorization code Google issued"
// @Param       state query string true "The value this service put in the authorization request"
// @Success     307 "Redirect to the application's registered callback"
// @Failure     403 {object} response.Failed "The login could not be matched or completed"
// @Failure     429 {object} response.Failed "Too many attempts"
// @Router      /api/google [get].
func (s *Server) googleCallback() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		login, code, resumed := s.resumeLogin(writer, request, oauth.Google)
		if !resumed {
			return
		}

		if code == "" {
			s.abandonLogin(writer, login)

			return
		}

		identity, err := s.google.Identify(request.Context(), code, login.Verifier, login.NonceDigest)
		if err != nil {
			s.refuseProvider(writer, request, err)

			return
		}

		s.completeLogin(writer, request, login, identity, urlpolicy.IdentityQueryKey)
	})
}

// abandonLogin returns a browser that came back without an authorization code
// to where it started. The person declined, or the provider sent them back; in
// neither case is there anything to exchange.
func (s *Server) abandonLogin(writer http.ResponseWriter, login oauth.Login) {
	callback, err := urlpolicy.ParseCallbackURI(login.CallbackURI)
	if err != nil {
		response.Error(writer, http.StatusForbidden, detailUnknownApplicationOrCallback)

		return
	}

	response.Redirect(writer, http.StatusTemporaryRedirect, callback.String())
}
