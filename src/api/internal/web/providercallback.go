package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// discordCallback finishes a login that was started with Discord.
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
		response.Error(writer, http.StatusForbidden, detailSignInValidationFailed)

		return
	}

	response.Redirect(writer, http.StatusTemporaryRedirect, callback.String())
}
