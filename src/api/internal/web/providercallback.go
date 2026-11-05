package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// admitCallback serves a provider callback only while it holds a public-
// protocol permit, taken before anything of the callback is read: one refused
// for want of a permit has consumed no state and asked no provider anything,
// so the same callback can be retried. For a public client a callback only
// authenticates the person and hands them to consent.
func (s *Server) admitCallback(callback http.HandlerFunc) http.Handler {
	return withPublicProtocolAdmission(s.admission, refuseCallbackOverload, callback)
}

// discordCallback finishes a login that was started with Discord.
func (s *Server) discordCallback() http.Handler {
	return s.admitCallback(func(writer http.ResponseWriter, request *http.Request) {
		login, code, resumed := s.resumeLogin(writer, request, oauth.Discord)
		if !resumed {
			return
		}

		if code == "" {
			s.abandonLogin(writer, request, login)

			return
		}

		identity, err := s.discord.Identify(request.Context(), code, login.Verifier)
		if err != nil {
			s.refuseProvider(writer, request, login, err)

			return
		}

		s.completeLogin(writer, request, login, identity, urlpolicy.ExchangeCodeQueryKey)
	})
}

// githubCallback finishes a login that was started with GitHub.
func (s *Server) githubCallback() http.Handler {
	return s.admitCallback(func(writer http.ResponseWriter, request *http.Request) {
		login, code, resumed := s.resumeLogin(writer, request, oauth.GitHub)
		if !resumed {
			return
		}

		if code == "" {
			s.abandonLogin(writer, request, login)

			return
		}

		identity, err := s.github.Identify(request.Context(), code, login.Verifier)
		if err != nil {
			s.refuseProvider(writer, request, login, err)

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
	return s.admitCallback(func(writer http.ResponseWriter, request *http.Request) {
		login, code, resumed := s.resumeLogin(writer, request, oauth.Google)
		if !resumed {
			return
		}

		if code == "" {
			s.abandonLogin(writer, request, login)

			return
		}

		identity, err := s.google.Identify(request.Context(), code, login.Verifier, login.NonceDigest)
		if err != nil {
			s.refuseProvider(writer, request, login, err)

			return
		}

		s.completeLogin(writer, request, login, identity, urlpolicy.IdentityQueryKey)
	})
}

// steamCallback finishes a login that was started with Steam.
//
// Every check that needs neither the login nor Steam comes first, so a
// malformed or ambiguous callback spends no login and causes no request. The
// login is then spent before Steam is asked to verify the assertion, so one
// login causes at most one verification and a refused one cannot be retried.
func (s *Server) steamCallback() http.Handler {
	return s.admitCallback(func(writer http.ResponseWriter, request *http.Request) {
		callback, err := s.steam.ReadCallback(request.URL.RawQuery)
		if err != nil {
			response.Error(writer, http.StatusForbidden, detailSignInValidationFailed)

			return
		}

		login, consumed := s.consumeLogin(writer, request, oauth.Steam, callback.State)
		if !consumed {
			return
		}

		if callback.Cancelled() {
			s.abandonLogin(writer, request, login)

			return
		}

		identity, err := s.steam.Identify(request.Context(), callback)
		if err != nil {
			s.refuseProvider(writer, request, login, err)

			return
		}

		s.completeLogin(writer, request, login, identity, urlpolicy.ExchangeCodeQueryKey)
	})
}

// abandonLogin returns a browser that came back without an authorization code
// to where it started. The person declined, or the provider sent them back; in
// neither case is there anything to exchange. A public client is told the
// person declined.
func (s *Server) abandonLogin(writer http.ResponseWriter, request *http.Request, login oauth.Login) {
	if login.Native != nil {
		s.endNativeLogin(writer, request, *login.Native, response.OAuthAccessDenied)

		return
	}

	callback, err := urlpolicy.ParseCallbackURI(login.CallbackURI)
	if err != nil {
		response.Error(writer, http.StatusForbidden, detailSignInValidationFailed)

		return
	}

	response.Redirect(writer, http.StatusTemporaryRedirect, callback.String())
}
