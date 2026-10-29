package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// index sends a browser that arrived at the root of the API to the site.
//
// It is not part of the published API. Nothing programmatic depends on it; it
// exists so that typing the address into a browser lands somewhere useful. The
// destination is the configured site origin, so a forged Host or forwarding
// header cannot choose where a browser is sent.
func (s *Server) index() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		response.Redirect(writer, http.StatusTemporaryRedirect, s.config.Site.String())
	})
}

// indexEntry sends a browser from the bare root to the root itself, so the two
// spellings of it lead to one answer.
func (s *Server) indexEntry() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		response.Redirect(writer, http.StatusTemporaryRedirect, APIRoot+"/")
	})
}
