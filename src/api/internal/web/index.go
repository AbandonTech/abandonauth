package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// sitePath is where a browser that arrives at the API's root is sent. It is a
// path on this host rather than the site's own origin: the reverse proxy serves
// both, and the redirect has to work the same from inside the deployment as
// from outside it.
const sitePath = "/ui"

// index sends a browser that arrived at the root of the API to the site.
//
// It is not part of the published API. Nothing programmatic depends on it; it
// exists so that typing the host into a browser lands somewhere useful.
func (s *Server) index() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		response.Redirect(writer, http.StatusTemporaryRedirect, sitePath)
	})
}
