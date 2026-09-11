package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Headers a browser may send on a cross-origin request to this service.
var allowedRequestHeaders = []string{"Authorization", "Content-Type", CSRFHeader, ExchangeTokenHeader}

// Methods a browser may use cross-origin. They are listed rather than reflected
// so that a preflight cannot talk the service into permitting one it does not
// serve.
var allowedMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// preflightMaxAge is how long a browser may remember the answer to a preflight.
const preflightMaxAge = 10 * time.Minute

// answerCORS tells a browser what the site may do with this API.
//
// Exactly one origin is ever permitted: the site this deployment was configured
// with. Credentials are allowed, so a wildcard is not merely disallowed by the
// specification but would hand every origin a signed-in person's session.
//
// Only an address the route table names is answered for. A preflight to
// anything else is left to the router, which reports that it is not served,
// rather than being told what a browser could do with an address there is
// nothing at.
func (s *Server) answerCORS(next http.Handler) http.Handler {
	site := s.config.Site

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		served := declaredPath(rawPath(request))
		origin := request.Header.Get("Origin")
		permitted := served && origin != "" && site.MatchesHeader(origin)

		if permitted {
			header := writer.Header()
			header.Set("Access-Control-Allow-Origin", site.String())
			header.Set("Access-Control-Allow-Credentials", "true")
			header.Set("Access-Control-Expose-Headers", RequestIDHeader)
			// The answer differs by origin, so a shared cache must not serve
			// one origin's answer to another.
			header.Add("Vary", "Origin")
		}

		if !served || request.Method != http.MethodOptions ||
			request.Header.Get("Access-Control-Request-Method") == "" {
			next.ServeHTTP(writer, request)

			return
		}

		if permitted {
			header := writer.Header()
			header.Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
			header.Set("Access-Control-Allow-Headers", strings.Join(allowedRequestHeaders, ", "))
			header.Set("Access-Control-Max-Age", strconv.Itoa(int(preflightMaxAge.Seconds())))
			header.Add("Vary", "Access-Control-Request-Method")
			header.Add("Vary", "Access-Control-Request-Headers")
		}

		// A preflight is answered here whether or not the origin is permitted.
		// An unpermitted one simply receives no permission headers, which is
		// what stops the browser from making the request.
		writer.WriteHeader(http.StatusNoContent)
	})
}
