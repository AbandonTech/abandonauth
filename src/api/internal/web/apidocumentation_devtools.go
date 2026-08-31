//go:build devtools

package web

import (
	"net/http"
	"strings"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/abandontech/abandonauth/src/api/docs"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// externalPrefix is where a reverse proxy serves this API from. The
// documentation page is loaded in a browser, so the address it fetches the
// schema from has to be the one the browser can reach, not the one inside the
// deployment.
const externalPrefix = "/api"

// APISchemaPath is where the published schema is served.
const APISchemaPath = "/openapi.json"

// documentationHandlers are the routes only the development build serves.
func (s *Server) devtoolsHandlers() map[RouteName]http.Handler {
	return map[RouteName]http.Handler{
		RouteCreateTestUser: s.createPasswordAccount(),
		RouteLoginTestUser:  s.signInWithPassword(),

		RouteSwaggerUI:      s.documentationEntry(),
		RouteSwaggerUIIndex: s.documentation(),
		RouteSwaggerOAuth2:  s.documentationRedirectPage(),
		RouteAPISchema:      s.apiSchema(),
	}
}

// documentationEntry sends a browser from the bare path to the subtree the page
// and its files are served under.
//
// The location is relative so it resolves correctly whether the service is
// reached directly or behind the prefix a proxy serves it from.
func (s *Server) documentationEntry() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if !s.documentationReachable(writer) {
			return
		}

		response.Redirect(writer, http.StatusTemporaryRedirect, "docs/")
	})
}

// documentation serves the page and the files it loads.
func (s *Server) documentation() http.Handler {
	page := httpSwagger.Handler(httpSwagger.URL(externalPrefix + APISchemaPath))

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.documentationReachable(writer) {
			return
		}

		// A request for the subtree itself is answered with the page, rather
		// than with a redirect to the file the page happens to live in.
		if strings.HasSuffix(request.URL.Path, "/") {
			page.ServeHTTP(writer, addressedTo(request, request.URL.Path+"index.html"))

			return
		}

		page.ServeHTTP(writer, request)
	})
}

// documentationRedirectPage serves the page a provider returns to when the
// documentation is used to try a sign-in. Its address is the one registered
// with the providers, which is why the served file is named separately from it.
func (s *Server) documentationRedirectPage() http.Handler {
	page := httpSwagger.Handler(httpSwagger.URL(externalPrefix + APISchemaPath))

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.documentationReachable(writer) {
			return
		}

		page.ServeHTTP(writer, addressedTo(request, request.URL.Path+".html"))
	})
}

// addressedTo copies a request as though it had asked for another path.
//
// The documentation handler selects the file from the unparsed request target,
// so rewriting only the parsed URL would leave the request unchanged as far as
// it is concerned.
func addressedTo(request *http.Request, path string) *http.Request {
	rewritten := request.Clone(request.Context())
	rewritten.URL.Path = path
	rewritten.URL.RawQuery = ""
	rewritten.RequestURI = path

	return rewritten
}

// apiSchema serves the published schema this build was generated with.
func (s *Server) apiSchema() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if !s.documentationReachable(writer) {
			return
		}

		writer.Header().Set("Content-Type", response.ContentTypeJSON)
		_, _ = writer.Write([]byte(docs.SwaggerInfo.ReadDoc()))
	})
}

// documentationReachable reports whether the documentation may be served at
// all, and otherwise answers as if it were not compiled in.
func (s *Server) documentationReachable(writer http.ResponseWriter) bool {
	if s.config.DocumentationEnabled() {
		return true
	}

	response.NotFound(writer)

	return false
}
