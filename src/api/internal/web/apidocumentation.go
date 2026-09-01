package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

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

// generatedAPISchema renders the annotations into a document.
//
// The annotations are read from the source, which carries no build constraints,
// so the result describes every annotated endpoint rather than the ones this
// build serves. publishedAPISchema is what a reader gets.
//
// Rendering writes back to the package-level value it renders from, so two
// callers at once race on it. The result is the same every time, so it is
// produced once.
var generatedAPISchema = sync.OnceValue(docs.SwaggerInfo.ReadDoc)

// publishedAPISchema is the generated document with every address this build
// does not serve removed, so it cannot advertise an endpoint that answers 404.
var publishedAPISchema = sync.OnceValues(func() (string, error) {
	return schemaLimitedTo(generatedAPISchema(), documentedPaths())
})

// documentationHandlers publish this API's documentation. It describes only
// endpoints a caller could discover by trying them, so every build serves it.
func (s *Server) documentationHandlers() map[RouteName]http.Handler {
	return map[RouteName]http.Handler{
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
		response.Redirect(writer, http.StatusTemporaryRedirect, "docs/")
	})
}

// documentation serves the page and the files it loads.
func (s *Server) documentation() http.Handler {
	page := httpSwagger.Handler(httpSwagger.URL(externalPrefix + APISchemaPath))

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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

// apiSchema serves the schema this build publishes.
func (s *Server) apiSchema() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		document, err := publishedAPISchema()
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		writer.Header().Set("Content-Type", response.ContentTypeJSON)
		_, _ = writer.Write([]byte(document))
	})
}

// documentedPaths are the addresses this build serves and publishes.
func documentedPaths() map[string]bool {
	published := make(map[string]bool)

	for _, route := range Routes() {
		if route.Documented {
			published[route.Path()] = true
		}
	}

	return published
}

// schemaLimitedTo removes from a document every path the given set does not
// name. A document it cannot read is an error rather than a document served
// unfiltered, because the filtering is what keeps the two builds apart.
func schemaLimitedTo(document string, published map[string]bool) (string, error) {
	var rendered map[string]json.RawMessage

	if err := json.Unmarshal([]byte(document), &rendered); err != nil {
		return "", fmt.Errorf("the API schema is not a JSON document: %w", err)
	}

	var paths map[string]json.RawMessage

	if err := json.Unmarshal(rendered["paths"], &paths); err != nil {
		return "", fmt.Errorf("the API schema declares no paths: %w", err)
	}

	for path := range paths {
		if !published[path] {
			delete(paths, path)
		}
	}

	limited, err := json.Marshal(paths)
	if err != nil {
		return "", fmt.Errorf("the remaining paths could not be written: %w", err)
	}

	rendered["paths"] = limited

	complete, err := json.Marshal(rendered)
	if err != nil {
		return "", fmt.Errorf("the API schema could not be written: %w", err)
	}

	return string(complete), nil
}
