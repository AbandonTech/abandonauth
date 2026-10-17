package web

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	httpSwagger "github.com/swaggo/http-swagger/v2"
	"go.yaml.in/yaml/v3"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// schemaFromDocumentation is how the documentation page names the schema. The
// page is loaded in a browser, and a relative reference resolves against the
// address that browser actually asked for, so no host, port or origin has to be
// guessed for it.
const schemaFromDocumentation = "../openapi.yaml"

const contentTypeYAML = "application/yaml; charset=utf-8"

//go:embed openapi.yaml
var embeddedOpenAPISchema []byte

// Why a schema source is refused. Each is fixed text: the YAML library's own
// errors can quote the offending source, so they are never wrapped or logged.
var (
	errOpenAPIUnreadable   = errors.New("the OpenAPI source is not exactly one YAML mapping")
	errOpenAPIIncomplete   = errors.New("the OpenAPI source lacks a required top-level member")
	errOpenAPIExample      = errors.New("the OpenAPI source carries an example or default value")
	errOpenAPIUnrenderable = errors.New("the OpenAPI source cannot be represented as JSON")
)

// forbiddenOpenAPIMembers can carry a literal value anywhere in a document, and
// a value pasted there for convenience could be a credential.
var forbiddenOpenAPIMembers = []string{"example", "examples", "default"}

// openAPIRepresentations are the two forms one schema source is served in.
type openAPIRepresentations struct {
	YAML []byte
	JSON []byte
}

// publishedOpenAPI is the embedded source, checked and rendered once.
var publishedOpenAPI = sync.OnceValues(func() (openAPIRepresentations, error) {
	return renderOpenAPIRepresentations(embeddedOpenAPISchema)
})

// renderOpenAPIRepresentations checks a schema source and derives its JSON form.
// A source that fails any check yields neither form, so nothing unchecked is
// ever served.
func renderOpenAPIRepresentations(source []byte) (openAPIRepresentations, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(source))

	var document map[string]any
	if err := decoder.Decode(&document); err != nil || document == nil {
		return openAPIRepresentations{}, errOpenAPIUnreadable
	}

	var another any
	if err := decoder.Decode(&another); !errors.Is(err, io.EOF) {
		return openAPIRepresentations{}, errOpenAPIUnreadable
	}

	if !hasRequiredOpenAPIMembers(document) {
		return openAPIRepresentations{}, errOpenAPIIncomplete
	}

	if carriesForbiddenOpenAPIMember(document) {
		return openAPIRepresentations{}, errOpenAPIExample
	}

	rendered, err := json.Marshal(document)
	if err != nil {
		return openAPIRepresentations{}, errOpenAPIUnrenderable
	}

	return openAPIRepresentations{YAML: bytes.Clone(source), JSON: rendered}, nil
}

func hasRequiredOpenAPIMembers(document map[string]any) bool {
	if _, ok := document["openapi"].(string); !ok {
		return false
	}

	for _, member := range []string{"info", "paths", "components"} {
		if _, ok := document[member].(map[string]any); !ok {
			return false
		}
	}

	return true
}

func carriesForbiddenOpenAPIMember(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, member := range typed {
			if isForbiddenOpenAPIMember(key) || carriesForbiddenOpenAPIMember(member) {
				return true
			}
		}
	case []any:
		for _, element := range typed {
			if carriesForbiddenOpenAPIMember(element) {
				return true
			}
		}
	}

	return false
}

func isForbiddenOpenAPIMember(key string) bool {
	for _, forbidden := range forbiddenOpenAPIMembers {
		if key == forbidden {
			return true
		}
	}

	return false
}

// documentationHandlers publish this API's documentation. It describes only
// endpoints a caller could discover by trying them, so every build serves it.
func (s *Server) documentationHandlers() map[RouteName]http.Handler {
	return map[RouteName]http.Handler{
		RouteSwaggerUI:      s.documentationEntry(),
		RouteSwaggerUIIndex: s.documentation(),
		RouteSwaggerOAuth2:  s.documentationRedirectPage(),
		RouteOpenAPIYAML:    s.openAPIYAML(),
		RouteOpenAPIJSON:    s.openAPIJSON(),
	}
}

// documentationEntry sends a browser from the bare path to the subtree the page
// and its files are served under.
//
// The location is relative so it resolves against the address the browser
// asked for.
func (s *Server) documentationEntry() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		response.Redirect(writer, http.StatusTemporaryRedirect, "docs/")
	})
}

// documentation serves the page and the files it loads.
func (s *Server) documentation() http.Handler {
	page := httpSwagger.Handler(httpSwagger.URL(schemaFromDocumentation))

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
	page := httpSwagger.Handler(httpSwagger.URL(schemaFromDocumentation))

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

// openAPIYAML serves the schema in the form it is written in.
func (s *Server) openAPIYAML() http.Handler {
	return s.serveOpenAPI(contentTypeYAML, func() ([]byte, error) {
		published, err := publishedOpenAPI()

		return published.YAML, err
	})
}

// openAPIJSON serves the same schema as JSON.
func (s *Server) openAPIJSON() http.Handler {
	return s.serveOpenAPI(response.ContentTypeJSON, func() ([]byte, error) {
		published, err := publishedOpenAPI()

		return published.JSON, err
	})
}

// serveOpenAPI writes what load returns, or refuses when it returns an error.
func (s *Server) serveOpenAPI(contentType string, load func() ([]byte, error)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		document, err := load()
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		writer.Header().Set("Content-Type", contentType)
		_, _ = writer.Write(document)
	})
}
