package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// rawPath is the path of the request target as the client spelled it, with the
// query removed and nothing decoded.
func rawPath(request *http.Request) string {
	path, _, _ := strings.Cut(request.RequestURI, "?")

	return path
}

// canonicalPath reports whether a raw path is spelled the single way this
// service serves it.
//
// The router decodes and cleans a path before it matches, so an escaped,
// repeated-slash or dot-segment spelling is a second name for an address that
// consumes login state, a provider's authorization code or a one-time code. No
// segment of any address here needs escaping, so a percent marker in the path
// is refused outright rather than decoded and inspected.
//
// Only the path is examined. A percent marker in the query is ordinary, and the
// value behind it belongs to the handler exactly as it arrived.
func canonicalPath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}

	if strings.ContainsAny(path, `%\`) || strings.Contains(path, "//") {
		return false
	}

	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}

	return true
}

// onlyCanonicalTargets refuses a target this service does not spell, before a
// browser is told what it may do with it and before the router can clean it
// into one that is served.
//
// The refusal is the service's own 404 and carries no Location: a redirect to
// the cleaned spelling would hand whatever the request carried to the address
// this check exists to protect.
func onlyCanonicalTargets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !canonicalPath(rawPath(request)) {
			response.NotFound(writer)

			return
		}

		next.ServeHTTP(writer, request)
	})
}

// routePaths builds a router over every pattern the route table names, with
// the method left off, so a question about a path is answered by the same
// matcher that serves it and the two cannot drift apart. Every pattern answers
// with the given handler.
func routePaths(answer http.Handler) *http.ServeMux {
	paths := http.NewServeMux()
	registered := make(map[string]bool)

	for _, route := range Routes() {
		if registered[route.Pattern] {
			continue
		}

		registered[route.Pattern] = true

		paths.Handle(route.Pattern, answer)
	}

	return paths
}

// declaredPaths answers whether the route table names a path, whatever method
// it is asked for with. A preflight asks what a browser may do with a URL, so
// the answer cannot depend on the method being asked about.
type declaredPaths struct {
	paths  *http.ServeMux
	marker *declaredMarker
}

// declaredMarker is the handler every declared pattern answers with. It is
// compared by identity: the router answers a path it would redirect, clean or
// refuse with a handler of its own, and none of those is a declared path.
type declaredMarker struct{}

func (*declaredMarker) ServeHTTP(http.ResponseWriter, *http.Request) {}

func newDeclaredPaths() declaredPaths {
	marker := &declaredMarker{}

	return declaredPaths{paths: routePaths(marker), marker: marker}
}

// names reports whether a canonical path is one the route table declares.
func (d declaredPaths) names(path string) bool {
	handler, _ := d.paths.Handler(&http.Request{Method: http.MethodGet, URL: &url.URL{Path: path}})

	return handler == http.Handler(d.marker)
}
