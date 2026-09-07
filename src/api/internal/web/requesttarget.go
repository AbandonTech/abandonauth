package web

import (
	"net/http"
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

// declaredPath reports whether the route table names a path, whatever method it
// is asked for with. A preflight asks what a browser may do with a URL, so the
// answer cannot depend on the method being asked about.
func declaredPath(path string) bool {
	for _, route := range Routes() {
		if patternNames(route.Pattern, path) {
			return true
		}
	}

	return false
}

// patternNames reports whether a route pattern covers a path. A pattern
// anchored with {$} names that path alone, a pattern ending in a slash names
// its whole subtree, and a {wildcard} segment names any one non-empty segment.
func patternNames(pattern, path string) bool {
	if anchored, found := strings.CutSuffix(pattern, "{$}"); found {
		return path == anchored
	}

	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, pattern)
	}

	declared := strings.Split(pattern, "/")
	asked := strings.Split(path, "/")

	if len(declared) != len(asked) {
		return false
	}

	for index, segment := range declared {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			if asked[index] == "" {
				return false
			}

			continue
		}

		if segment != asked[index] {
			return false
		}
	}

	return true
}
