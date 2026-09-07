package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The router decodes and cleans a path before it matches, so anything it would
// turn into an address this service serves has to be refused first. A percent
// marker is refused without being decoded: no segment of any address here needs
// escaping, so an escaped one is somebody spelling an address a second way.
func TestOnlyOneSpellingOfAPathIsCanonical(t *testing.T) {
	t.Parallel()

	canonical := []string{
		"/",
		"/api",
		"/api/",
		"/api/me",
		"/api/ui/discord-callback",
		"/api/docs/swagger-ui.css",
		"/api/developer_application/6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0",
		"/api/openapi.json",
		"/api/ui/logout.",
		"/api/..hidden",
	}

	for _, path := range canonical {
		if !canonicalPath(path) {
			t.Errorf("%q was refused, want it accepted", path)
		}
	}

	refused := map[string]string{
		"an empty target":                    "",
		"a target that is not a path":        "*",
		"an absolute-form target":            "http://elsewhere.test/api/me",
		"a repeated slash":                   "//api/me",
		"a repeated slash inside the path":   "/api//me",
		"a backslash":                        `/api\me`,
		"a dot segment":                      "/api/./me",
		"a parent segment":                   "/api/../api/me",
		"a trailing dot segment":             "/api/me/..",
		"an escaped slash":                   "/api%2fme",
		"an escaped dot segment":             "/api/%2e%2e/me",
		"an escaped letter":                  "/api/%6de",
		"an escaped space":                   "/api/me%20",
		"an escaped percent":                 "/api/%25",
		"escaped UTF-8":                      "/api/m%C3%A9",
		"an escape before the route root":    "/%61pi/me",
		"a dot segment above the route root": "/../api/me",
	}

	for name, path := range refused {
		if canonicalPath(path) {
			t.Errorf("%s (%q) was accepted", name, path)
		}
	}
}

// The query is the caller's, and a value in it is escaped as a matter of
// course. Reading only the path is what lets an escaped value through to the
// handler that has to see it exactly as it was sent.
func TestOnlyThePathOfATargetDecidesWhetherItIsCanonical(t *testing.T) {
	t.Parallel()

	targets := []string{
		"/api/ui/discord/authorize?callback_uri=https%3A%2F%2Frelying.example.test%2Freturn",
		"/api/google?code=a%2Bb&state=c%2Fd",
		"/api/me?a=%25&b=..&c=//",
	}

	for _, target := range targets {
		request := httptest.NewRequest(http.MethodGet, target, nil)

		if !canonicalPath(rawPath(request)) {
			t.Errorf("%q was refused for something in its query", target)
		}
	}
}

// A refused target is answered here, before the router, and is never sent on to
// the spelling it would have been cleaned into.
func TestATargetThisServiceDoesNotSpellIsRefusedWithoutARedirect(t *testing.T) {
	t.Parallel()

	served := false
	boundary := onlyCanonicalTargets(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		served = true
	}))

	request := httptest.NewRequest(http.MethodGet, "/api/../api/me", nil)
	recorder := httptest.NewRecorder()

	boundary.ServeHTTP(recorder, request)

	if served {
		t.Error("a target that is not spelled the way this service serves it reached a handler")
	}

	if recorder.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}

	if location := recorder.Header().Get("Location"); location != "" {
		t.Errorf("Location = %q, want nothing", location)
	}
}

// A browser is told what it may do with an address this service serves and with
// nothing else, so the match is made against the route table rather than
// against a prefix.
func TestTheRouteTableDecidesWhichPathsAreDeclared(t *testing.T) {
	t.Parallel()

	declared := []string{
		"/api",
		"/api/",
		"/api/me",
		"/api/user/applications",
		"/api/login",
		"/api/developer_application",
		"/api/developer_application/6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0",
		"/api/developer_application/6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0/reset_token",
		"/api/ui",
		"/api/ui/",
		"/api/ui/logout",
		"/api/ui/discord/authorize",
		"/api/google",
		"/api/docs",
		"/api/docs/",
		"/api/docs/swagger-ui.css",
		"/api/openapi.json",
	}

	for _, path := range declared {
		if !declaredPath(path) {
			t.Errorf("%q is served but is not recognised as declared", path)
		}
	}

	undeclared := []string{
		"/",
		"/me",
		"/login",
		"/ui/logout",
		"/openapi.json",
		"/api/me/",
		"/api/nothing-claims-this",
		"/api/developer_application//reset_token",
		"/api/ui//authorize",
		"/api/user",
		"/api/docs2",
	}

	for _, path := range undeclared {
		if declaredPath(path) {
			t.Errorf("%q is not served but is recognised as declared", path)
		}
	}
}
