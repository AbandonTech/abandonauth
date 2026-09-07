//go:build integration

package web_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The root of the API is not an API endpoint. Somebody who types the address
// into a browser is sent to the site, which is named by configuration rather
// than by anything in the request.
func TestTheRootSendsABrowserToTheSite(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.AtExactTarget(http.MethodGet, "/api").
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo("/api/")

	service.AtExactTarget(http.MethodGet, "/api/").
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(servertest.SiteOrigin)
}

// Every address this service serves is under its own route root. Nothing
// answers above it, so a caller that reaches this service directly uses the
// same addresses a browser does.
func TestNothingIsServedAboveTheAPIsRouteRoot(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	unserved := []string{
		"/",
		"/me",
		"/user/applications",
		"/login",
		"/burn-token",
		"/developer_application",
		"/developer_application/6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0",
		"/google?code=placeholder&state=placeholder",
		"/ui",
		"/ui/",
		"/ui/logout",
		"/ui/discord-callback?code=placeholder&state=placeholder",
		"/ui/github-callback?code=placeholder&state=placeholder",
		"/ui/discord/authorize?application_id=placeholder&callback_uri=placeholder",
		"/docs",
		"/docs/",
		"/openapi.json",
		"/create_test_user",
		"/login_test_user",
	}

	for _, target := range unserved {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			answer := service.AtExactTarget(method, target).ExpectStatus(http.StatusNotFound)

			if location := answer.Header.Get("Location"); location != "" {
				t.Errorf("%s %s was sent to %q instead of being refused", method, target, location)
			}
		}
	}
}

// A path below the route root that no route claims is not served either, and
// the failure is one a client can parse rather than the router's plain text.
func TestAPathThatNoRouteClaimsIsNotFound(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/nothing-claims-this").
		ExpectStatus(http.StatusNotFound).
		ExpectDetail("Not Found")
}

// A URL this service serves under another method is not the same as a URL it
// does not serve. A client can act on the difference, so the answers differ.
func TestAKnownPathUnderTheWrongMethodIsRefusedAsSuch(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/", map[string]string{}).
		ExpectStatus(http.StatusMethodNotAllowed).
		ExpectDetail("Method Not Allowed")

	service.POSTJSON("/nothing-claims-this", map[string]string{}).
		ExpectStatus(http.StatusNotFound).
		ExpectDetail("Not Found")
}

// One spelling of an address is served. A target the router would clean, decode
// or redirect into one of them is refused where it arrives, so it never reaches
// the handler that would spend a login, a code or a session.
func TestATargetSpelledAnotherWayReachesNothing(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	spellings := map[string]string{
		"a repeated slash before the route root": "//api/me",
		"a repeated slash inside the path":       "/api//me",
		"a dot segment":                          "/api/./me",
		"a parent segment":                       "/api/../api/me",
		"a parent segment above the root":        "/../api/me",
		"a backslash":                            `/api\me`,
		"an escaped slash":                       "/api%2fme",
		"an escaped dot segment":                 "/api/%2e%2e/api/me",
		"an escaped letter":                      "/api/%6de",
		"an escaped space":                       "/api/me%20",
		"an escaped percent":                     "/api/%25",
		"an escaped UTF-8 letter":                "/api/m%C3%A9",
		"a trailing slash on an exact path":      "/api/me/",
		"a callback reached by a dot segment":    "/api/ui/../ui/discord-callback?state=placeholder",
	}

	for name, target := range spellings {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			answer := service.AtExactTarget(http.MethodGet, target).ExpectStatus(http.StatusNotFound)

			if location := answer.Header.Get("Location"); location != "" {
				t.Errorf("%q was sent to %q instead of being refused", target, location)
			}

			if got := answer.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("Access-Control-Allow-Origin = %q, want nothing", got)
			}
		})
	}
}

// Only the path decides. A query value is escaped as a matter of course, and it
// reaches the handler exactly as it was sent, which is what an exact callback
// comparison depends on.
func TestAnEscapedQueryOnAnExactPathReachesTheHandler(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	query := url.Values{
		"application_id": {service.Site.ApplicationID.String()},
		"callback_uri":   {service.Site.CallbackURI},
	}.Encode()

	service.GET("/ui/discord/authorize?" + query).
		ExpectStatus(http.StatusTemporaryRedirect)

	started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
	service.FinishLogin(started, service.Providers.Someone(oauth.Discord, "a person")).
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(service.Site.CallbackURI)
}
