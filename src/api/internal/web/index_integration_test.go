//go:build integration && !devtools

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
func TestRootSendsBrowserToSite(t *testing.T) {
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
func TestNothingIsServedAboveAPIsRouteRoot(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	unserved := []string{
		"/",
		"/me",
		"/user/applications",
		"/login",
		"/burn-token",
		"/developer_application",
		"/developer_application/00000000-0000-0000-0000-000000000001",
		"/google?code=placeholder&state=placeholder",
		"/ui",
		"/ui/",
		"/ui/logout",
		"/ui/discord-callback?code=placeholder&state=placeholder",
		"/ui/github-callback?code=placeholder&state=placeholder",
		"/ui/steam-callback?state=placeholder&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=cancel",
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
func TestPathThatNoRouteClaimsIsNotFound(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/nothing-claims-this").
		ExpectStatus(http.StatusNotFound).
		ExpectDetail("Not Found")
}

// A URL this service serves under another method is not the same as a URL it
// does not serve. A client can act on the difference, so the answers differ.
func TestKnownPathUnderWrongMethodIsRefusedAsSuch(t *testing.T) {
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
func TestTargetSpelledAnotherWayReachesNothing(t *testing.T) {
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
func TestEscapedQueryOnExactPathReachesHandler(t *testing.T) {
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

// The public-client addresses have one spelling each too. A handle, a code or
// a token sent to a spelling the router would clean or decode reaches nothing,
// is redirected nowhere and spends nothing; a wrong method is told so.
func TestPublicClientTargetsSpelledAnotherWayReachNothing(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	handle := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49152, "openid")))
	page := "/api/oauth/authorization/" + handle

	for name, target := range map[string]string{
		"a repeated slash":           "/api/oauth//authorization/" + handle,
		"a trailing slash":           page + "/",
		"a dot segment":              "/api/oauth/./authorization/" + handle,
		"a parent segment":           "/api/oauth/authorization/x/../" + handle,
		"a backslash":                `/api/oauth\authorization/` + handle,
		"an escaped handle byte":     "/api/oauth/authorization/%41" + handle[1:],
		"an escaped slash":           "/api/oauth/authorization%2F" + handle,
		"an empty handle":            "/api/oauth/authorization/",
		"a cancellation dot segment": page + "/x/../cancel",
		"a cancellation trailing":    page + "/cancel/",
		"an escaped provider":        page + "/%64iscord",
		"an empty provider":          page + "//discord",
		"a discovery trailing slash": "/api/.well-known/openid-configuration/",
		"an escaped discovery":       "/api/%2Ewell-known/openid-configuration",
		"a token trailing slash":     "/api/oauth/token/",
		"an escaped token address":   "/api/oauth/%74oken",
		"a repeated slash to revoke": "/api/oauth//revoke",
		"an authorize dot segment":   "/api/oauth/../oauth/authorize",
		"a key set trailing slash":   "/api/oidc/jwks/",
		"a userinfo escaped byte":    "/api/oauth/userinf%6F",
	} {
		t.Run(name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				answer := service.AtExactTarget(method, target, service.FromSite).ExpectStatus(http.StatusNotFound)

				if location := answer.Header.Get("Location"); location != "" {
					t.Errorf("%s %q was sent to %q", method, target, location)
				}
			}
		})
	}

	for target, method := range map[string]string{
		page:                                    http.MethodPost,
		page + "/discord":                       http.MethodGet,
		page + "/cancel":                        http.MethodGet,
		"/api/oauth/token":                      http.MethodGet,
		"/api/oauth/revoke":                     http.MethodGet,
		"/api/oauth/userinfo":                   http.MethodPost,
		"/api/oauth/authorize":                  http.MethodPost,
		"/api/.well-known/openid-configuration": http.MethodPost,
	} {
		service.AtExactTarget(method, target, service.FromSite).
			ExpectStatus(http.StatusMethodNotAllowed).
			ExpectDetail("Method Not Allowed")
	}

	// Nothing above consumed the request: it can still be chosen.
	service.POSTForm("/oauth/authorization/"+handle+"/discord", "", service.FromSite).ExpectStatus(http.StatusSeeOther)
}
