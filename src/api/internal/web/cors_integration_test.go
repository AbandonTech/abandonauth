//go:build integration && !devtools

package web_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// Exactly one origin may use this API from a browser, and it is named rather
// than reflected: a session is sent with these requests, so an origin that
// asked nicely would be given one.
func TestOnlyTheSiteMayUseTheAPIFromABrowser(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	permitted := service.GET("/ui/", servertest.Header("Origin", servertest.SiteOrigin))

	if got := permitted.Header.Get("Access-Control-Allow-Origin"); got != servertest.SiteOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, servertest.SiteOrigin)
	}

	if got := permitted.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q", got)
	}

	if !strings.Contains(permitted.Header.Get("Vary"), "Origin") {
		t.Errorf("Vary = %q, want the answer to be cached per origin", permitted.Header.Get("Vary"))
	}

	refused := map[string]string{
		"another site":                    "https://elsewhere.example.test",
		"the site over plain HTTP":        strings.Replace(servertest.SiteOrigin, "https", "http", 1),
		"a host the site is a prefix of":  servertest.SiteOrigin + ".elsewhere.example.test",
		"a name that is not an origin":    "not an origin",
		"the wildcard somebody asked for": "*",
	}

	for name, origin := range refused {
		t.Run(name, func(t *testing.T) {
			response := service.GET("/ui/", servertest.Header("Origin", origin))

			if got := response.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("Access-Control-Allow-Origin = %q, want nothing", got)
			}
		})
	}
}

// A preflight is answered without reaching a handler, and it names the methods
// this service serves rather than the one that was asked about.
func TestAPreflightNamesWhatTheServiceServes(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	response := service.OPTIONS("/developer_application",
		servertest.Header("Origin", servertest.SiteOrigin),
		servertest.Header("Access-Control-Request-Method", "DELETE"),
		servertest.Header("Access-Control-Request-Headers", "X-CSRF-Token"),
	).ExpectStatus(http.StatusNoContent)

	methods := response.Header.Get("Access-Control-Allow-Methods")
	for _, method := range []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"} {
		if !strings.Contains(methods, method) {
			t.Errorf("Access-Control-Allow-Methods = %q, without %s", methods, method)
		}
	}

	if strings.Contains(methods, "PUT") || strings.Contains(methods, "TRACE") {
		t.Errorf("Access-Control-Allow-Methods = %q, naming a method this service does not serve", methods)
	}

	headers := response.Header.Get("Access-Control-Allow-Headers")
	for _, header := range []string{"Authorization", "Content-Type", "X-CSRF-Token", "exchange-token"} {
		if !strings.Contains(headers, header) {
			t.Errorf("Access-Control-Allow-Headers = %q, without %s", headers, header)
		}
	}
}

// A preflight from an origin that may not use the API is answered, but with no
// permission in it, which is what stops the browser.
func TestAPreflightFromAnotherSiteIsGivenNoPermission(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	response := service.OPTIONS("/developer_application",
		servertest.Header("Origin", "https://elsewhere.example.test"),
		servertest.Header("Access-Control-Request-Method", "POST"),
	).ExpectStatus(http.StatusNoContent)

	for _, header := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
	} {
		if got := response.Header.Get(header); got != "" {
			t.Errorf("%s = %q, want nothing", header, got)
		}
	}
}

// A preflight asks what a browser may do with an address. An address this
// service does not serve is reported as not served, whoever asked: answering it
// would describe permissions for something there is nothing at, and would do so
// for spellings the route table deliberately refuses.
func TestAPreflightToAnAddressThisServiceDoesNotServeIsRefused(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	targets := map[string]string{
		"an address above the route root":   "/developer_application",
		"a session endpoint above the root": "/ui/logout",
		"an address no route claims":        "/api/nothing-claims-this",
		"a repeated slash":                  "/api//developer_application",
		"a dot segment":                     "/api/../api/developer_application",
		"an escaped slash":                  "/api%2fdeveloper_application",
		"a trailing slash on an exact path": "/api/developer_application/login/",
	}

	origins := map[string]string{
		"the site":       servertest.SiteOrigin,
		"another origin": "https://elsewhere.example.test",
	}

	for name, target := range targets {
		for originName, origin := range origins {
			t.Run(name+", from "+originName, func(t *testing.T) {
				t.Parallel()

				response := service.AtExactTarget(http.MethodOptions, target,
					servertest.Header("Origin", origin),
					servertest.Header("Access-Control-Request-Method", "POST"),
				).ExpectStatus(http.StatusNotFound)

				for _, header := range []string{
					"Access-Control-Allow-Origin",
					"Access-Control-Allow-Credentials",
					"Access-Control-Allow-Methods",
					"Access-Control-Allow-Headers",
				} {
					if got := response.Header.Get(header); got != "" {
						t.Errorf("%s = %q, want nothing", header, got)
					}
				}
			})
		}
	}
}

// The permission headers a plain request carries are decided the same way, so
// an address that is not served describes nothing to a browser either.
func TestAnAddressThisServiceDoesNotServeGrantsNoOriginPermission(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	for _, target := range []string{"/me", "/api/nothing-claims-this", "/api//me"} {
		response := service.AtExactTarget(http.MethodGet, target,
			servertest.Header("Origin", servertest.SiteOrigin),
		).ExpectStatus(http.StatusNotFound)

		if got := response.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s: Access-Control-Allow-Origin = %q, want nothing", target, got)
		}
	}
}

// Every answer carries an identifier a person can quote, and one they supplied
// is used so a request can be followed through a proxy.
func TestEveryAnswerCarriesAnIdentifier(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	generated := service.GET("/ui/").Header.Get(web.RequestIDHeader)
	if generated == "" {
		t.Error("an answer carried no identifier")
	}

	supplied := service.GET("/ui/", servertest.Header(web.RequestIDHeader, "a-request-a-proxy-named"))
	if got := supplied.Header.Get(web.RequestIDHeader); got != "a-request-a-proxy-named" {
		t.Errorf("identifier = %q, want the one the request carried", got)
	}

	unusable := map[string]string{
		"far longer than any identifier": strings.Repeat("x", 128),
		"a value that is not plain text": "an identifier with é in it",
	}

	for name, value := range unusable {
		t.Run(name, func(t *testing.T) {
			response := service.GET("/ui/", servertest.Header(web.RequestIDHeader, value))

			if got := response.Header.Get(web.RequestIDHeader); got == value || got == "" {
				t.Errorf("identifier = %q, want one this service made up", got)
			}
		})
	}
}

// The log says what happened without repeating anything the request carried.
func TestTheLogHoldsNoRequestValues(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	session := service.CookieValue(service.SessionCookieName())

	service.GET("/user/applications?a-query-value=should-not-be-logged")

	written := service.Logs.String()

	for name, value := range map[string]string{
		"a query value":   "should-not-be-logged",
		"a session value": session,
	} {
		if value != "" && strings.Contains(written, value) {
			t.Errorf("%s reached the log", name)
		}
	}

	if !strings.Contains(written, `"route":"GET /api/user/applications"`) {
		t.Error("the log does not say which route answered")
	}
}
