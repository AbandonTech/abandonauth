//go:build integration

package web_test

import (
	"net/http"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The root of the API is not an API endpoint. Somebody who types the host into a
// browser is sent to the site.
func TestTheRootSendsABrowserToTheSite(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/").
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo("/ui")
}

// Only the root itself redirects. A path below it is not the site.
func TestAPathThatNoRouteClaimsIsNotFound(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/nothing-claims-this").ExpectStatus(http.StatusNotFound)
}

// A URL this service serves under another method is not the same as a URL it
// does not serve. A client can act on the difference, so the answers differ.
func TestAKnownPathUnderTheWrongMethodIsRefusedAsSuch(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/", map[string]string{}).
		ExpectStatus(http.StatusMethodNotAllowed).
		ExpectDetail("Method Not Allowed")
}

// Every failure a client can provoke is one it can parse. The router's own
// plain-text answers would not be.
func TestAFailureThatNoHandlerProducedIsStillTheServicesOwnShape(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/nothing-claims-this").
		ExpectStatus(http.StatusNotFound).
		ExpectDetail("Not Found")
}
