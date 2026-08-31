//go:build integration && !devtools

package web_test

import (
	"net/http"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// A deployment publishes no documentation. The handlers are not compiled into
// this build, so no configuration and no request can reach them: the addresses
// they would answer at are addresses this service does not serve.
func TestADeploymentServesNoDocumentation(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	unserved := []string{
		"/docs",
		"/docs/",
		"/docs/oauth2-redirect",
		"/docs/index.html",
		"/openapi.json",
		"/redoc",
	}

	for _, path := range unserved {
		service.GET(path).
			ExpectStatus(http.StatusNotFound).
			ExpectDetail("Not Found")
	}
}

// Seeding an account without a provider is development tooling. A deployment
// does not carry it, so the addresses are simply not served.
func TestADeploymentSeedsNoAccounts(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	for _, path := range []string{"/create_test_user", "/login_test_user"} {
		service.POSTJSON(path, map[string]string{
			"username": "a developer",
			"password": "placeholder-password",
		}).ExpectStatus(http.StatusNotFound).ExpectDetail("Not Found")
	}
}
