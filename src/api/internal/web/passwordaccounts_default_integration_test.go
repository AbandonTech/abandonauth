//go:build integration && !devtools

package web_test

import (
	"net/http"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

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
