//go:build integration

package web_test

import (
	"net/http"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// Rotating the authority is what an operator reaches for when a credential may
// have leaked, and it has to be enough on its own. Every class of credential
// this service accepts stops being accepted at the endpoints that took it.
//
// Each of them is proved to work first, so a refusal afterwards cannot pass by
// the whole arrangement having been broken from the start.
func TestNothingIssuedBeforeARotationIsAcceptedAfterIt(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)

	applicationToken := applicationAccessToken(t, service, application.ID, application.RefreshToken)
	personToken := userAccessToken(t, service, application)
	withdrawnToken := userAccessToken(t, service, application)

	service.GET("/developer_application/me", servertest.Bearer(applicationToken)).
		ExpectStatus(http.StatusOK)
	service.GET("/me", servertest.Bearer(personToken)).ExpectStatus(http.StatusOK)
	service.GET("/me", servertest.Bearer(withdrawnToken)).ExpectStatus(http.StatusOK)
	service.GET("/me").ExpectStatus(http.StatusOK)

	service.POSTJSON("/burn-token", map[string]string{"token": withdrawnToken}).
		ExpectStatus(http.StatusOK)

	service.GET("/me", servertest.Bearer(withdrawnToken)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")
	service.GET("/me", servertest.Bearer(personToken)).ExpectStatus(http.StatusOK)

	if _, err := database.RotateAuthority(t.Context(), service.Pool); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	service.GET("/me", servertest.Bearer(personToken)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")

	service.GET("/developer_application/me", servertest.Bearer(applicationToken)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")

	// The record that refused this one is among the things a rotation clears,
	// and it is refused all the same: the authority it was issued under is what
	// refuses it now.
	service.GET("/me", servertest.Bearer(withdrawnToken)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")

	service.GET("/me").
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")
}

// userAccessToken signs a new person in to an application and collects the
// token that identifies them to it.
func userAccessToken(
	t *testing.T, service *servertest.Service, application servertest.Application,
) string {
	t.Helper()

	code := signInToApplication(t, service, application, externalCallbackURI)

	var granted struct {
		Token string `json:"token"`
	}

	service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusOK).DecodeInto(&granted)

	return granted.Token
}
