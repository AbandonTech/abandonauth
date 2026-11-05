//go:build integration && !devtools

package web_test

import (
	"bytes"
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
func TestNothingIssuedBeforeRotationIsAcceptedAfterIt(t *testing.T) {
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
		ExpectDetail("Invalid access token")
	service.GET("/me", servertest.Bearer(personToken)).ExpectStatus(http.StatusOK)

	if _, err := database.RotateAuthority(t.Context(), service.Pool); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	rotatedUser := service.GET("/me", servertest.Bearer(personToken)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid access token")

	rotatedApplication := service.GET("/developer_application/me", servertest.Bearer(applicationToken)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid access token")

	// The withdrawal record is among the things a rotation clears, and the token
	// is refused all the same: its auth epoch claim is no longer current.
	service.GET("/me", servertest.Bearer(withdrawnToken)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid access token")

	// A stale auth epoch is indistinguishable from a token this service never
	// issued.
	forged := service.GET("/me", servertest.Bearer("not-a-token")).ExpectStatus(http.StatusForbidden)

	for name, refused := range map[string]*servertest.Response{
		"a user token":                  rotatedUser,
		"a developer application token": rotatedApplication,
	} {
		if !bytes.Equal(refused.Body, forged.Body) {
			t.Errorf("%s from before the rotation was refused as %s, a forged token as %s", name, refused.Body, forged.Body)
		}
	}

	service.GET("/me").
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Authentication required")
}

// userAccessToken signs a new user in to an application and collects a user
// access token whose audience is that application.
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

// Rotating the authority withdraws every public client's authority at once: a
// page waiting for a choice, a sign-in at the provider, an unredeemed code, an
// offline grant and AbandonAuth's acceptance of an access token. A sign-in
// afterwards names the person by the same canonical UUID, their user
// identifier, which no rotation touches.
func TestRotationWithdrawsEveryPublicClientAuthority(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	person := service.Providers.Someone(oauth.Discord, "the person")
	_, issued := client.Tokens(ipv4Template, "openid offline_access", person)

	handle := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49153, "openid")))

	atProvider := client.Pending(ipv4Template, 49154, "openid")
	started := client.BeginPublicSignIn(atProvider, oauth.GitHub)

	unredeemed := client.Pending(ipv4Template, 49155, "openid")
	code := client.SignIn(unredeemed, oauth.Discord, "someone")

	consent := client.ReachConsent(client.Pending(ipv4Template, 49156, "openid"), oauth.Discord,
		service.Providers.Someone(oauth.Discord, "someone deciding"))

	if _, err := database.RotateAuthority(t.Context(), service.Pool); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	service.GET("/oauth/authorization/" + handle).ExpectStatus(http.StatusNotFound)
	service.FinishLogin(started, service.Providers.Someone(oauth.GitHub, "someone")).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Sign-in validation failed")
	expectUnavailable(t, service.GET("/oauth/consent/"+consent))
	expectUnavailable(t, service.AllowConsent(consent))
	expectUnavailable(t, service.CancelConsent(consent))
	expectOAuthError(t, client.Exchange(unredeemed, code), http.StatusBadRequest, "invalid_grant")
	expectOAuthError(t, client.Refresh(issued.RefreshToken, ""), http.StatusBadRequest, "invalid_grant")
	expectInvalidToken(t, service.GET("/oauth/userinfo", servertest.Bearer(issued.AccessToken)))

	_, after := client.Tokens(ipv4Template, "openid", person)

	if subject := servertest.DecodeClaims(after.AccessToken)["sub"]; subject != userIDOf(t, service, "the person") ||
		subject != servertest.DecodeClaims(issued.AccessToken)["sub"] {
		t.Errorf("a sign-in after the rotation named the person %v", subject)
	}
}
