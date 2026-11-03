//go:build integration && !devtools

package web_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

func expectEmptyRevocation(t *testing.T, answer *servertest.Response) {
	t.Helper()

	answer.ExpectStatus(http.StatusOK)

	if len(answer.Body) != 0 {
		t.Errorf("a revocation answered with a body: %q", answer.Body)
	}

	if answer.Header.Get("Cache-Control") != "no-store" || answer.Header.Get("Pragma") != "no-cache" {
		t.Error("a revocation answer may be cached")
	}
}

// Revoking a refresh token ends its family at once, whatever hints come with
// it, and every well-formed request that revokes nothing is answered the same.
func TestRevokingRefreshTokenEndsItsFamily(t *testing.T) {
	t.Parallel()

	for name, hints := range map[string][]string{
		"no hint":           nil,
		"the matching hint": {"refresh_token"},
		"the other hint":    {"access_token"},
		"an unknown hint":   {"id_token"},
		"an empty hint":     {""},
		"repeated hints":    {"access_token", "refresh_token", "REFRESH_TOKEN"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			_, client := installedClient(t, service)

			_, issued := client.Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "p"))

			expectEmptyRevocation(t, client.Revoke(issued.RefreshToken, hints...))
			expectOAuthError(t, client.Refresh(issued.RefreshToken, ""), http.StatusBadRequest, "invalid_grant")
			expectEmptyRevocation(t, client.Revoke(issued.RefreshToken, hints...))
		})
	}
}

// Revoking an access token makes AbandonAuth refuse it at once, while a
// resource server validating it locally still accepts it until it expires.
func TestRevokingAccessTokenStopsUserInfoNotLocalValidation(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)
	_, accessTokens := validators(t, service)

	_, issued := client.Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "p"))

	service.GET("/oauth/userinfo", servertest.Bearer(issued.AccessToken)).ExpectStatus(http.StatusOK)

	expectEmptyRevocation(t, client.Revoke(issued.AccessToken, "refresh_token"))

	expectInvalidToken(t, service.GET("/oauth/userinfo", servertest.Bearer(issued.AccessToken)))

	if _, err := accessTokens.ValidateAccessToken(issued.AccessToken, application.ID.String()); err != nil {
		t.Errorf("a local validator stopped accepting a revoked token before it expired: %v", err)
	}

	// Revoking an access token leaves the offline grant it came from.
	client.Refresh(issued.RefreshToken, "").ExpectStatus(http.StatusOK)
}

// A revocation that names another client, a confidential application, an
// unknown one or an unknown token revokes nothing and is answered exactly as
// one that does.
func TestRevocationIsIndistinguishableWhenItRevokesNothing(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	other := service.InstalledClient(service.RegisterPublicClient("another installed application", ipv4Template))
	confidential := service.RegisterApplication("a server-side application", externalCallbackURI)

	_, issued := client.Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "p"))

	revoke := func(clientID, token string) *servertest.Response {
		return service.POSTForm("/oauth/revoke", "client_id="+clientID+"&token="+token)
	}

	for name, answer := range map[string]*servertest.Response{
		"another client's refresh token": revoke(other.ClientID.String(), issued.RefreshToken),
		"another client's access token":  revoke(other.ClientID.String(), issued.AccessToken),
		"a confidential application":     revoke(confidential.ID.String(), issued.RefreshToken),
		"an unknown application":         revoke("00000000-0000-0000-0000-00000000dead", issued.RefreshToken),
		"an unknown refresh token":       revoke(client.ClientID.String(), strings.Repeat("U", 42)+"A"),
		"an ID token":                    revoke(client.ClientID.String(), issued.IDToken),
		"something else entirely":        revoke(client.ClientID.String(), "not-a-token"),
	} {
		t.Run(name, func(t *testing.T) { expectEmptyRevocation(t, answer) })
	}

	client.Refresh(issued.RefreshToken, "").ExpectStatus(http.StatusOK)
	service.GET("/oauth/userinfo", servertest.Bearer(issued.AccessToken)).ExpectStatus(http.StatusOK)

	expectOAuthError(t, service.POSTForm("/oauth/revoke", "client_id="+client.ClientID.String()),
		http.StatusBadRequest, "invalid_request")
	expectOAuthError(t, service.POSTJSON("/oauth/revoke", map[string]string{"token": issued.RefreshToken}),
		http.StatusBadRequest, "invalid_request")
}

// One person and one application hold at most a thousand revoked access tokens
// that have not expired. Beyond that, revoking a genuine token is refused as
// temporarily unavailable and the token is not recorded as revoked; another
// person's allowance is untouched.
func TestAccessTokenRevocationsAreBoundedPerPersonAndApplication(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)

	_, full := client.Tokens(ipv4Template, "openid", service.Providers.Someone(oauth.Discord, "p"))
	_, bystander := client.Tokens(ipv4Template, "openid", service.Providers.Someone(oauth.Discord, "q"))

	subject, _ := servertest.DecodeClaims(full.AccessToken)["sub"].(string)

	// A thousand revocations are written directly: each would otherwise need
	// its own sign-in.
	testdatabase.Execute(t, service.Pool, `INSERT INTO oauth_access_token_revocation (jti, application_id, user_id, expires_at)
		SELECT gen_random_uuid(), s.application_id, s.user_id, CURRENT_TIMESTAMP + interval '10 minutes'
		FROM oauth_pairwise_subject s, generate_series(1, $3::int)
		WHERE s.application_id = $1 AND s.subject = $2`, application.ID, subject, oauth.MaxAccessTokenRevocations)

	expectOAuthError(t, client.Revoke(full.AccessToken), http.StatusServiceUnavailable, "temporarily_unavailable")
	service.GET("/oauth/userinfo", servertest.Bearer(full.AccessToken)).ExpectStatus(http.StatusOK)

	expectEmptyRevocation(t, client.Revoke(bystander.AccessToken))
	expectInvalidToken(t, service.GET("/oauth/userinfo", servertest.Bearer(bystander.AccessToken)))

	// Revocations that have expired are reclaimed first, which frees room.
	testdatabase.Execute(t, service.Pool, `UPDATE oauth_access_token_revocation
		SET expires_at = CURRENT_TIMESTAMP - interval '1 second'
		WHERE jti IN (
			SELECT v.jti FROM oauth_access_token_revocation v
			JOIN oauth_pairwise_subject s ON s.application_id = v.application_id AND s.user_id = v.user_id
			WHERE s.application_id = $1 AND s.subject = $2
			LIMIT 1)`, application.ID, subject)

	expectEmptyRevocation(t, client.Revoke(full.AccessToken))
	expectInvalidToken(t, service.GET("/oauth/userinfo", servertest.Bearer(full.AccessToken)))
}
