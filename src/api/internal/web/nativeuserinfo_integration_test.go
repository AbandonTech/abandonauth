//go:build integration && !devtools

package web_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

func expectInvalidToken(t *testing.T, answer *servertest.Response) {
	t.Helper()

	expectOAuthError(t, answer, http.StatusUnauthorized, "invalid_token")

	if got := answer.Header.Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Errorf("challenge = %q", got)
	}
}

// UserInfo releases the user's canonical UUID as the subject, the same one the
// token carries, and the username only under profile.
func TestUserInfoReleasesOnlyWhatScopeGrants(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	_, withProfile := client.Tokens(ipv4Template, "openid profile", service.Providers.Someone(oauth.Discord, "the person"))
	_, without := client.Tokens(ipv4Template, "openid", service.Providers.Someone(oauth.Discord, "another person"))

	for name, test := range map[string]struct {
		token    string
		username string
		members  []string
	}{
		"with profile":    {withProfile.AccessToken, "the person", []string{"preferred_username", "sub"}},
		"without profile": {without.AccessToken, "another person", []string{"sub"}},
	} {
		t.Run(name, func(t *testing.T) {
			answer := service.GET("/oauth/userinfo", servertest.Bearer(test.token)).ExpectStatus(http.StatusOK)

			if answer.Header.Get("Cache-Control") != "no-store" || answer.Header.Get("Pragma") != "no-cache" {
				t.Error("the claims may be cached")
			}

			var claims map[string]json.RawMessage
			answer.DecodeInto(&claims)

			names := make([]string, 0, len(claims))
			for name := range claims {
				names = append(names, name)
			}

			slices.Sort(names)

			if !slices.Equal(names, test.members) {
				t.Errorf("released %v, want %v", names, test.members)
			}

			if subject := servertest.DecodeClaims(test.token)["sub"]; string(claims["sub"]) != `"`+subject.(string)+`"` {
				t.Error("UserInfo named another subject than the token")
			}

			if want := `"` + userIDOf(t, service, test.username) + `"`; string(claims["sub"]) != want {
				t.Errorf("UserInfo named the person %s, want %s", claims["sub"], want)
			}
		})
	}
}

// Only a genuine, current OIDC access token is accepted, and every refusal is
// the same fixed challenge that quotes nothing.
func TestUserInfoAcceptsOnlyGenuineCurrentAccessTokens(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	service.SignInSomeone("a site user")
	confidential := service.RegisterApplication("a server-side application", externalCallbackURI)
	userToken := userAccessToken(t, service, confidential)
	applicationToken := applicationAccessToken(t, service, confidential.ID, confidential.RefreshToken)

	_, issued := client.Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "p"))
	keys := servertest.SigningKeyFiles(t)

	claims := servertest.DecodeClaims(issued.AccessToken)

	header := func(kid, typ string) map[string]any { return map[string]any{"alg": "RS256", "kid": kid, "typ": typ} }
	accessKeyID := keys.AccessTokenKeyID()
	idKeyID := keys.IDTokenKeyID()

	altered := func(change func(map[string]any)) map[string]any {
		copied := make(map[string]any, len(claims))
		for name, value := range claims {
			copied[name] = value
		}

		change(copied)

		return copied
	}

	sign := func(key string, header, claims map[string]any) string {
		private := keys.AccessTokenPrivate
		if key == "id" {
			private = keys.IDTokenPrivate
		}

		token, err := servertest.SignAs(private, header, claims)
		if err != nil {
			t.Fatalf("signing a test token: %v", err)
		}

		return token
	}

	now := time.Now().Unix()
	subject, _ := claims["sub"].(string)
	resigned := func(change func(map[string]any)) string {
		return "Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(change))
	}
	withSubject := func(value any) string {
		return resigned(func(c map[string]any) { c["sub"] = value })
	}

	for name, headers := range map[string][]string{
		"no header":                      nil,
		"an ID token":                    {"Bearer " + issued.IDToken},
		"a refresh token":                {"Bearer " + issued.RefreshToken},
		"a user access token":            {"Bearer " + userToken},
		"an application token":           {"Bearer " + applicationToken},
		"another scheme":                 {"Basic " + issued.AccessToken},
		"two headers":                    {"Bearer " + issued.AccessToken, "Bearer " + issued.AccessToken},
		"a truncated signature":          {"Bearer " + issued.AccessToken[:len(issued.AccessToken)-4]},
		"an oversized token":             {"Bearer " + strings.Repeat("a", 8193)},
		"signed with the ID key":         {"Bearer " + sign("id", header(accessKeyID, "at+jwt"), claims)},
		"the ID key's identifier":        {"Bearer " + sign("id", header(idKeyID, "at+jwt"), claims)},
		"the ID token type":              {"Bearer " + sign("access", header(accessKeyID, "JWT"), claims)},
		"no type":                        {"Bearer " + sign("access", map[string]any{"alg": "RS256", "kid": accessKeyID}, claims)},
		"another algorithm":              {"Bearer " + sign("access", map[string]any{"alg": "RS384", "kid": accessKeyID, "typ": "at+jwt"}, claims)},
		"no algorithm":                   {"Bearer " + unsignedToken(claims)},
		"an embedded key":                {"Bearer " + sign("access", map[string]any{"alg": "RS256", "kid": accessKeyID, "typ": "at+jwt", "jwk": map[string]any{}}, claims)},
		"another issuer":                 {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["iss"] = servertest.APIOrigin }))},
		"an audience list":               {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["aud"] = []any{c["aud"]} }))},
		"another audience":               {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["aud"] = uuid.NewString() }))},
		"a longer lifetime":              {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["exp"] = now + 3600 }))},
		"an expired token":               {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["iat"], c["nbf"], c["exp"] = now-1000, now-1000, now-100 }))},
		"a fractional time":              {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["iat"] = 1.5 }))},
		"a string time":                  {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["exp"] = "9999999999" }))},
		"an unknown user":                {withSubject(uuid.NewString())},
		"a user the client never served": {withSubject(userIDOf(t, service, "a site user"))},
		"the nil subject":                {withSubject(uuid.Nil.String())},
		"an upper-case subject":          {withSubject(strings.ToUpper(subject))},
		"a braced subject":               {withSubject("{" + subject + "}")},
		"a compact subject":              {withSubject(strings.ReplaceAll(subject, "-", ""))},
		"a malformed subject":            {withSubject(subject[:35] + "g")},
		"an opaque subject":              {withSubject(strings.Repeat("S", 42) + "A")},
		"a numeric subject":              {withSubject(7)},
		"no subject":                     {resigned(func(c map[string]any) { delete(c, "sub") })},
		"a stale epoch":                  {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["auth_epoch"] = uuid.NewString() }))},
		"an added claim":                 {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["preferred_username"] = "p" }))},
		"a non-canonical scope":          {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["scope"] = "offline_access openid" }))},
		"another client, same claim":     {"Bearer " + sign("access", header(accessKeyID, "at+jwt"), altered(func(c map[string]any) { c["client_id"], c["aud"] = uuid.NewString(), uuid.NewString() }))},
	} {
		t.Run(name, func(t *testing.T) {
			expectInvalidToken(t, service.GET("/oauth/userinfo", func(request *http.Request) {
				for _, value := range headers {
					request.Header.Add("Authorization", value)
				}
			}))
		})
	}

	// The genuine token is the positive control, and so is the same claims
	// re-signed with the genuine key and header.
	service.GET("/oauth/userinfo", servertest.Bearer(issued.AccessToken)).ExpectStatus(http.StatusOK)
	service.GET("/oauth/userinfo", servertest.Bearer(sign("access", header(accessKeyID, "at+jwt"), claims))).
		ExpectStatus(http.StatusOK)

	// An OIDC access token is refused by every route that takes the other
	// token classes.
	service.Forget(service.SessionCookieName())
	service.GET("/me", servertest.Bearer(issued.AccessToken)).ExpectStatus(http.StatusForbidden)
	service.GET("/developer_application/me", servertest.Bearer(issued.AccessToken)).ExpectStatus(http.StatusForbidden)
}

// unsignedToken is the alg-none spelling of a token, which carries no key and
// no signature.
func unsignedToken(claims map[string]any) string {
	encoded, _ := json.Marshal(claims)

	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(encoded) + "."
}

// AbandonAuth refuses an access token at once after authority rotation, user
// deletion or application deletion, while a resource server validating it
// locally still accepts it until it expires.
func TestUserInfoStopsAtOnceWhileLocalValidationContinues(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)
	_, accessTokens := validators(t, service)

	deleted := service.RegisterPublicClient("a deleted installed application", ipv4Template)
	_, ofDeleted := service.InstalledClient(deleted).
		Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "q"))

	service.GET("/oauth/userinfo", servertest.Bearer(ofDeleted.AccessToken)).ExpectStatus(http.StatusOK)
	service.DELETE("/developer_application/"+deleted.ID.String(), service.Protected).ExpectStatus(http.StatusOK)
	expectInvalidToken(t, service.GET("/oauth/userinfo", servertest.Bearer(ofDeleted.AccessToken)))
	expectOAuthError(t, service.InstalledClient(deleted).Refresh(ofDeleted.RefreshToken, ""),
		http.StatusBadRequest, "invalid_client")

	if _, err := accessTokens.ValidateAccessToken(ofDeleted.AccessToken, deleted.ID.String()); err != nil {
		t.Errorf("a local validator stopped accepting a deleted application's token before it expired: %v", err)
	}

	// No endpoint deletes a person, so the row is removed as an operator would.
	_, ofGone := client.Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "gone"))

	service.GET("/oauth/userinfo", servertest.Bearer(ofGone.AccessToken)).ExpectStatus(http.StatusOK)
	testdatabase.Execute(t, service.Pool, `DELETE FROM "User" WHERE "id" = $1`, userIDOf(t, service, "gone"))
	expectInvalidToken(t, service.GET("/oauth/userinfo", servertest.Bearer(ofGone.AccessToken)))
	expectOAuthError(t, client.Refresh(ofGone.RefreshToken, ""), http.StatusBadRequest, "invalid_grant")

	if _, err := accessTokens.ValidateAccessToken(ofGone.AccessToken, application.ID.String()); err != nil {
		t.Errorf("a local validator stopped accepting a deleted person's token before it expired: %v", err)
	}

	_, issued := client.Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "p"))

	service.GET("/oauth/userinfo", servertest.Bearer(issued.AccessToken)).ExpectStatus(http.StatusOK)

	// A rotation also ends the developer's own browser session, so it comes
	// last.
	if _, err := database.RotateAuthority(t.Context(), service.Pool); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	expectInvalidToken(t, service.GET("/oauth/userinfo", servertest.Bearer(issued.AccessToken)))
	expectOAuthError(t, client.Refresh(issued.RefreshToken, ""), http.StatusBadRequest, "invalid_grant")

	if _, err := accessTokens.ValidateAccessToken(issued.AccessToken, application.ID.String()); err != nil {
		t.Errorf("a local validator stopped accepting a token before it expired: %v", err)
	}

	_, current := client.Tokens(ipv4Template, "openid", service.Providers.Someone(oauth.Discord, "r"))
	service.GET("/oauth/userinfo", servertest.Bearer(current.AccessToken)).ExpectStatus(http.StatusOK)
}

// A validator allows no clock tolerance: a token is accepted from the second
// it is issued until the second before it expires, and a real clock error
// moves that window by exactly the error.
func TestLocalValidationHasNoClockTolerance(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)

	_, issued := client.Tokens(ipv4Template, "openid", service.Providers.Someone(oauth.Discord, "p"))

	claims := servertest.DecodeClaims(issued.AccessToken)
	issuedAt, _ := claims["iat"].(json.Number).Int64()

	for name, test := range map[string]struct {
		at     int64
		accept bool
	}{
		"a second before issue":                  {issuedAt - 1, false},
		"at issue":                               {issuedAt, true},
		"a second before expiry":                 {issuedAt + 899, true},
		"at expiry":                              {issuedAt + 900, false},
		"after expiry":                           {issuedAt + 901, false},
		"a clock thirty seconds slow, at expiry": {issuedAt + 900 - 30, true},
		"a clock thirty seconds fast, at issue":  {issuedAt + 30, true},
	} {
		t.Run(name, func(t *testing.T) {
			validator, err := service.AccessTokenValidator(servertest.OpenIDIssuer, func() time.Time {
				return time.Unix(test.at, 0)
			})
			if err != nil {
				t.Fatalf("building a validator: %v", err)
			}

			_, err = validator.ValidateAccessToken(issued.AccessToken, application.ID.String())
			if accepted := err == nil; accepted != test.accept {
				t.Errorf("accepted = %v, want %v", accepted, test.accept)
			}
		})
	}
}
