//go:build integration && !devtools

package web_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The discovery document advertises exactly the implemented profile, below
// exactly the configured issuer, and may be cached for five minutes.
func TestDiscoveryAdvertisesExactlyTheImplementedProfile(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	answer := service.GET("/.well-known/openid-configuration", servertest.Header("Origin", servertest.SiteOrigin)).
		ExpectStatus(http.StatusOK)

	if got := answer.Header.Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", got)
	}

	if answer.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("the discovery document permits a cross-origin read")
	}

	var document map[string]any
	answer.DecodeInto(&document)

	issuer := servertest.OpenIDIssuer
	want := map[string]any{
		"issuer":                                         issuer,
		"authorization_endpoint":                         issuer + "/oauth/authorize",
		"token_endpoint":                                 issuer + "/oauth/token",
		"userinfo_endpoint":                              issuer + "/oauth/userinfo",
		"revocation_endpoint":                            issuer + "/oauth/revoke",
		"jwks_uri":                                       issuer + "/oidc/jwks",
		"access_token_jwks_uri":                          issuer + "/oauth/access-jwks",
		"response_types_supported":                       []any{"code"},
		"response_modes_supported":                       []any{"query"},
		"grant_types_supported":                          []any{"authorization_code", "refresh_token"},
		"subject_types_supported":                        []any{"public"},
		"id_token_signing_alg_values_supported":          []any{"RS256"},
		"scopes_supported":                               []any{"openid", "profile", "offline_access"},
		"token_endpoint_auth_methods_supported":          []any{"none"},
		"revocation_endpoint_auth_methods_supported":     []any{"none"},
		"code_challenge_methods_supported":               []any{"S256"},
		"authorization_response_iss_parameter_supported": true,
	}

	if len(document) != len(want) {
		t.Errorf("the document has %d members, want %d", len(document), len(want))
	}

	for member, value := range want {
		encodedWant, _ := json.Marshal(value)
		encodedGot, _ := json.Marshal(document[member])

		if string(encodedGot) != string(encodedWant) {
			t.Errorf("%s = %s, want %s", member, encodedGot, encodedWant)
		}
	}
}

// Each key set publishes exactly one public key, of its own purpose, under its
// RFC 7638 thumbprint, and nothing private.
func TestKeySetsArePublicAndPurposeSeparated(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	keys := servertest.SigningKeyFiles(t)

	published := map[string]string{}

	for path, private := range map[string]string{
		"/oidc/jwks":         keys.IDTokenKeyID(),
		"/oauth/access-jwks": keys.AccessTokenKeyID(),
	} {
		answer := service.GET(path).ExpectStatus(http.StatusOK)

		if got := answer.Header.Get("Cache-Control"); got != "public, max-age=300" {
			t.Errorf("%s Cache-Control = %q", path, got)
		}

		var set struct {
			Keys []map[string]any `json:"keys"`
		}

		answer.DecodeInto(&set)

		if len(set.Keys) != 1 {
			t.Fatalf("%s publishes %d keys, want one", path, len(set.Keys))
		}

		key := set.Keys[0]

		members := make([]string, 0, len(key))
		for member := range key {
			members = append(members, member)
		}

		slices.Sort(members)

		if !slices.Equal(members, []string{"alg", "e", "kid", "kty", "n", "use"}) {
			t.Errorf("%s publishes members %v", path, members)
		}

		if key["kty"] != "RSA" || key["use"] != "sig" || key["alg"] != "RS256" || key["kid"] != private {
			t.Errorf("%s publishes %v", path, key)
		}

		canonical := `{"e":"` + key["e"].(string) + `","kty":"RSA","n":"` + key["n"].(string) + `"}`
		digest := sha256.Sum256([]byte(canonical))

		if thumbprint := base64.RawURLEncoding.EncodeToString(digest[:]); key["kid"] != thumbprint {
			t.Errorf("%s publishes a kid that is not the key's thumbprint", path)
		}

		published[path] = key["kid"].(string)
	}

	if published["/oidc/jwks"] == published["/oauth/access-jwks"] {
		t.Error("both purposes publish the same key")
	}
}

// A client trusts discovery only from the issuer it was configured with, and
// only when the document names that issuer exactly.
func TestDiscoveryIsTrustedOnlyFromExpectedIssuer(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	if _, err := service.Discovery(servertest.OpenIDIssuer); err != nil {
		t.Fatalf("discovery from the configured issuer was refused: %v", err)
	}

	for _, expected := range []string{
		servertest.OpenIDIssuer + "/",
		servertest.APIOrigin,
		servertest.SiteOrigin + "/api",
		servertest.OpenIDIssuer + "/oauth",
	} {
		if _, err := service.IDTokenValidator(expected, nil); err == nil {
			t.Errorf("a validator expecting %q trusted this service's discovery", expected)
		}
	}
}

// Compromise of one purpose's key never lets a validator of the other class
// accept a forged token: a complete access token signed with the ID token key
// and a complete ID token signed with the access token key are both refused,
// by external validators and by UserInfo, while genuine tokens are accepted.
func TestForgedCrossPurposeTokensAreRefused(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)
	keys := servertest.SigningKeyFiles(t)
	idTokens, accessTokens := validators(t, service)

	pending, issued := client.Tokens(ipv4Template, "openid profile", service.Providers.Someone(oauth.Discord, "p"))

	accessClaims := servertest.DecodeClaims(issued.AccessToken)
	idClaims := servertest.DecodeClaims(issued.IDToken)

	forge := func(private string, kid, typ string, claims map[string]any) string {
		key := keys.AccessTokenPrivate
		if private == "id" {
			key = keys.IDTokenPrivate
		}

		token, err := servertest.SignAs(key, map[string]any{"alg": "RS256", "kid": kid, "typ": typ}, claims)
		if err != nil {
			t.Fatalf("forging a token: %v", err)
		}

		return token
	}

	clientID := application.ID.String()

	for name, token := range map[string]string{
		"with the ID key under its own kid":    forge("id", keys.IDTokenKeyID(), "at+jwt", accessClaims),
		"with the ID key under the access kid": forge("id", keys.AccessTokenKeyID(), "at+jwt", accessClaims),
		"a genuine ID token":                   issued.IDToken,
		"a genuine ID token's claims re-typed": forge("access", keys.AccessTokenKeyID(), "at+jwt", idClaims),
	} {
		if _, err := accessTokens.ValidateAccessToken(token, clientID); err == nil {
			t.Errorf("an access token validator accepted an access token forged %s", name)
		}

		expectInvalidToken(t, service.GET("/oauth/userinfo", servertest.Bearer(token)))
	}

	for name, token := range map[string]string{
		"with the access key under its own kid": forge("access", keys.AccessTokenKeyID(), "JWT", idClaims),
		"with the access key under the ID kid":  forge("access", keys.IDTokenKeyID(), "JWT", idClaims),
		"a genuine access token":                issued.AccessToken,
		"access claims under the ID key":        forge("id", keys.IDTokenKeyID(), "JWT", accessClaims),
	} {
		if _, err := idTokens.ValidateIDToken(token, clientID, pending.Nonce); err == nil {
			t.Errorf("an ID token validator accepted an ID token forged %s", name)
		}
	}

	if _, err := idTokens.ValidateIDToken(issued.IDToken, clientID, pending.Nonce); err != nil {
		t.Errorf("the genuine ID token was refused: %v", err)
	}

	if _, err := idTokens.ValidateIDToken(issued.IDToken, clientID, "another nonce"); err == nil {
		t.Error("an ID token was accepted for another authorization's nonce")
	}

	if _, err := accessTokens.ValidateAccessToken(issued.AccessToken, clientID); err != nil {
		t.Errorf("the genuine access token was refused: %v", err)
	}

	if _, err := accessTokens.ValidateAccessToken(issued.AccessToken, "00000000-0000-0000-0000-00000000dead"); err == nil {
		t.Error("an access token was accepted for another client")
	}
}

// Validators built from discovery alone accept a subject only as the canonical
// lower-case spelling of a non-nil UUID, and refuse a payload that names a
// member twice or carries anything after its object, even under each class's
// genuine key. A canonical subject re-signed with that key is the positive
// control.
func TestValidatorsAcceptOnlyCanonicalUserSubjects(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)
	keys := servertest.SigningKeyFiles(t)
	idTokens, accessTokens := validators(t, service)

	pending, issued := client.Tokens(ipv4Template, "openid", service.Providers.Someone(oauth.Discord, "p"))
	clientID := application.ID.String()
	subject, _ := servertest.DecodeClaims(issued.AccessToken)["sub"].(string)
	another := uuid.NewString()

	for class, profile := range map[string]struct {
		key      *rsa.PrivateKey
		kid, typ string
		token    string
		validate func(string) error
	}{
		"ID token": {keys.IDTokenPrivate, keys.IDTokenKeyID(), "JWT", issued.IDToken, func(token string) error {
			_, err := idTokens.ValidateIDToken(token, clientID, pending.Nonce)

			return err
		}},
		"access token": {keys.AccessTokenPrivate, keys.AccessTokenKeyID(), "at+jwt", issued.AccessToken, func(token string) error {
			_, err := accessTokens.ValidateAccessToken(token, clientID)

			return err
		}},
	} {
		header := map[string]any{"alg": "RS256", "kid": profile.kid, "typ": profile.typ}

		payload := func(value any) []byte {
			claims := servertest.DecodeClaims(profile.token)
			if value == nil {
				delete(claims, "sub")
			} else {
				claims["sub"] = value
			}

			encoded, err := json.Marshal(claims)
			if err != nil {
				t.Fatalf("encoding claims: %v", err)
			}

			return encoded
		}

		sign := func(payload []byte) string {
			token, err := servertest.SignPayload(profile.key, header, payload)
			if err != nil {
				t.Fatalf("signing a test token: %v", err)
			}

			return token
		}

		if err := profile.validate(sign(payload(another))); err != nil {
			t.Fatalf("%s: a canonical subject re-signed with the genuine key was refused, so the cases below prove nothing: %v", class, err)
		}

		canonical := payload(subject)

		for name, refused := range map[string][]byte{
			"the nil UUID":              payload(uuid.Nil.String()),
			"an upper-case UUID":        payload(strings.ToUpper(subject)),
			"a braced UUID":             payload("{" + subject + "}"),
			"a compact UUID":            payload(strings.ReplaceAll(subject, "-", "")),
			"a URN":                     payload("urn:uuid:" + subject),
			"a malformed UUID":          payload(subject[:35] + "g"),
			"an opaque value":           payload(strings.Repeat("s", 43)),
			"a number":                  payload(7),
			"an array":                  payload([]string{subject}),
			"no subject":                payload(nil),
			"a conflicting duplicate":   bytes.Replace(canonical, []byte(`"sub":`), []byte(`"sub":"`+another+`","sub":`), 1),
			"a duplicate of any member": bytes.Replace(canonical, []byte(`"iss":`), []byte(`"iss":"`+servertest.OpenIDIssuer+`","iss":`), 1),
			"trailing JSON":             append(bytes.Clone(canonical), `{}`...),
		} {
			if err := profile.validate(sign(refused)); err == nil {
				t.Errorf("%s with %s was accepted", class, name)
			}
		}
	}
}
