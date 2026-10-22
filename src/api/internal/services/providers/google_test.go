package providers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

const (
	testClientID = "placeholder-google-client-id"
	testNonce    = "placeholder-login-nonce"

	// marker is part of every synthetic token, claim, code, body and query
	// value below, so one search shows whether any of them reached an error.
	marker = "synthetic-marker"
)

// expectRefused requires an error to be ErrProviderRefused with exactly the
// given package-owned reason. Only the error is printed.
func expectRefused(t *testing.T, err error, reason string) {
	t.Helper()

	if err == nil {
		t.Fatal("the identity token was accepted")
	}

	if !errors.Is(err, ErrProviderRefused) {
		t.Errorf("error = %v, want it to wrap ErrProviderRefused", err)
	}

	if want := "identity provider authentication failed: " + reason; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}

	expectNoMarker(t, err)
}

func expectNoMarker(t *testing.T, err error) {
	t.Helper()

	if err != nil && strings.Contains(err.Error(), marker) {
		t.Errorf("the error repeats a token, claim, code, body or query value: %q", err.Error())
	}
}

func segment(text string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(text))
}

func TestIdentityTokenHeaderIsCheckedBeforeSignature(t *testing.T) {
	t.Parallel()

	claims := segment(`{"sub":"` + marker + `"}`)
	signature := segment(marker)

	withHeader := func(header string) string {
		return header + "." + claims + "." + signature
	}

	const unsupportedAlgorithm = "unsupported identity token signing algorithm"

	tests := map[string]struct {
		token  string
		reason string
	}{
		"one segment":               {marker, "malformed identity token"},
		"four segments":             {withHeader(segment(`{"alg":"RS256"}`)) + "." + marker, "malformed identity token"},
		"a header not in base64url": {withHeader("!" + marker), "invalid identity token header"},
		"a header that is not JSON": {withHeader(segment(marker)), "invalid identity token header"},
		"a symmetric algorithm":     {withHeader(segment(`{"alg":"HS256"}`)), unsupportedAlgorithm},
		"no algorithm":              {withHeader(segment(`{"alg":"none"}`)), unsupportedAlgorithm},
		"a critical header": {
			withHeader(segment(`{"alg":"RS256","crit":["` + marker + `"]}`)),
			"unsupported critical identity token header",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			expectRefused(t, requireIdentityTokenAlgorithm(test.token), test.reason)
		})
	}

	if err := requireIdentityTokenAlgorithm(withHeader(segment(`{"alg":"RS256","kid":"placeholder"}`))); err != nil {
		t.Errorf("an RS256 header was refused: %v", err)
	}
}

func TestAudienceClaimIsStringOrStringList(t *testing.T) {
	t.Parallel()

	for _, accepted := range []string{`"` + testClientID + `"`, `["` + testClientID + `","placeholder-other"]`} {
		var parsed audience
		if err := json.Unmarshal([]byte(accepted), &parsed); err != nil {
			t.Errorf("an aud claim of %s was refused: %v", accepted, err)
		}
	}

	for _, refusedClaim := range []string{`42`, `{"` + marker + `":true}`, `["` + marker + `",7]`, `true`} {
		var parsed audience

		err := json.Unmarshal([]byte(refusedClaim), &parsed)
		if !errors.Is(err, errInvalidAudienceClaimType) {
			t.Errorf("an aud claim of the wrong type gave %v, want errInvalidAudienceClaimType", err)
		}

		expectNoMarker(t, err)
	}
}

func TestAudienceAndAuthorizedPartyMustNameThisClient(t *testing.T) {
	t.Parallel()

	google := &Google{clientID: testClientID}
	other := marker + "-client-id"

	tests := map[string]struct {
		claims identityClaims
		reason string
	}{
		"another audience": {
			identityClaims{Audience: audience{other}}, "identity token audience mismatch",
		},
		"no audience": {
			identityClaims{}, "identity token audience mismatch",
		},
		"several audiences without an authorized party": {
			identityClaims{Audience: audience{testClientID, other}}, "identity token missing authorized party claim",
		},
		"several audiences authorized to another party": {
			identityClaims{Audience: audience{testClientID, other}, AuthorizedTo: other},
			"identity token authorized party mismatch",
		},
		"one audience authorized to another party": {
			identityClaims{Audience: audience{testClientID}, AuthorizedTo: other},
			"identity token authorized party mismatch",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			expectRefused(t, google.verifyAudience(test.claims), test.reason)
		})
	}

	accepted := map[string]identityClaims{
		"this client alone":                    {Audience: audience{testClientID}},
		"this client authorized":               {Audience: audience{testClientID}, AuthorizedTo: testClientID},
		"several audiences authorized to this": {Audience: audience{other, testClientID}, AuthorizedTo: testClientID},
	}

	for name, claims := range accepted {
		if err := google.verifyAudience(claims); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

func TestIdentityTokenTimeClaimsAreEnforced(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	google := &Google{clientID: testClientID, now: func() time.Time { return now }}

	at := func(offset time.Duration) *int64 {
		value := now.Add(offset).Unix()

		return &value
	}

	beyond := maxIdentityClockSkew + time.Second
	within := maxIdentityClockSkew - time.Second

	tests := map[string]struct {
		claims identityClaims
		reason string
	}{
		"no exp":           {identityClaims{IssuedAt: at(0)}, "identity token missing exp or iat claim"},
		"no iat":           {identityClaims{ExpiresAt: at(time.Minute)}, "identity token missing exp or iat claim"},
		"an exp past skew": {identityClaims{IssuedAt: at(-time.Hour), ExpiresAt: at(-beyond)}, "identity token expired"},
		"an iat beyond skew": {
			identityClaims{IssuedAt: at(beyond), ExpiresAt: at(time.Hour)}, "identity token iat claim is in the future",
		},
		"an nbf beyond skew": {
			identityClaims{IssuedAt: at(0), ExpiresAt: at(time.Hour), NotBefore: at(beyond)},
			"identity token is not active",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			expectRefused(t, google.verifyValidity(test.claims), test.reason)
		})
	}

	accepted := map[string]identityClaims{
		"no nbf":                {IssuedAt: at(0), ExpiresAt: at(time.Hour)},
		"exp within skew":       {IssuedAt: at(-time.Hour), ExpiresAt: at(-within)},
		"iat and nbf in skew":   {IssuedAt: at(within), ExpiresAt: at(time.Hour), NotBefore: at(within)},
		"nbf already in effect": {IssuedAt: at(0), ExpiresAt: at(time.Hour), NotBefore: at(-time.Minute)},
	}

	for name, claims := range accepted {
		if err := google.verifyValidity(claims); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

func TestAccessTokenHashBindsAccessToken(t *testing.T) {
	t.Parallel()

	accessToken := marker + "-access-token"
	digest := sha256.Sum256([]byte(accessToken))
	sum := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])

	expectRefused(t, verifyAccessTokenSum(sum, ""), "identity token at_hash has no access token")
	expectRefused(t, verifyAccessTokenSum(marker+"-at-hash", accessToken), "identity token at_hash mismatch")
	expectRefused(t, verifyAccessTokenSum(sum, accessToken+"-other"), "identity token at_hash mismatch")

	if err := verifyAccessTokenSum(sum, accessToken); err != nil {
		t.Errorf("a matching at_hash was refused: %v", err)
	}

	if err := verifyAccessTokenSum("", accessToken); err != nil {
		t.Errorf("an absent at_hash was refused: %v", err)
	}
}

func testCallback(t *testing.T) urlpolicy.Callback {
	t.Helper()

	callback, err := urlpolicy.ParseCallbackURI("https://api.auth.example.test/api/google_callback")
	if err != nil {
		t.Fatalf("parsing the callback: %v", err)
	}

	return callback
}

func newTestGoogle(t *testing.T, endpoints GoogleEndpoints, transport http.RoundTripper) *Google {
	t.Helper()

	return NewGoogle(config.Provider{
		ClientID:     testClientID,
		ClientSecret: config.NewSecret("placeholder-client-secret"),
		Callback:     testCallback(t),
	}, endpoints, transport, nil)
}

// identifyAgainst signs in through a local Google answering as the options
// describe, and returns what Identify returned.
func identifyAgainst(t *testing.T, options providertest.Options) (string, error) {
	t.Helper()

	options.GoogleClientID = testClientID
	local := providertest.New(t, options)
	google := newTestGoogle(t, GoogleEndpoints{}, local.Transport())

	code := local.Issue(oauth.Google, providertest.Grant{
		Identity: providertest.Identity{ID: "placeholder-google-subject", Username: "placeholder-name"},
		Nonce:    testNonce,
	})

	identity, err := google.Identify(
		t.Context(), code, "placeholder-verifier", credentials.Digest(credentials.DomainIdentityNonce, testNonce),
	)
	if err != nil && strings.Contains(err.Error(), code) {
		t.Errorf("the error repeats the authorization code: %q", err.Error())
	}

	return identity.ID, err
}

func altering(change func(jwt.MapClaims)) providertest.Options {
	return providertest.Options{AlterIdentityToken: change}
}

func TestIdentifyRefusesIdentityTokenWithPackageOwnedReason(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		options providertest.Options
		reason  string
	}{
		"a symmetric signature": {
			providertest.Options{IdentityTokenAlgorithm: jwt.SigningMethodHS256},
			"unsupported identity token signing algorithm",
		},
		"a key Google does not publish": {
			providertest.Options{SignIdentityTokenWithAnotherKey: true},
			"identity token signature validation failed",
		},
		"an aud claim of the wrong type": {
			altering(func(claims jwt.MapClaims) { claims["aud"] = map[string]any{marker: true} }),
			"invalid audience claim type",
		},
		"an exp claim of the wrong type": {
			altering(func(claims jwt.MapClaims) { claims["exp"] = marker }),
			"invalid identity token claims",
		},
		"another issuer": {
			altering(func(claims jwt.MapClaims) { claims["iss"] = "https://" + marker + ".example.test" }),
			"identity token issuer mismatch",
		},
		"another audience": {
			altering(func(claims jwt.MapClaims) { claims["aud"] = marker }),
			"identity token audience mismatch",
		},
		"an expired token": {
			altering(func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Hour).Unix() }),
			"identity token expired",
		},
		"another nonce": {
			altering(func(claims jwt.MapClaims) { claims["nonce"] = marker }),
			"identity token nonce mismatch",
		},
		"another access token": {
			altering(func(claims jwt.MapClaims) { claims["at_hash"] = marker }),
			"identity token at_hash mismatch",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := identifyAgainst(t, test.options)
			expectRefused(t, err, test.reason)
		})
	}
}

func TestIdentifyReportsIncompleteIdentitySeparately(t *testing.T) {
	t.Parallel()

	_, err := identifyAgainst(t, altering(func(claims jwt.MapClaims) { claims["sub"] = "" }))

	if !errors.Is(err, ErrUnusableIdentity) || errors.Is(err, ErrProviderRefused) {
		t.Fatalf("error = %v, want ErrUnusableIdentity alone", err)
	}

	if err.Error() != "identity provider returned incomplete identity" {
		t.Errorf("error = %q", err.Error())
	}
}

// The control for the refusals above: an identity token as Google issues it
// yields the subject it was issued for.
func TestIdentifyAcceptsIdentityTokenGoogleIssued(t *testing.T) {
	t.Parallel()

	subject, err := identifyAgainst(t, providertest.Options{})
	if err != nil {
		t.Fatalf("a correct identity token was refused: %v", err)
	}

	if subject != "placeholder-google-subject" {
		t.Errorf("subject = %q", subject)
	}
}

func TestDiscoveryDocumentMustMatchCompiledEndpoints(t *testing.T) {
	t.Parallel()

	local := providertest.New(t, providertest.Options{GoogleClientID: testClientID})
	google := newTestGoogle(t, GoogleEndpoints{Issuer: "https://" + marker + ".example.test"}, local.Transport())

	_, err := google.Identify(t.Context(), marker+"-code", "placeholder-verifier", nil)
	expectRefused(t, err, "provider discovery configuration mismatch")
}

// roundTripFunc answers provider requests in the test itself.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func answer(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func TestProviderFailuresRepeatNeitherBodyNorCodeNorQuery(t *testing.T) {
	t.Parallel()

	discovery, err := json.Marshal(map[string]string{
		"issuer":                 googleIssuer,
		"authorization_endpoint": googleAuthorizeEndpoint,
		"token_endpoint":         googleTokenEndpoint,
		"jwks_uri":               googleJWKSEndpoint,
	})
	if err != nil {
		t.Fatalf("encoding the discovery document: %v", err)
	}

	refusingExchange := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == googleDiscoveryEndpoint {
			return answer(http.StatusOK, string(discovery)), nil
		}

		return answer(http.StatusBadRequest, `{"error":"`+marker+`-provider-body"}`), nil
	})

	_, err = newTestGoogle(t, GoogleEndpoints{}, refusingExchange).
		Identify(t.Context(), marker+"-code", "placeholder-verifier", nil)
	if !errors.Is(err, ErrProviderRefused) {
		t.Errorf("a refused exchange gave %v, want ErrProviderRefused", err)
	}

	expectNoMarker(t, err)

	unreachable := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("placeholder transport failure")
	})

	_, err = newTestGoogle(t, GoogleEndpoints{Discovery: googleDiscoveryEndpoint + "?" + marker + "=query"}, unreachable).
		Identify(t.Context(), marker+"-code", "placeholder-verifier", nil)
	if !errors.Is(err, ErrProviderRefused) {
		t.Errorf("an unreachable provider gave %v, want ErrProviderRefused", err)
	}

	expectNoMarker(t, err)
}
