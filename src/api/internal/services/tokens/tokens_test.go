package tokens_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/keyring"
	"github.com/abandontech/abandonauth/src/api/internal/services/tokens"
)

const (
	rootSecret = "placeholder-signing-secret-placeholder-signing-secret-placeholder"
	issuer     = "https://api.auth.example.test"
)

var (
	internalApplication = uuid.MustParse("6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0")
	otherApplication    = uuid.MustParse("1c9d6b3e-5f2a-4d7c-9b8e-2a4f6c8d0e12")
	person              = uuid.MustParse("ac7e2f10-9d4b-4a63-8f21-5b6c7d8e9f01")
	epoch               = uuid.MustParse("3f1c8a2b-6d5e-4f70-9a1b-2c3d4e5f6071")
)

// clock lets a test place a token before, inside or after its own validity
// without waiting.
type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func newSigner(t *testing.T, at *clock) *tokens.Signer {
	t.Helper()

	keys, err := keyring.New(rootSecret)
	if err != nil {
		t.Fatalf("deriving keys: %v", err)
	}

	signer, err := tokens.NewSigner(tokens.Options{
		Issuer:                issuer,
		InternalApplicationID: internalApplication,
		Keys:                  keys,
		Now:                   at.now,
	})
	if err != nil {
		t.Fatalf("building the signer: %v", err)
	}

	return signer
}

func newClock() *clock {
	return &clock{at: time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)}
}

func issueUserAccess(t *testing.T, signer *tokens.Signer, audience uuid.UUID) string {
	t.Helper()

	raw, _, err := signer.IssueUserAccess(person, audience, epoch)
	if err != nil {
		t.Fatalf("issuing a user access token: %v", err)
	}

	return raw
}

func issueDeveloperAccess(t *testing.T, signer *tokens.Signer, application uuid.UUID, version int64) string {
	t.Helper()

	raw, _, err := signer.IssueDeveloperApplicationAccess(application, epoch, version)
	if err != nil {
		t.Fatalf("issuing a developer application access token: %v", err)
	}

	return raw
}

// decodeParts returns the header and the claims of a token without verifying
// it, so a test can assert what is actually on the wire.
func decodeParts(t *testing.T, raw string) (map[string]any, map[string]any) {
	t.Helper()

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("a token has %d parts, want 3", len(parts))
	}

	return decodeSegment(t, parts[0]), decodeSegment(t, parts[1])
}

func decodeSegment(t *testing.T, segment string) map[string]any {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decoding a token segment: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("a token segment is not JSON: %v", err)
	}

	return decoded
}

// resign rebuilds a token from altered claims, so a test can present a token
// that is correctly signed but says something it should not.
func resign(t *testing.T, key []byte, keyID string, header, claims map[string]any) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims(claims))
	token.Header["kid"] = keyID

	for name, value := range header {
		if name == "alg" || name == "typ" {
			token.Header[name] = value
		}
	}

	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("re-signing a token: %v", err)
	}

	return raw
}

func userKey(t *testing.T) []byte {
	t.Helper()

	keys, err := keyring.New(rootSecret)
	if err != nil {
		t.Fatalf("deriving keys: %v", err)
	}

	return keys.UserAccessSigning()
}

func TestAnIssuedUserTokenCarriesEveryClaimTheServiceCommitsTo(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)

	raw := issueUserAccess(t, signer, otherApplication)
	header, claims := decodeParts(t, raw)

	if header["alg"] != "HS512" {
		t.Errorf("alg = %v, want HS512", header["alg"])
	}

	if header["kid"] != tokens.UserAccessKeyID {
		t.Errorf("kid = %v, want %s", header["kid"], tokens.UserAccessKeyID)
	}

	want := map[string]any{
		"user_id":    person.String(),
		"sub":        person.String(),
		"iss":        issuer,
		"aud":        otherApplication.String(),
		"scope":      "identify",
		"lifespan":   "long",
		"token_type": string(tokens.UserAccess),
		"auth_epoch": epoch.String(),
		"iat":        float64(at.at.Unix()),
		"nbf":        float64(at.at.Unix()),
		"exp":        float64(at.at.Add(tokens.AccessLifetime).Unix()),
	}

	for name, value := range want {
		if claims[name] != value {
			t.Errorf("claim %s = %v, want %v", name, claims[name], value)
		}
	}

	if _, err := uuid.Parse(claims["jti"].(string)); err != nil {
		t.Errorf("jti is not a UUID: %v", err)
	}

	if _, carried := claims["credential_version"]; carried {
		t.Error("a user token carries a credential version, which belongs to an application")
	}
}

// The site itself needs to manage applications; an application acting for a
// person only needs to identify them.
func TestScopeDependsOnWhoTheTokenWasIssuedFor(t *testing.T) {
	t.Parallel()

	signer := newSigner(t, newClock())

	_, internal := decodeParts(t, issueUserAccess(t, signer, internalApplication))
	if internal["scope"] != "abandonauth identify" {
		t.Errorf("internal scope = %v, want \"abandonauth identify\"", internal["scope"])
	}

	_, external := decodeParts(t, issueUserAccess(t, signer, otherApplication))
	if external["scope"] != "identify" {
		t.Errorf("external scope = %v, want \"identify\"", external["scope"])
	}
}

func TestAnIssuedApplicationTokenNamesTheApplicationAndItsCredentialVersion(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)

	raw := issueDeveloperAccess(t, signer, otherApplication, 7)
	header, claims := decodeParts(t, raw)

	if header["kid"] != tokens.DeveloperAccessKeyID {
		t.Errorf("kid = %v, want %s", header["kid"], tokens.DeveloperAccessKeyID)
	}

	want := map[string]any{
		"user_id":            otherApplication.String(),
		"sub":                otherApplication.String(),
		"aud":                internalApplication.String(),
		"scope":              "abandonauth identify",
		"token_type":         string(tokens.DeveloperApplicationAccess),
		"credential_version": float64(7),
	}

	for name, value := range want {
		if claims[name] != value {
			t.Errorf("claim %s = %v, want %v", name, claims[name], value)
		}
	}
}

func TestVerifyingReturnsWhatTheTokenSays(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)

	verified, err := signer.Verify(issueUserAccess(t, signer, otherApplication))
	if err != nil {
		t.Fatalf("verifying a token this service just issued: %v", err)
	}

	if verified.Class != tokens.UserAccess {
		t.Errorf("class = %q, want %q", verified.Class, tokens.UserAccess)
	}

	if verified.Subject != person {
		t.Errorf("subject = %s, want %s", verified.Subject, person)
	}

	if verified.Audience != otherApplication {
		t.Errorf("audience = %s, want %s", verified.Audience, otherApplication)
	}

	if verified.AuthEpoch != epoch {
		t.Errorf("auth epoch = %s, want %s", verified.AuthEpoch, epoch)
	}

	if !verified.HasScope("identify") {
		t.Error("the token does not carry the identify scope")
	}

	if verified.HasScope("abandonauth") {
		t.Error("the token carries a scope it was not issued with")
	}
}

// A scope is a whitespace-delimited list of exact words. Matching a substring
// would let "identify" satisfy a requirement for "identi" or the reverse.
func TestScopeMembershipIsExact(t *testing.T) {
	t.Parallel()

	signer := newSigner(t, newClock())

	verified, err := signer.Verify(issueUserAccess(t, signer, internalApplication))
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}

	for _, scope := range []string{"abandonauth", "identify"} {
		if !verified.HasScope(scope) {
			t.Errorf("scope %q is missing", scope)
		}
	}

	for _, scope := range []string{"identi", "dentify", "abandonauth identify", "", " ", "IDENTIFY"} {
		if verified.HasScope(scope) {
			t.Errorf("scope %q was accepted", scope)
		}
	}
}

func TestTokensExpireAfterTheFixedAccessLifetime(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)
	raw := issueUserAccess(t, signer, otherApplication)

	at.at = at.at.Add(tokens.AccessLifetime + tokens.MaxClockSkew + time.Second)

	if _, err := signer.Verify(raw); err == nil {
		t.Fatal("an expired token was accepted")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expiry error = %v, want it to name expiry", err)
	}
}

// Hosts do not agree on the time to the second. A small tolerance keeps a token
// usable across them without letting an expired one live materially longer.
func TestVerificationToleratesOnlyASmallClockDifference(t *testing.T) {
	t.Parallel()

	at := newClock()
	issued := at.at
	signer := newSigner(t, at)
	raw := issueUserAccess(t, signer, otherApplication)

	at.at = issued.Add(tokens.AccessLifetime + tokens.MaxClockSkew - time.Second)

	if _, err := signer.Verify(raw); err != nil {
		t.Errorf("a token one second inside the tolerated skew was refused: %v", err)
	}

	at.at = issued.Add(-tokens.MaxClockSkew + time.Second)

	if _, err := signer.Verify(raw); err != nil {
		t.Errorf("a token from one second inside the tolerated skew was refused: %v", err)
	}

	at.at = issued.Add(-tokens.MaxClockSkew - time.Second)

	if _, err := signer.Verify(raw); err == nil {
		t.Error("a token from beyond the tolerated skew in the future was accepted")
	}
}

func TestATokenIsRefusedWhenAnythingAboutItIsWrong(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)
	key := userKey(t)

	original := issueUserAccess(t, signer, otherApplication)
	header, base := decodeParts(t, original)

	// altered returns the issued claims with one of them changed.
	altered := func(changes map[string]any) map[string]any {
		claims := make(map[string]any, len(base))
		for name, value := range base {
			claims[name] = value
		}

		for name, value := range changes {
			if value == nil {
				delete(claims, name)

				continue
			}

			claims[name] = value
		}

		return claims
	}

	tests := map[string]string{
		"empty":                "",
		"not a token":          "placeholder",
		"two parts":            strings.Join(strings.Split(original, ".")[:2], "."),
		"truncated":            original[:len(original)-4],
		"altered signature":    withAlteredSignature(original),
		"signed with the root": resign(t, []byte(rootSecret), tokens.UserAccessKeyID, header, base),
		"signed with the developer key": resign(
			t, developerKey(t), tokens.UserAccessKeyID, header, base,
		),
		"unknown key id":  resign(t, key, "abandonauth-unknown-v1", header, base),
		"no key id":       resign(t, key, "", header, base),
		"wrong issuer":    resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"iss": "https://elsewhere.example.test"})),
		"missing issuer":  resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"iss": nil})),
		"missing subject": resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"sub": nil})),
		"subject and user_id disagree": resign(
			t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"sub": person.String() + "x"}),
		),
		"subject is not a uuid": resign(
			t, key, tokens.UserAccessKeyID, header,
			altered(map[string]any{"sub": "placeholder", "user_id": "placeholder"}),
		),
		"missing audience":       resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"aud": nil})),
		"audience is not a uuid": resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"aud": "placeholder"})),
		"audience is a list": resign(
			t, key, tokens.UserAccessKeyID, header,
			altered(map[string]any{"aud": []any{otherApplication.String()}}),
		),
		"missing token type": resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"token_type": nil})),
		"token type does not match the key": resign(
			t, key, tokens.UserAccessKeyID, header,
			altered(map[string]any{"token_type": string(tokens.DeveloperApplicationAccess)}),
		),
		"unknown token type": resign(
			t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"token_type": "exchange"}),
		),
		"missing lifespan": resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"lifespan": nil})),
		"wrong lifespan":   resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"lifespan": "short"})),
		"missing jti":      resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"jti": nil})),
		"jti is not a uuid": resign(
			t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"jti": "placeholder"}),
		),
		"missing scope":      resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"scope": nil})),
		"missing auth epoch": resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"auth_epoch": nil})),
		"auth epoch is not a uuid": resign(
			t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"auth_epoch": "placeholder"}),
		),
		"missing expiry": resign(t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"exp": nil})),
		"missing issued at": resign(
			t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"iat": nil}),
		),
		"missing not before": resign(
			t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"nbf": nil}),
		),
		"not yet valid": resign(
			t, key, tokens.UserAccessKeyID, header,
			altered(map[string]any{"nbf": float64(at.at.Add(time.Hour).Unix())}),
		),
		"lives longer than the access lifetime": resign(
			t, key, tokens.UserAccessKeyID, header,
			altered(map[string]any{"exp": float64(at.at.Add(tokens.AccessLifetime + time.Second).Unix())}),
		),
		"a user token carrying a credential version": resign(
			t, key, tokens.UserAccessKeyID, header, altered(map[string]any{"credential_version": float64(1)}),
		),
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := signer.Verify(raw); err == nil {
				t.Error("the token was accepted")
			}
		})
	}
}

// An application token names an application, so it must not be usable where a
// person is expected, and the reverse.
func TestTheTwoTokenClassesCannotStandInForEachOther(t *testing.T) {
	t.Parallel()

	signer := newSigner(t, newClock())

	userToken, err := signer.Verify(issueUserAccess(t, signer, internalApplication))
	if err != nil {
		t.Fatalf("verifying a user token: %v", err)
	}

	applicationToken, err := signer.Verify(issueDeveloperAccess(t, signer, otherApplication, 1))
	if err != nil {
		t.Fatalf("verifying an application token: %v", err)
	}

	if userToken.Class == applicationToken.Class {
		t.Fatal("both classes verify as the same kind of token")
	}

	if applicationToken.CredentialVersion != 1 {
		t.Errorf("credential version = %d, want 1", applicationToken.CredentialVersion)
	}

	if userToken.CredentialVersion != 0 {
		t.Errorf("a user token reported credential version %d, want 0", userToken.CredentialVersion)
	}
}

// A token may not choose how it is verified. An unsigned or differently signed
// token must be refused before any claim is read.
func TestOnlyTheOneSigningAlgorithmIsAccepted(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)
	_, claims := decodeParts(t, issueUserAccess(t, signer, otherApplication))

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims))
	unsigned.Header["kid"] = tokens.UserAccessKeyID

	raw, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("building an unsigned token: %v", err)
	}

	if _, err := signer.Verify(raw); err == nil {
		t.Error("an unsigned token was accepted")
	}

	weaker := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	weaker.Header["kid"] = tokens.UserAccessKeyID

	raw, err = weaker.SignedString(userKey(t))
	if err != nil {
		t.Fatalf("building a differently signed token: %v", err)
	}

	if _, err := signer.Verify(raw); err == nil {
		t.Error("a token signed with another algorithm was accepted")
	}
}

// Rotating the root secret is how a deployment withdraws every token at once.
func TestTokensDoNotSurviveARootSecretChange(t *testing.T) {
	t.Parallel()

	at := newClock()
	raw := issueUserAccess(t, newSigner(t, at), otherApplication)

	rotated, err := keyring.New(rootSecret + "-rotated")
	if err != nil {
		t.Fatalf("deriving keys: %v", err)
	}

	after, err := tokens.NewSigner(tokens.Options{
		Issuer:                issuer,
		InternalApplicationID: internalApplication,
		Keys:                  rotated,
		Now:                   at.now,
	})
	if err != nil {
		t.Fatalf("building the signer: %v", err)
	}

	if _, err := after.Verify(raw); err == nil {
		t.Error("a token issued under the previous root secret was accepted")
	}
}

func TestASignerNeedsEverythingItSignsWith(t *testing.T) {
	t.Parallel()

	keys, err := keyring.New(rootSecret)
	if err != nil {
		t.Fatalf("deriving keys: %v", err)
	}

	complete := tokens.Options{
		Issuer:                issuer,
		InternalApplicationID: internalApplication,
		Keys:                  keys,
	}

	tests := map[string]func(*tokens.Options){
		"no issuer":               func(o *tokens.Options) { o.Issuer = "" },
		"no internal application": func(o *tokens.Options) { o.InternalApplicationID = uuid.Nil },
		"no keys":                 func(o *tokens.Options) { o.Keys = keyring.Keyring{} },
	}

	for name, breakOne := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			options := complete
			breakOne(&options)

			if _, err := tokens.NewSigner(options); err == nil {
				t.Error("the signer was built")
			}
		})
	}
}

func TestASignerRefusesToIssueATokenForNobody(t *testing.T) {
	t.Parallel()

	signer := newSigner(t, newClock())

	if _, _, err := signer.IssueUserAccess(uuid.Nil, otherApplication, epoch); err == nil {
		t.Error("a token was issued without a subject")
	}

	if _, _, err := signer.IssueUserAccess(person, uuid.Nil, epoch); err == nil {
		t.Error("a token was issued without an audience")
	}

	if _, _, err := signer.IssueUserAccess(person, otherApplication, uuid.Nil); err == nil {
		t.Error("a token was issued without an authority epoch")
	}

	if _, _, err := signer.IssueDeveloperApplicationAccess(otherApplication, epoch, 0); err == nil {
		t.Error("an application token was issued without a credential version")
	}
}

func developerKey(t *testing.T) []byte {
	t.Helper()

	keys, err := keyring.New(rootSecret)
	if err != nil {
		t.Fatalf("deriving keys: %v", err)
	}

	return keys.DeveloperAccessSigning()
}

// withAlteredSignature changes a bit the signature is actually made of. The
// last character of a 64-byte signature carries bits base64 does not use, so
// changing that one can decode to the same signature.
func withAlteredSignature(token string) string {
	parts := strings.Split(token, ".")

	replacement := "A"
	if strings.HasPrefix(parts[2], "A") {
		replacement = "B"
	}

	parts[2] = replacement + parts[2][1:]

	return strings.Join(parts, ".")
}
