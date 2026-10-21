package tokens_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

// Package-owned refusal reasons shared by several cases below.
const (
	malformedOrBadSignature = "malformed token or invalid signature"
	scopeMismatch           = "scope claim mismatch"
	typeMismatch            = "token type does not match signing key"
	lifetimeMismatch        = "exp does not equal iat plus access lifetime"
	timeClaimsConflict      = "nbf and iat claims conflict"
	missingTimeClaim        = "missing exp, iat, or nbf claim"
)

var (
	internalApplication = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	otherApplication    = uuid.MustParse("00000000-0000-0000-0000-000000000002")
	epoch               = uuid.MustParse("00000000-0000-0000-0000-000000000004")
	// Ends in a letter so that spelling it in upper case changes it.
	person = uuid.MustParse("00000000-0000-0000-0000-00000000000a")
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
// that is correctly signed but carries claims this service does not issue.
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

// resignWithoutKeyID rebuilds a token whose header has no kid member at all.
func resignWithoutKeyID(t *testing.T, key []byte, claims map[string]any) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims(claims))
	delete(token.Header, "kid")

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

// expectInvalid requires a token to be refused as invalid for exactly the given
// package-owned reason. Only the error is printed, never the token.
func expectInvalid(t *testing.T, signer *tokens.Signer, raw, reason string) {
	t.Helper()

	_, err := signer.Verify(raw)
	if err == nil {
		t.Fatal("the token was accepted")
	}

	if !errors.Is(err, tokens.ErrInvalid) || errors.Is(err, tokens.ErrExpired) {
		t.Errorf("error = %v, want it to be ErrInvalid alone", err)
	}

	if want := "invalid token: " + reason; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestIssuedUserTokenCarriesEveryClaimServiceCommitsTo(t *testing.T) {
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
		t.Error("a user token carries a credential version claim, which belongs to a developer application token")
	}
}

// A user token for the site authorizes application management; a user token
// for any other audience authorizes identification only.
func TestScopeDependsOnTokenAudience(t *testing.T) {
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

func TestIssuedApplicationTokenNamesApplicationAndItsCredentialVersion(t *testing.T) {
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

func TestVerifyingReturnsTokenClaims(t *testing.T) {
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

func TestTokensExpireAfterFixedAccessLifetime(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)
	raw := issueUserAccess(t, signer, otherApplication)

	at.at = at.at.Add(tokens.AccessLifetime + tokens.MaxClockSkew + time.Second)

	_, err := signer.Verify(raw)
	if err == nil {
		t.Fatal("an expired token was accepted")
	}

	if !errors.Is(err, tokens.ErrExpired) || errors.Is(err, tokens.ErrInvalid) {
		t.Errorf("error = %v, want it to be ErrExpired alone", err)
	}

	if err.Error() != "expired token" {
		t.Errorf("error = %q, want %q", err.Error(), "expired token")
	}
}

// Hosts do not agree on the time to the second. A small tolerance keeps a token
// usable across them without letting an expired one live materially longer.
func TestVerificationToleratesOnlySmallClockDifference(t *testing.T) {
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

	expectInvalid(t, signer, raw, "iat claim is in the future")
}

// alteredClaims returns a copy of issued claims with some changed. A nil value
// removes the claim.
func alteredClaims(base map[string]any, changes map[string]any) map[string]any {
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

// The positive controls for the refusals below: a token of either class, to
// either audience, that this service issued verifies with the claims it was
// issued with.
func TestEveryShapeThisServiceIssuesVerifies(t *testing.T) {
	t.Parallel()

	signer := newSigner(t, newClock())

	issued := map[string]struct {
		raw    string
		class  tokens.Class
		scopes []string
	}{
		"a user token for the site": {
			raw:    issueUserAccess(t, signer, internalApplication),
			class:  tokens.UserAccess,
			scopes: []string{"abandonauth", "identify"},
		},
		"a user token for another application": {
			raw:    issueUserAccess(t, signer, otherApplication),
			class:  tokens.UserAccess,
			scopes: []string{"identify"},
		},
		"a developer application token for the site": {
			raw:    issueDeveloperAccess(t, signer, otherApplication, 3),
			class:  tokens.DeveloperApplicationAccess,
			scopes: []string{"abandonauth", "identify"},
		},
	}

	for name, token := range issued {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verified, err := signer.Verify(token.raw)
			if err != nil {
				t.Fatalf("a token this service issued was refused: %v", err)
			}

			if verified.Class != token.class {
				t.Errorf("class = %q, want %q", verified.Class, token.class)
			}

			if strings.Join(verified.Scopes, " ") != strings.Join(token.scopes, " ") {
				t.Errorf("scopes = %v, want %v", verified.Scopes, token.scopes)
			}
		})
	}
}

// refusal is a token a test presents and the exact reason it must be refused
// for.
type refusal struct {
	raw    string
	reason string
}

func TestTokenIsRefusedWhenAnythingAboutItIsWrong(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)
	key := userKey(t)

	genuine := issueUserAccess(t, signer, otherApplication)
	header, base := decodeParts(t, genuine)

	altered := func(changes map[string]any) string {
		return resign(t, key, tokens.UserAccessKeyID, header, alteredClaims(base, changes))
	}

	_, toSite := decodeParts(t, issueUserAccess(t, signer, internalApplication))

	alteredToSite := func(changes map[string]any) string {
		return resign(t, key, tokens.UserAccessKeyID, header, alteredClaims(toSite, changes))
	}

	tests := map[string]refusal{
		"empty":                {"", "empty token"},
		"not a token":          {"placeholder", malformedOrBadSignature},
		"two parts":            {strings.Join(strings.Split(genuine, ".")[:2], "."), malformedOrBadSignature},
		"truncated":            {genuine[:len(genuine)-4], malformedOrBadSignature},
		"altered signature":    {withAlteredSignature(genuine), malformedOrBadSignature},
		"signed with the root": {resign(t, []byte(rootSecret), tokens.UserAccessKeyID, header, base), malformedOrBadSignature},
		"signed with the developer key": {
			resign(t, developerKey(t), tokens.UserAccessKeyID, header, base), malformedOrBadSignature,
		},
		"unknown key id": {resign(t, key, "abandonauth-unknown-v1", header, base), "unknown key ID"},
		"empty key id":   {resign(t, key, "", header, base), "unknown key ID"},
		"no key id":      {resignWithoutKeyID(t, key, base), "missing key ID"},
		"wrong issuer":   {altered(map[string]any{"iss": "https://elsewhere.example.test"}), "issuer claim mismatch"},
		"missing issuer": {altered(map[string]any{"iss": nil}), "issuer claim mismatch"},
		"missing subject": {
			altered(map[string]any{"sub": nil}), "subject and user ID conflict",
		},
		"subject and user_id conflict": {
			altered(map[string]any{"sub": person.String() + "x"}), "subject and user ID conflict",
		},
		"subject is not a uuid": {
			altered(map[string]any{"sub": "placeholder", "user_id": "placeholder"}),
			"invalid subject claim: invalid UUID",
		},
		"missing audience":       {altered(map[string]any{"aud": nil}), "invalid audience claim: invalid UUID"},
		"audience is not a uuid": {altered(map[string]any{"aud": "placeholder"}), "invalid audience claim: invalid UUID"},
		"audience is a list": {
			altered(map[string]any{"aud": []any{otherApplication.String()}}), malformedOrBadSignature,
		},
		"missing token type": {altered(map[string]any{"token_type": nil}), typeMismatch},
		"token type does not match the key": {
			altered(map[string]any{"token_type": string(tokens.DeveloperApplicationAccess)}), typeMismatch,
		},
		"unknown token type": {altered(map[string]any{"token_type": "exchange"}), typeMismatch},
		"missing lifespan":   {altered(map[string]any{"lifespan": nil}), "invalid lifespan claim"},
		"wrong lifespan":     {altered(map[string]any{"lifespan": "short"}), "invalid lifespan claim"},
		"missing jti":        {altered(map[string]any{"jti": nil}), "invalid token ID claim: invalid UUID"},
		"jti is not a uuid":  {altered(map[string]any{"jti": "placeholder"}), "invalid token ID claim: invalid UUID"},
		"missing scope":      {altered(map[string]any{"scope": nil}), scopeMismatch},
		"missing auth epoch": {altered(map[string]any{"auth_epoch": nil}), "invalid auth epoch claim: invalid UUID"},
		"auth epoch is not a uuid": {
			altered(map[string]any{"auth_epoch": "placeholder"}), "invalid auth epoch claim: invalid UUID",
		},
		"missing expiry":     {altered(map[string]any{"exp": nil}), missingTimeClaim},
		"missing issued at":  {altered(map[string]any{"iat": nil}), missingTimeClaim},
		"missing not before": {altered(map[string]any{"nbf": nil}), missingTimeClaim},
		"not yet valid": {
			altered(map[string]any{"nbf": float64(at.at.Add(time.Hour).Unix())}), timeClaimsConflict,
		},
		"lives longer than the access lifetime": {
			altered(map[string]any{"exp": float64(at.at.Add(tokens.AccessLifetime + time.Second).Unix())}),
			lifetimeMismatch,
		},
		"a user token carrying a credential version": {
			altered(map[string]any{"credential_version": float64(1)}), "unexpected credential version claim",
		},
		"lives shorter than the access lifetime": {
			altered(map[string]any{"exp": float64(at.at.Add(tokens.AccessLifetime - time.Second).Unix())}),
			lifetimeMismatch,
		},
		"an iat that exp does not match": {
			altered(map[string]any{
				"iat": float64(at.at.Add(-time.Minute).Unix()),
				"nbf": float64(at.at.Add(-time.Minute).Unix()),
			}),
			lifetimeMismatch,
		},
		"an nbf later than iat": {
			altered(map[string]any{"nbf": float64(at.at.Add(time.Second).Unix())}), timeClaimsConflict,
		},
		"an nbf earlier than iat": {
			altered(map[string]any{"nbf": float64(at.at.Add(-time.Second).Unix())}), timeClaimsConflict,
		},
		"a scope this service does not issue": {altered(map[string]any{"scope": "identify admin"}), scopeMismatch},
		"an unknown scope alone":              {altered(map[string]any{"scope": "admin"}), scopeMismatch},
		"the site's scope on a token to another application": {
			altered(map[string]any{"scope": "abandonauth identify"}), scopeMismatch,
		},
		"a scope repeated":                  {altered(map[string]any{"scope": "identify identify"}), scopeMismatch},
		"a scope with leading whitespace":   {altered(map[string]any{"scope": " identify"}), scopeMismatch},
		"a scope with trailing whitespace":  {altered(map[string]any{"scope": "identify "}), scopeMismatch},
		"a scope in another case":           {altered(map[string]any{"scope": "Identify"}), scopeMismatch},
		"an empty scope":                    {altered(map[string]any{"scope": ""}), scopeMismatch},
		"the site's scopes reordered":       {alteredToSite(map[string]any{"scope": "identify abandonauth"}), scopeMismatch},
		"the site's scopes with two spaces": {alteredToSite(map[string]any{"scope": "abandonauth  identify"}), scopeMismatch},
		"only one of the site's scopes":     {alteredToSite(map[string]any{"scope": "identify"}), scopeMismatch},
		"a nil subject": {
			altered(map[string]any{"sub": uuid.Nil.String(), "user_id": uuid.Nil.String()}),
			"invalid subject claim: nil UUID",
		},
		"a nil audience": {
			altered(map[string]any{"aud": uuid.Nil.String()}), "invalid audience claim: nil UUID",
		},
		"a nil auth epoch": {
			altered(map[string]any{"auth_epoch": uuid.Nil.String()}), "invalid auth epoch claim: nil UUID",
		},
		"a nil token ID": {
			altered(map[string]any{"jti": uuid.Nil.String()}), "invalid token ID claim: nil UUID",
		},
		"a subject in upper case": {
			altered(map[string]any{
				"sub":     strings.ToUpper(person.String()),
				"user_id": strings.ToUpper(person.String()),
			}),
			"invalid subject claim: non-canonical UUID",
		},
		"an audience with a urn prefix": {
			altered(map[string]any{"aud": "urn:uuid:" + otherApplication.String()}),
			"invalid audience claim: non-canonical UUID",
		},
		"an audience in braces": {
			altered(map[string]any{"aud": "{" + otherApplication.String() + "}"}),
			"invalid audience claim: non-canonical UUID",
		},
		"an auth epoch without hyphens": {
			altered(map[string]any{"auth_epoch": strings.ReplaceAll(epoch.String(), "-", "")}),
			"invalid auth epoch claim: non-canonical UUID",
		},
		"a token ID in upper case": {
			altered(map[string]any{"jti": strings.ToUpper(base["jti"].(string))}),
			"invalid token ID claim: non-canonical UUID",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			expectInvalid(t, signer, test.raw, test.reason)
		})
	}
}

// A developer application token has one shape too: signed with the developer
// application key, with the site as its audience, both scopes and a positive
// credential version.
func TestApplicationTokenIsRefusedWhenAnythingAboutItIsWrong(t *testing.T) {
	t.Parallel()

	at := newClock()
	signer := newSigner(t, at)
	key := developerKey(t)

	genuine := issueDeveloperAccess(t, signer, otherApplication, 7)
	header, base := decodeParts(t, genuine)

	altered := func(changes map[string]any) string {
		return resign(t, key, tokens.DeveloperAccessKeyID, header, alteredClaims(base, changes))
	}

	const (
		notInternal    = "audience does not identify internal application"
		invalidVersion = "missing or invalid credential version claim"
	)

	tests := map[string]refusal{
		"signed with the user key": {
			resign(t, userKey(t), tokens.DeveloperAccessKeyID, header, base), malformedOrBadSignature,
		},
		"typed as a user token": {
			altered(map[string]any{"token_type": string(tokens.UserAccess)}), typeMismatch,
		},
		"to another application":            {altered(map[string]any{"aud": otherApplication.String()}), notInternal},
		"to itself":                         {altered(map[string]any{"aud": base["sub"]}), notInternal},
		"without a credential version":      {altered(map[string]any{"credential_version": nil}), invalidVersion},
		"with a credential version of zero": {altered(map[string]any{"credential_version": float64(0)}), invalidVersion},
		"with a negative credential version": {
			altered(map[string]any{"credential_version": float64(-1)}), invalidVersion,
		},
		"with only the identify scope": {altered(map[string]any{"scope": "identify"}), scopeMismatch},
		"with its scopes reordered":    {altered(map[string]any{"scope": "identify abandonauth"}), scopeMismatch},
		"with an extra scope":          {altered(map[string]any{"scope": "abandonauth identify admin"}), scopeMismatch},
		"with a nil subject": {
			altered(map[string]any{"sub": uuid.Nil.String(), "user_id": uuid.Nil.String()}),
			"invalid subject claim: nil UUID",
		},
		"living longer than the access lifetime": {
			altered(map[string]any{"exp": float64(at.at.Add(tokens.AccessLifetime + time.Second).Unix())}),
			lifetimeMismatch,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			expectInvalid(t, signer, test.raw, test.reason)
		})
	}

	// The control: the unaltered token, re-signed the same way, is accepted.
	if _, err := signer.Verify(resign(t, key, tokens.DeveloperAccessKeyID, header, base)); err != nil {
		t.Errorf("the unaltered application token was refused: %v", err)
	}
}

// A developer application token authenticates an application, so it must not
// be accepted where a user principal is expected, and the reverse.
func TestTwoTokenClassesCannotStandInForEachOther(t *testing.T) {
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
func TestOnlyOneSigningAlgorithmIsAccepted(t *testing.T) {
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

	expectInvalid(t, signer, raw, malformedOrBadSignature)

	weaker := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	weaker.Header["kid"] = tokens.UserAccessKeyID

	raw, err = weaker.SignedString(userKey(t))
	if err != nil {
		t.Fatalf("building a differently signed token: %v", err)
	}

	expectInvalid(t, signer, raw, malformedOrBadSignature)
}

// Rotating the root secret is how a deployment withdraws every token at once.
func TestTokensDoNotSurviveRootSecretChange(t *testing.T) {
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

	expectInvalid(t, after, raw, malformedOrBadSignature)
}

func TestSignerNeedsEverythingItSignsWith(t *testing.T) {
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

	tests := map[string]struct {
		breakOne func(*tokens.Options)
		want     string
	}{
		"no issuer": {func(o *tokens.Options) { o.Issuer = "" }, "missing issuer"},
		"no internal application": {
			func(o *tokens.Options) { o.InternalApplicationID = uuid.Nil }, "missing internal application ID",
		},
		"no keys": {func(o *tokens.Options) { o.Keys = keyring.Keyring{} }, "missing signing key"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			options := complete
			test.breakOne(&options)

			_, err := tokens.NewSigner(options)
			if err == nil {
				t.Fatal("the signer was built")
			}

			if err.Error() != test.want {
				t.Errorf("error = %q, want %q", err.Error(), test.want)
			}
		})
	}
}

func TestSignerRefusesToIssueTokenWithNilIdentifier(t *testing.T) {
	t.Parallel()

	signer := newSigner(t, newClock())

	issueUser := func(subject, audience, authEpoch uuid.UUID) func() error {
		return func() error {
			_, _, err := signer.IssueUserAccess(subject, audience, authEpoch)

			return err
		}
	}

	issueDeveloper := func(application, authEpoch uuid.UUID, version int64) func() error {
		return func() error {
			_, _, err := signer.IssueDeveloperApplicationAccess(application, authEpoch, version)

			return err
		}
	}

	tests := map[string]struct {
		issue func() error
		want  string
	}{
		"a user token with a nil subject":    {issueUser(uuid.Nil, otherApplication, epoch), "user ID is nil"},
		"a user token with a nil audience":   {issueUser(person, uuid.Nil, epoch), "audience application ID is nil"},
		"a user token with a nil auth epoch": {issueUser(person, otherApplication, uuid.Nil), "auth epoch is nil"},
		"a developer application token with a nil application": {
			issueDeveloper(uuid.Nil, epoch, 1), "developer application ID is nil",
		},
		"a developer application token with credential version zero": {
			issueDeveloper(otherApplication, epoch, 0), "credential version must be positive",
		},
		"a developer application token with a nil auth epoch": {
			issueDeveloper(otherApplication, uuid.Nil, 1), "auth epoch is nil",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := test.issue()
			if err == nil {
				t.Fatal("the token was issued")
			}

			if err.Error() != test.want {
				t.Errorf("error = %q, want %q", err.Error(), test.want)
			}
		})
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
