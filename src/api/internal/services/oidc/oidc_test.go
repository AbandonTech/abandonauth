package oidc_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
)

const issuer = "https://auth.example.test/api"

// testKeys are generated once: RSA generation is slow and these protect
// nothing. Three keys let a test hold one key per purpose and a third that
// belongs to neither.
var testKeys = sync.OnceValue(func() []*rsa.PrivateKey {
	keys := make([]*rsa.PrivateKey, 3)

	for index := range keys {
		key, err := rsa.GenerateKey(rand.Reader, oidc.MinModulusBits)
		if err != nil {
			panic(err)
		}

		keys[index] = key
	}

	return keys
})

// keyFile writes a key as the PKCS #8 PEM file `openssl genpkey` makes.
func keyFile(t *testing.T, key any) []byte {
	t.Helper()

	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding a key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func thumbprintOf(key *rsa.PrivateKey) string {
	return oidc.Thumbprint(
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	)
}

func signingKeys(t *testing.T) (oidc.SigningKeys, *rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()

	idKey, accessKey := testKeys()[0], testKeys()[1]

	keys, err := oidc.ParseSigningKeys(keyFile(t, idKey), keyFile(t, accessKey))
	if err != nil {
		t.Fatalf("the service refuses its own key files: %v", err)
	}

	return keys, idKey, accessKey
}

// keyMembers decodes a published key set.
func keyMembers(t *testing.T, set []byte) []map[string]any {
	t.Helper()

	var decoded struct {
		Keys []map[string]any `json:"keys"`
	}

	if err := json.Unmarshal(set, &decoded); err != nil {
		t.Fatalf("decoding a key set: %v", err)
	}

	return decoded.Keys
}

func TestKeyFilesAreAcceptedOnlyAsOnePKCS8RSAKey(t *testing.T) {
	t.Parallel()

	idKey, accessKey, other := testKeys()[0], testKeys()[1], testKeys()[2]
	validFile, accessFile := keyFile(t, idKey), keyFile(t, accessKey)

	keys, err := oidc.ParseSigningKeys(validFile, accessFile)
	if err != nil {
		t.Fatalf("the positive control was refused: %v", err)
	}

	if keys.IDToken().ActiveKeyID() != thumbprintOf(idKey) || keys.AccessToken().ActiveKeyID() != thumbprintOf(accessKey) {
		t.Error("a key is not identified by its RFC 7638 thumbprint")
	}

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating a weak key: %v", err)
	}

	curve, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating an EC key: %v", err)
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(idKey)
	if err != nil {
		t.Fatalf("encoding a key: %v", err)
	}

	refused := map[string]struct {
		file []byte
		want error
	}{
		"an empty file":   {nil, oidc.ErrKeyFileMalformed},
		"not PEM":         {[]byte("not a key"), oidc.ErrKeyFileMalformed},
		"two keys":        {append(bytes.Clone(validFile), keyFile(t, other)...), oidc.ErrKeyFileMalformed},
		"trailing text":   {append(bytes.Clone(validFile), "trailing"...), oidc.ErrKeyFileMalformed},
		"a PKCS #1 block": {pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(idKey)}), oidc.ErrKeyFileMalformed},
		"a PEM header": {pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: encoded,
		}), oidc.ErrKeyFileMalformed},
		"a corrupt key":  {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded[:len(encoded)/2]}), oidc.ErrKeyType},
		"an EC key":      {keyFile(t, curve), oidc.ErrKeyType},
		"a weak modulus": {keyFile(t, weak), oidc.ErrKeyTooWeak},
		"oversized":      {append(bytes.Clone(validFile), bytes.Repeat([]byte(" "), oidc.MaxKeyFileBytes)...), oidc.ErrKeyFileTooLarge},
	}

	for name, refusal := range refused {
		_, err := oidc.ParseSigningKeys(refusal.file, accessFile)
		if !errors.Is(err, refusal.want) {
			t.Errorf("%s: refused with %v, want %v", name, err, refusal.want)

			continue
		}

		for _, private := range []string{idKey.D.String()[:20], string(validFile[200:240])} {
			if strings.Contains(err.Error(), private) {
				t.Errorf("%s: the refusal quotes the key", name)
			}
		}
	}

	if _, err := oidc.ParseSigningKeys(accessFile, accessFile); !errors.Is(err, oidc.ErrKeyShared) {
		t.Errorf("one key for both purposes was refused with %v", err)
	}
}

// Each published set holds exactly its purpose's public keys, with exactly the
// members a validator needs, and an identifier that is the key's thumbprint.
func TestPublishedKeySetsArePublicAndPurposeSeparated(t *testing.T) {
	t.Parallel()

	keys, idKey, accessKey := signingKeys(t)

	for name, published := range map[string]struct {
		set  []byte
		want *rsa.PrivateKey
	}{
		"ID token":     {keys.IDToken().PublicJWKSet(), idKey},
		"access token": {keys.AccessToken().PublicJWKSet(), accessKey},
	} {
		listed := keyMembers(t, published.set)
		if len(listed) != 1 {
			t.Fatalf("%s set lists %d keys", name, len(listed))
		}

		key := listed[0]
		if len(key) != 6 || key["kty"] != "RSA" || key["use"] != "sig" || key["alg"] != "RS256" {
			t.Errorf("%s key = %v, want exactly the six public members", name, key)
		}

		if key["kid"] != oidc.Thumbprint(key["n"].(string), key["e"].(string)) {
			t.Errorf("%s key identifier is not its thumbprint", name)
		}

		modulus, _ := base64.RawURLEncoding.DecodeString(key["n"].(string))
		if new(big.Int).SetBytes(modulus).Cmp(published.want.N) != 0 {
			t.Errorf("%s set publishes another purpose's key", name)
		}

		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if strings.Contains(string(published.set), `"`+private+`"`) {
				t.Errorf("%s set publishes %s", name, private)
			}
		}
	}

	if keys.IDToken().ActiveKeyID() == keys.AccessToken().ActiveKeyID() {
		t.Error("both purposes sign with one key")
	}

	for _, rendered := range []string{keys.String(), keys.GoString(), keys.IDToken().String(), keys.AccessToken().GoString()} {
		if strings.Contains(rendered, idKey.D.String()[:16]) || strings.Contains(rendered, "RSA") {
			t.Error("a rendered key set carries key material")
		}
	}
}

func TestScopesAreReadStrictlyAndReportedCanonically(t *testing.T) {
	t.Parallel()

	for raw, canonical := range map[string]string{
		"openid":                        "openid",
		"profile openid":                "openid profile",
		"offline_access openid profile": "openid profile offline_access",
		"openid offline_access":         "openid offline_access",
	} {
		scopes, err := oidc.ParseScopes(raw)
		if err != nil || scopes.String() != canonical {
			t.Errorf("%q = %q, %v; want %q", raw, scopes, err, canonical)
		}
	}

	for raw, want := range map[string]error{
		"":                            oidc.ErrMalformedScope,
		" openid":                     oidc.ErrMalformedScope,
		"openid ":                     oidc.ErrMalformedScope,
		"openid  profile":             oidc.ErrMalformedScope,
		"openid\tprofile":             oidc.ErrMalformedScope,
		"openid\x00":                  oidc.ErrMalformedScope,
		"openïd":                      oidc.ErrMalformedScope,
		strings.Repeat("openid ", 10): oidc.ErrMalformedScope,
		"profile":                     oidc.ErrInvalidScope,
		"openid openid":               oidc.ErrInvalidScope,
		"openid email":                oidc.ErrInvalidScope,
		"OPENID":                      oidc.ErrInvalidScope,
	} {
		if _, err := oidc.ParseScopes(raw); !errors.Is(err, want) {
			t.Errorf("%q refused with %v, want %v", raw, err, want)
		}
	}
}

type clock struct{ now time.Time }

func (c *clock) read() time.Time { return c.now }

func issuerAndVerifier(t *testing.T) (*oidc.Issuer, *oidc.AccessTokenVerifier, *clock, oidc.SigningKeys) {
	t.Helper()

	keys, _, _ := signingKeys(t)
	at := &clock{now: time.Unix(1_800_000_000, 0)}

	signer, err := oidc.NewIssuer(issuer, keys, at.read)
	if err != nil {
		t.Fatalf("building the issuer: %v", err)
	}

	return signer, oidc.NewAccessTokenVerifier(issuer, keys, at.read), at, keys
}

func segments(t *testing.T, token string) (map[string]any, map[string]any) {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("a token has %d segments", len(parts))
	}

	decode := func(segment string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatalf("a segment is not base64url: %v", err)
		}

		var members map[string]any
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatalf("a segment is not JSON: %v", err)
		}

		return members
	}

	return decode(parts[0]), decode(parts[1])
}

func TestIssuedTokensCarryExactlyTheirProfile(t *testing.T) {
	t.Parallel()

	signer, verifier, at, keys := issuerAndVerifier(t)
	client := uuid.New()
	epoch := uuid.New()
	subject := uuid.New()
	canonical := strings.ToLower(subject.String())
	username := "someone"

	access, claims, err := signer.IssueAccessToken(oidc.Access{
		Subject: subject, ClientID: client, Scopes: oidc.ScopeOpenID | oidc.ScopeOfflineAccess | oidc.ScopeProfile,
		AuthEpoch: epoch,
	})
	if err != nil {
		t.Fatalf("issuing an access token: %v", err)
	}

	header, payload := segments(t, access)
	if len(header) != 3 || header["alg"] != "RS256" || header["typ"] != "at+jwt" ||
		header["kid"] != keys.AccessToken().ActiveKeyID() {
		t.Errorf("access token header = %v", header)
	}

	if len(payload) != 10 || payload["iss"] != issuer || payload["sub"] != canonical || payload["aud"] != client.String() ||
		payload["client_id"] != client.String() || payload["scope"] != "openid profile offline_access" ||
		payload["auth_epoch"] != epoch.String() || payload["iat"] != payload["nbf"] ||
		payload["exp"].(float64)-payload["iat"].(float64) != 900 {
		t.Errorf("access token claims = %v", payload)
	}

	for _, absent := range []string{"preferred_username", "user_id"} {
		if _, present := payload[absent]; present {
			t.Errorf("an access token carries %s", absent)
		}
	}

	verified, err := verifier.Verify(access)
	if err != nil || verified != claims || verified.Identifier().String() != claims.TokenID ||
		verified.SubjectIdentifier() != subject {
		t.Errorf("the verifier refuses the issued token: %v", err)
	}

	if (oidc.AccessTokenClaims{}).SubjectIdentifier() != uuid.Nil {
		t.Error("claims Verify did not return named a user")
	}

	authenticated := at.now.Add(-time.Minute)

	id, err := signer.IssueIDToken(oidc.Identity{
		Subject: subject, ClientID: client, AuthTime: authenticated, Nonce: "n0nce", Username: &username,
	})
	if err != nil {
		t.Fatalf("issuing an ID token: %v", err)
	}

	header, payload = segments(t, id)
	if header["typ"] != "JWT" || header["kid"] != keys.IDToken().ActiveKeyID() || header["alg"] != "RS256" {
		t.Errorf("ID token header = %v", header)
	}

	if len(payload) != 8 || payload["sub"] != canonical || payload["aud"] != client.String() ||
		payload["nonce"] != "n0nce" || payload["preferred_username"] != username ||
		payload["auth_time"] != float64(authenticated.Unix()) ||
		payload["exp"].(float64)-payload["iat"].(float64) != 300 {
		t.Errorf("ID token claims = %v", payload)
	}

	if _, present := payload["user_id"]; present {
		t.Error("an ID token carries user_id")
	}

	refreshed, err := signer.IssueIDToken(oidc.Identity{Subject: subject, ClientID: client, AuthTime: authenticated})
	if err != nil {
		t.Fatalf("issuing a refreshed ID token: %v", err)
	}

	if _, payload = segments(t, refreshed); len(payload) != 6 {
		t.Errorf("a refreshed ID token without profile carries %v", payload)
	}

	if _, err := verifier.Verify(id); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Error("an ID token was accepted as an access token")
	}

	for _, incomplete := range []oidc.Access{
		{ClientID: client, Scopes: oidc.ScopeOpenID, AuthEpoch: epoch},
		{Subject: subject, Scopes: oidc.ScopeOpenID, AuthEpoch: epoch},
		{Subject: subject, ClientID: client, AuthEpoch: epoch},
		{Subject: subject, ClientID: client, Scopes: oidc.ScopeOpenID},
	} {
		if _, _, err := signer.IssueAccessToken(incomplete); err == nil {
			t.Errorf("an access token was issued for %+v", incomplete)
		}
	}

	if _, err := signer.IssueIDToken(oidc.Identity{Subject: subject, ClientID: client}); err == nil {
		t.Error("an ID token was issued without an authentication time")
	}

	if _, err := signer.IssueIDToken(oidc.Identity{ClientID: client, AuthTime: authenticated}); err == nil {
		t.Error("an ID token was issued for the nil user")
	}

	if _, err := oidc.NewIssuer("", keys, nil); err == nil {
		t.Error("an issuer was built without an identifier")
	}

	if signer.Identifier() != issuer {
		t.Errorf("Identifier() = %q", signer.Identifier())
	}
}

// The verifier allows no clock tolerance: a token is accepted from its issue
// up to, and not at, its expiry.
func TestAccessTokensAreAcceptedForExactlyTheirLifetime(t *testing.T) {
	t.Parallel()

	signer, verifier, at, _ := issuerAndVerifier(t)
	issuedAt := at.now

	token, _, err := signer.IssueAccessToken(oidc.Access{
		Subject: uuid.New(), ClientID: uuid.New(), Scopes: oidc.ScopeOpenID, AuthEpoch: uuid.New(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	for offset, accepted := range map[time.Duration]bool{
		-time.Second:                           false,
		0:                                      true,
		oidc.AccessTokenLifetime - time.Second: true,
		oidc.AccessTokenLifetime:               false,
		oidc.AccessTokenLifetime + time.Second: false,
	} {
		at.now = issuedAt.Add(offset)

		_, err := verifier.Verify(token)
		if (err == nil) != accepted {
			t.Errorf("at %v after issue: accepted = %v, want %v", offset, err == nil, accepted)
		}
	}
}

// forge signs any header and payload with a key, so the abuse cases below are
// genuine signatures over altered content rather than broken ones.
func forge(t *testing.T, key *rsa.PrivateKey, header, payload any) string {
	t.Helper()

	encode := func(value any) string {
		if raw, isRaw := value.(string); isRaw {
			return base64.RawURLEncoding.EncodeToString([]byte(raw))
		}

		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("encoding: %v", err)
		}

		return base64.RawURLEncoding.EncodeToString(encoded)
	}

	input := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(input))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifierRefusesEveryAlteredToken(t *testing.T) {
	t.Parallel()

	signer, verifier, _, keys := issuerAndVerifier(t)
	_, idKey, accessKey := signingKeys(t)
	client := uuid.New()

	subject := uuid.New().String()

	genuine, claims, err := signer.IssueAccessToken(oidc.Access{
		Subject: uuid.MustParse(subject), ClientID: client, Scopes: oidc.ScopeOpenID, AuthEpoch: uuid.New(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	if _, err := verifier.Verify(genuine); err != nil {
		t.Fatalf("the positive control was refused: %v", err)
	}

	header, payload := segments(t, genuine)

	if _, err := verifier.Verify(forge(t, accessKey, header, payload)); err != nil {
		t.Fatalf("a re-signed genuine token was refused, so the cases below prove nothing: %v", err)
	}

	with := func(source map[string]any, name string, value any) map[string]any {
		changed := make(map[string]any, len(source)+1)
		for member, existing := range source {
			changed[member] = existing
		}

		if value == nil {
			delete(changed, name)
		} else {
			changed[name] = value
		}

		return changed
	}

	another := uuid.New()

	reassigned, err := verifier.Verify(forge(t, accessKey, header, with(payload, "sub", another.String())))
	if err != nil || reassigned.SubjectIdentifier() != another {
		t.Fatalf("a canonical subject re-signed with the genuine key was refused, so the subject cases prove nothing: %v", err)
	}

	hmacToken := func() string {
		hs := with(header, "alg", "HS256")
		encodedHeader, _ := json.Marshal(hs)
		encodedPayload, _ := json.Marshal(payload)
		input := base64.RawURLEncoding.EncodeToString(encodedHeader) + "." + base64.RawURLEncoding.EncodeToString(encodedPayload)
		mac := hmac.New(sha256.New, []byte(keys.AccessToken().PublicJWKSet()))
		mac.Write([]byte(input))

		return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}

	parts := strings.Split(genuine, ".")

	refused := map[string]string{
		"empty":                        "",
		"two segments":                 parts[0] + "." + parts[1],
		"four segments":                genuine + ".x",
		"padded signature":             genuine + "=",
		"truncated signature":          genuine[:len(genuine)-4],
		"standard-base64 segment":      strings.ReplaceAll(parts[0], "-", "+") + "." + parts[1] + "." + parts[2] + "+",
		"oversized":                    genuine + "." + strings.Repeat("A", oidc.MaxTokenBytes),
		"alg none":                     parts[0][:0] + base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"`+keys.AccessToken().ActiveKeyID()+`","typ":"at+jwt"}`)) + "." + parts[1] + ".",
		"HS256 with the public key":    hmacToken(),
		"PS256":                        forge(t, accessKey, with(header, "alg", "PS256"), payload),
		"RS384":                        forge(t, accessKey, with(header, "alg", "RS384"), payload),
		"no kid":                       forge(t, accessKey, with(header, "kid", nil), payload),
		"empty kid":                    forge(t, accessKey, with(header, "kid", ""), payload),
		"numeric kid":                  forge(t, accessKey, with(header, "kid", 7), payload),
		"unknown kid":                  forge(t, accessKey, with(header, "kid", "unknown"), payload),
		"ID key kid":                   forge(t, idKey, with(header, "kid", keys.IDToken().ActiveKeyID()), payload),
		"signed by the ID key":         forge(t, idKey, header, payload),
		"crit":                         forge(t, accessKey, with(header, "crit", []string{"exp"}), payload),
		"b64":                          forge(t, accessKey, with(header, "b64", false), payload),
		"jku":                          forge(t, accessKey, with(header, "jku", "https://evil.example/jwks"), payload),
		"embedded jwk":                 forge(t, accessKey, with(header, "jwk", map[string]any{"kty": "RSA"}), payload),
		"x5u":                          forge(t, accessKey, with(header, "x5u", "https://evil.example"), payload),
		"x5c":                          forge(t, accessKey, with(header, "x5c", []string{"AAAA"}), payload),
		"ID token type":                forge(t, accessKey, with(header, "typ", "JWT"), payload),
		"duplicate alg":                forge(t, accessKey, `{"alg":"RS256","alg":"RS256","kid":"`+keys.AccessToken().ActiveKeyID()+`","typ":"at+jwt"}`, payload),
		"duplicate sub":                forge(t, accessKey, header, strings.Replace(mustJSON(t, payload), `"sub":`, `"sub":"`+another.String()+`","sub":`, 1)),
		"trailing JSON":                forge(t, accessKey, header, mustJSON(t, payload)+`{}`),
		"no subject":                   forge(t, accessKey, header, with(payload, "sub", nil)),
		"the nil subject":              forge(t, accessKey, header, with(payload, "sub", uuid.Nil.String())),
		"an upper-case subject":        forge(t, accessKey, header, with(payload, "sub", strings.ToUpper(subject))),
		"a braced subject":             forge(t, accessKey, header, with(payload, "sub", "{"+subject+"}")),
		"a compact subject":            forge(t, accessKey, header, with(payload, "sub", strings.ReplaceAll(subject, "-", ""))),
		"a URN subject":                forge(t, accessKey, header, with(payload, "sub", "urn:uuid:"+subject)),
		"a malformed subject":          forge(t, accessKey, header, with(payload, "sub", subject[:35]+"g")),
		"an opaque subject":            forge(t, accessKey, header, with(payload, "sub", strings.Repeat("s", 43))),
		"a numeric subject":            forge(t, accessKey, header, with(payload, "sub", 7)),
		"a subject array":              forge(t, accessKey, header, with(payload, "sub", []string{subject})),
		"another issuer":               forge(t, accessKey, header, with(payload, "iss", "https://evil.example/api")),
		"audience as an array":         forge(t, accessKey, header, with(payload, "aud", []string{client.String()})),
		"another audience":             forge(t, accessKey, header, with(payload, "aud", uuid.New().String())),
		"upper-case client":            forge(t, accessKey, header, with(with(payload, "client_id", strings.ToUpper(client.String())), "aud", strings.ToUpper(client.String()))),
		"unknown scope":                forge(t, accessKey, header, with(payload, "scope", "openid email")),
		"no openid":                    forge(t, accessKey, header, with(payload, "scope", "profile")),
		"scope out of order":           forge(t, accessKey, header, with(payload, "scope", "profile openid")),
		"a non-UUID token identifier":  forge(t, accessKey, header, with(payload, "jti", "not-a-uuid")),
		"a non-UUID epoch":             forge(t, accessKey, header, with(payload, "auth_epoch", "epoch")),
		"a username":                   forge(t, accessKey, header, with(payload, "preferred_username", "someone")),
		"no auth_epoch":                forge(t, accessKey, header, with(payload, "auth_epoch", nil)),
		"a string expiry":              forge(t, accessKey, header, with(payload, "exp", "1800000900")),
		"a fractional expiry":          forge(t, accessKey, header, with(payload, "exp", 1800000900.5)),
		"a negative issue time":        forge(t, accessKey, header, with(payload, "iat", -1)),
		"an overflowing expiry":        forge(t, accessKey, header, with(payload, "exp", 1e30)),
		"a longer lifetime":            forge(t, accessKey, header, with(payload, "exp", claims.ExpiresAt+1)),
		"a later not-before":           forge(t, accessKey, header, with(payload, "nbf", claims.IssuedAt+1)),
		"a payload that is not JSON":   forge(t, accessKey, header, "not json"),
		"a payload with invalid UTF-8": forge(t, accessKey, header, "{\"iss\":\"\xff\"}"),
	}

	for name, token := range refused {
		if _, err := verifier.Verify(token); !errors.Is(err, oidc.ErrInvalidToken) {
			t.Errorf("%s was accepted", name)
		}
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	return string(encoded)
}
