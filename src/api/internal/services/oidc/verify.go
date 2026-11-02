package oidc

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// MaxTokenBytes is the longest compact token read. A longer one is refused
// before any decoding or cryptography.
const MaxTokenBytes = 8192

// ErrInvalidToken reports an access token that is not accepted, for whatever
// reason, so a caller learns nothing about which check failed.
var ErrInvalidToken = errors.New("the access token is not accepted")

var (
	canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	opaqueSubject = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// AccessTokenVerifier accepts exactly the access tokens Issuer signs: the
// access token header, a key from the access token ring, this issuer, and
// every claim of the profile with its exact type and its exact lifetime. It
// allows no clock tolerance.
type AccessTokenVerifier struct {
	issuer string
	ring   KeyRing
	now    func() time.Time
}

// NewAccessTokenVerifier builds the verifier for one issuer.
func NewAccessTokenVerifier(issuer string, keys SigningKeys, now func() time.Time) *AccessTokenVerifier {
	if now == nil {
		now = time.Now
	}

	return &AccessTokenVerifier{issuer: issuer, ring: keys.accessToken, now: now}
}

// Verify returns an access token's claims when every check passes.
func (v *AccessTokenVerifier) Verify(token string) (AccessTokenClaims, error) {
	header, payload, err := verifySignature(token, v.ring)
	if err != nil {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	if header.Type != accessTokenType {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	claims, err := readAccessTokenClaims(payload)
	if err != nil {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	now := v.now().Unix()

	if claims.Issuer != v.issuer || claims.Audience != claims.ClientID ||
		claims.NotBefore != claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt != int64(AccessTokenLifetime/time.Second) ||
		now < claims.NotBefore || now >= claims.ExpiresAt {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	return claims, nil
}

// Identifier is the token's jti as a UUID, or the nil UUID for claims Verify
// did not return.
func (c AccessTokenClaims) Identifier() uuid.UUID {
	if !canonicalUUID.MatchString(c.TokenID) {
		return uuid.Nil
	}

	return uuid.MustParse(c.TokenID)
}

// verifySignature reads a compact token with exactly the three members an
// RS256 header of this service has, and checks its signature with the key its
// kid names in the ring. It reports the header and the decoded payload.
func verifySignature(token string, ring KeyRing) (signedHeader, []byte, error) {
	if len(token) > MaxTokenBytes {
		return signedHeader{}, nil, ErrInvalidToken
	}

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return signedHeader{}, nil, ErrInvalidToken
	}

	decoded := make([][]byte, 3)

	for index, segment := range segments {
		value, err := base64.RawURLEncoding.Strict().DecodeString(segment)
		if err != nil || len(value) == 0 {
			return signedHeader{}, nil, ErrInvalidToken
		}

		decoded[index] = value
	}

	header, err := readHeader(decoded[0])
	if err != nil {
		return signedHeader{}, nil, ErrInvalidToken
	}

	key, found := ring.verificationKey(header.KeyID)
	if !found {
		return signedHeader{}, nil, ErrInvalidToken
	}

	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))

	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], decoded[2]); err != nil {
		return signedHeader{}, nil, ErrInvalidToken
	}

	return header, decoded[1], nil
}

func readHeader(raw []byte) (signedHeader, error) {
	members, err := decodeObject(raw)
	if err != nil || !hasExactly(members, []string{"alg", "kid", "typ"}) {
		return signedHeader{}, ErrInvalidToken
	}

	var header signedHeader

	var valid bool

	if header.Algorithm, valid = decodeString(members["alg"]); !valid || header.Algorithm != keyAlgorithm {
		return signedHeader{}, ErrInvalidToken
	}

	if header.KeyID, valid = decodeString(members["kid"]); !valid || header.KeyID == "" {
		return signedHeader{}, ErrInvalidToken
	}

	if header.Type, valid = decodeString(members["typ"]); !valid {
		return signedHeader{}, ErrInvalidToken
	}

	return header, nil
}

func readAccessTokenClaims(raw []byte) (AccessTokenClaims, error) {
	members, err := decodeObject(raw)
	if err != nil || !hasExactly(members, accessTokenClaimNames) {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	var claims AccessTokenClaims

	texts := map[string]*string{
		"iss": &claims.Issuer, "sub": &claims.Subject, "aud": &claims.Audience, "client_id": &claims.ClientID,
		"scope": &claims.Scope, "jti": &claims.TokenID, "auth_epoch": &claims.AuthEpoch,
	}

	for name, target := range texts {
		value, isString := decodeString(members[name])
		if !isString {
			return AccessTokenClaims{}, ErrInvalidToken
		}

		*target = value
	}

	numbers := map[string]*int64{"iat": &claims.IssuedAt, "nbf": &claims.NotBefore, "exp": &claims.ExpiresAt}

	for name, target := range numbers {
		value, isNumber := decodeTimestamp(members[name])
		if !isNumber {
			return AccessTokenClaims{}, ErrInvalidToken
		}

		*target = value
	}

	scopes, err := ParseScopes(claims.Scope)
	if err != nil || scopes.String() != claims.Scope {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	if !canonicalUUID.MatchString(claims.ClientID) || !canonicalUUID.MatchString(claims.TokenID) ||
		!canonicalUUID.MatchString(claims.AuthEpoch) || !opaqueSubject.MatchString(claims.Subject) {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	return claims, nil
}

// decodeObject reads exactly one JSON object of valid UTF-8 and returns its
// members. A member named twice is refused: readers disagree about which of the
// two counts, and that disagreement is where a forged claim hides.
func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInvalidToken
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))

	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, ErrInvalidToken
	}

	members := make(map[string]json.RawMessage)

	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, ErrInvalidToken
		}

		key, isString := name.(string)
		if !isString {
			return nil, ErrInvalidToken
		}

		if _, repeated := members[key]; repeated {
			return nil, ErrInvalidToken
		}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrInvalidToken
		}

		members[key] = value
	}

	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, ErrInvalidToken
	}

	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidToken
	}

	return members, nil
}

func hasExactly(members map[string]json.RawMessage, names []string) bool {
	if len(members) != len(names) {
		return false
	}

	for _, name := range names {
		if _, found := members[name]; !found {
			return false
		}
	}

	return true
}

func decodeString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}

	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", false
	}

	return value, true
}

// decodeTimestamp reads a positive whole number of seconds written as plain
// digits: no sign, fraction, exponent or string.
func decodeTimestamp(raw json.RawMessage) (int64, bool) {
	text := string(bytes.TrimSpace(raw))
	if text == "" || len(text) > 18 || slices.ContainsFunc([]byte(text), func(character byte) bool {
		return character < '0' || character > '9'
	}) {
		return 0, false
	}

	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value <= 0 {
		return 0, false
	}

	return value, true
}
