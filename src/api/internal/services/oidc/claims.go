package oidc

import (
	"errors"
	"strings"
)

// Scopes is a set of the three scopes this profile supports.
type Scopes uint8

// The supported scopes. Their order here is the canonical order every response
// and token reports them in.
const (
	ScopeOpenID Scopes = 1 << iota
	ScopeProfile
	ScopeOfflineAccess
)

// MaxScopeBytes is the longest scope string read.
const MaxScopeBytes = 64

var scopeNames = []struct {
	scope Scopes
	name  string
}{
	{ScopeOpenID, "openid"},
	{ScopeProfile, "profile"},
	{ScopeOfflineAccess, "offline_access"},
}

// Reasons a scope string is refused. A malformed string is a malformed request;
// a well-formed one naming the wrong scopes is an invalid scope.
var (
	ErrMalformedScope = errors.New("the scope is not single-space-separated scope tokens")
	ErrInvalidScope   = errors.New("the scope is not openid with optionally profile and offline_access, once each")
)

// ParseScopes reads a scope string: tokens separated by single spaces with
// none leading or trailing, at most 64 bytes, naming openid and optionally
// profile and offline_access, each at most once and in any order.
func ParseScopes(raw string) (Scopes, error) {
	if raw == "" || len(raw) > MaxScopeBytes {
		return 0, ErrMalformedScope
	}

	var scopes Scopes

	for _, token := range strings.Split(raw, " ") {
		if token == "" || !isScopeToken(token) {
			return 0, ErrMalformedScope
		}

		named := scopeNamed(token)
		if named == 0 || scopes&named != 0 {
			return 0, ErrInvalidScope
		}

		scopes |= named
	}

	if scopes&ScopeOpenID == 0 {
		return 0, ErrInvalidScope
	}

	return scopes, nil
}

// isScopeToken admits the characters RFC 6749 allows in a scope token.
func isScopeToken(token string) bool {
	for index := range len(token) {
		character := token[index]
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}

	return true
}

func scopeNamed(name string) Scopes {
	for _, known := range scopeNames {
		if known.name == name {
			return known.scope
		}
	}

	return 0
}

// Has reports whether every scope in want is granted.
func (s Scopes) Has(want Scopes) bool {
	return s&want == want
}

// Names lists the granted scopes in canonical order.
func (s Scopes) Names() []string {
	names := make([]string, 0, len(scopeNames))

	for _, known := range scopeNames {
		if s&known.scope != 0 {
			names = append(names, known.name)
		}
	}

	return names
}

// String is the granted scopes in canonical order, separated by single spaces.
func (s Scopes) String() string {
	return strings.Join(s.Names(), " ")
}

// IDTokenClaims are an ID token's claims, and the only ones it carries. Nonce
// is present on the ID token issued for a code and absent from every refreshed
// one; PreferredUsername is present only when profile was granted.
type IDTokenClaims struct {
	Issuer            string  `json:"iss"`
	Subject           string  `json:"sub"`
	Audience          string  `json:"aud"`
	ExpiresAt         int64   `json:"exp"`
	IssuedAt          int64   `json:"iat"`
	AuthTime          int64   `json:"auth_time"`
	Nonce             string  `json:"nonce,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
}

// AccessTokenClaims are an RFC 9068 access token's claims, and the only ones it
// carries. It names no username and no AbandonAuth user identifier.
type AccessTokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	TokenID   string `json:"jti"`
	AuthEpoch string `json:"auth_epoch"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	ExpiresAt int64  `json:"exp"`
}

// accessTokenClaimNames are exactly the members an access token's payload has.
var accessTokenClaimNames = []string{
	"iss", "sub", "aud", "client_id", "scope", "jti", "auth_epoch", "iat", "nbf", "exp",
}
