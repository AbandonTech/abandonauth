package tokens

import (
	"github.com/golang-jwt/jwt/v5"
)

// claims is the body of a token, written exactly as it goes on the wire.
//
// The audience is a single string rather than a list, and the times are plain
// seconds, because that is the shape applications already parse. The three
// times are pointers so that a token which omits one is refused rather than
// read as the epoch.
type claims struct {
	UserID    string `json:"user_id"`
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Scope     string `json:"scope"`
	Lifespan  string `json:"lifespan"`
	TokenType string `json:"token_type"`
	AuthEpoch string `json:"auth_epoch"`
	TokenID   string `json:"jti"`

	IssuedAt  *int64 `json:"iat"`
	NotBefore *int64 `json:"nbf"`
	ExpiresAt *int64 `json:"exp"`

	CredentialVersion *int64 `json:"credential_version,omitempty"`
}

// The methods below satisfy jwt.Claims. Parsing runs with the library's own
// claim validation switched off, so they are not consulted; the service checks
// every claim itself against its own clock.

func (c claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return numericDate(c.ExpiresAt), nil
}

func (c claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return numericDate(c.IssuedAt), nil
}

func (c claims) GetNotBefore() (*jwt.NumericDate, error) {
	return numericDate(c.NotBefore), nil
}

func (c claims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c claims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c claims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}

	return jwt.ClaimStrings{c.Audience}, nil
}

func numericDate(value *int64) *jwt.NumericDate {
	if value == nil {
		return nil
	}

	return jwt.NewNumericDate(timeFromSeconds(*value))
}
