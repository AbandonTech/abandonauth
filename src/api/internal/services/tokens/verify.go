package tokens

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Key ID failures raised inside the key lookup, so they can be told apart from
// parser and signature failures without repeating the JWT library's text.
var (
	errMissingKeyID = errors.New("missing key ID")
	errUnknownKeyID = errors.New("unknown key ID")
)

// Reasons an identifier claim is refused.
var (
	errInvalidUUID      = errors.New("invalid UUID")
	errNilUUID          = errors.New("nil UUID")
	errNonCanonicalUUID = errors.New("non-canonical UUID")
)

// invalid wraps ErrInvalid with one package-owned reason.
func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, reason)
}

// invalidIdentifierClaim wraps ErrInvalid with the claim and the identifier
// rule it broke, never the claim's value.
func invalidIdentifierClaim(claim string, reason error) error {
	return fmt.Errorf("%w: invalid %s claim: %v", ErrInvalid, claim, reason)
}

// Verify checks a token's signature and every claim the service commits to, and
// returns its verified claims.
func (s *Signer) Verify(raw string) (Token, error) {
	if raw == "" {
		return Token{}, invalid("empty token")
	}

	var (
		body  claims
		class Class
	)

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{signingMethod.Alg()}),
		// Every temporal and identity claim is checked below against the
		// service's own clock and rules, so the library's defaults are not also
		// applied with a second, looser set.
		jwt.WithoutClaimsValidation(),
	)

	_, err := parser.ParseWithClaims(raw, &body, func(token *jwt.Token) (any, error) {
		identifier, present := token.Header["kid"].(string)
		if !present {
			return nil, errMissingKeyID
		}

		signedClass, known := s.classForKeyID(identifier)
		if !known {
			return nil, errUnknownKeyID
		}

		policy, err := s.policyFor(signedClass)
		if err != nil {
			return nil, err
		}

		class = signedClass

		return policy.key, nil
	})

	switch {
	case errors.Is(err, errMissingKeyID):
		return Token{}, invalid("missing key ID")
	case errors.Is(err, errUnknownKeyID):
		return Token{}, invalid("unknown key ID")
	case err != nil:
		// The library's text can describe the token's contents, so it is
		// replaced rather than appended.
		return Token{}, invalid("malformed token or invalid signature")
	}

	return s.verifyClaims(body, class)
}

// verifyClaims requires the body to be exactly what this service issues for the
// class the signing key ID selected, claim by claim.
func (s *Signer) verifyClaims(body claims, class Class) (Token, error) {
	policy, err := s.policyFor(class)
	if err != nil {
		return Token{}, invalid(err.Error())
	}

	if body.TokenType != string(class) {
		return Token{}, invalid("token type does not match signing key")
	}

	if body.Issuer != s.issuer {
		return Token{}, invalid("issuer claim mismatch")
	}

	if body.Lifespan != lifespan {
		return Token{}, invalid("invalid lifespan claim")
	}

	if body.Subject != body.UserID {
		return Token{}, invalid("subject and user ID conflict")
	}

	subject, err := identifier(body.Subject)
	if err != nil {
		return Token{}, invalidIdentifierClaim("subject", err)
	}

	audience, err := identifier(body.Audience)
	if err != nil {
		return Token{}, invalidIdentifierClaim("audience", err)
	}

	if policy.internalAudience && audience != s.internalApplicationID {
		return Token{}, invalid("audience does not identify internal application")
	}

	authEpoch, err := identifier(body.AuthEpoch)
	if err != nil {
		return Token{}, invalidIdentifierClaim("auth epoch", err)
	}

	tokenID, err := identifier(body.TokenID)
	if err != nil {
		return Token{}, invalidIdentifierClaim("token ID", err)
	}

	// The scope is compared as the one string this service writes, so a scope
	// that is unknown, repeated, reordered or spaced differently is refused
	// without being split up and read.
	scopes := s.scopesFor(class, audience)
	if body.Scope != strings.Join(scopes, " ") {
		return Token{}, invalid("scope claim mismatch")
	}

	version, err := credentialVersionOf(body, policy)
	if err != nil {
		return Token{}, err
	}

	issuedAt, expiresAt, err := s.verifyValidity(body)
	if err != nil {
		return Token{}, err
	}

	return Token{
		Class:             class,
		Subject:           subject,
		Audience:          audience,
		Scopes:            slices.Clone(scopes),
		AuthEpoch:         authEpoch,
		ID:                tokenID,
		CredentialVersion: version,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
	}, nil
}

// identifier reads a claim that must be a non-nil UUID in this service's
// canonical lowercase hyphenated form. The UUID library's error is replaced,
// because it can quote the value.
func identifier(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, errInvalidUUID
	}

	if parsed == uuid.Nil {
		return uuid.Nil, errNilUUID
	}

	if parsed.String() != value {
		return uuid.Nil, errNonCanonicalUUID
	}

	return parsed, nil
}

// verifyValidity checks that the token's interval is exactly the one this
// service issues, starting at iat and lasting the access lifetime, and that the
// clock is inside it.
func (s *Signer) verifyValidity(body claims) (time.Time, time.Time, error) {
	if body.IssuedAt == nil || body.NotBefore == nil || body.ExpiresAt == nil {
		return time.Time{}, time.Time{}, invalid("missing exp, iat, or nbf claim")
	}

	issuedAt := timeFromSeconds(*body.IssuedAt)
	notBefore := timeFromSeconds(*body.NotBefore)
	expiresAt := timeFromSeconds(*body.ExpiresAt)

	if !notBefore.Equal(issuedAt) {
		return time.Time{}, time.Time{}, invalid("nbf and iat claims conflict")
	}

	if !expiresAt.Equal(issuedAt.Add(AccessLifetime)) {
		return time.Time{}, time.Time{}, invalid("exp does not equal iat plus access lifetime")
	}

	now := s.now().UTC()

	if now.After(expiresAt.Add(MaxClockSkew)) {
		return time.Time{}, time.Time{}, ErrExpired
	}

	if now.Before(issuedAt.Add(-MaxClockSkew)) {
		return time.Time{}, time.Time{}, invalid("iat claim is in the future")
	}

	return issuedAt, expiresAt, nil
}

// credentialVersionOf reads the credential version a developer application
// token was issued against, and refuses the claim on a class that must omit it,
// so a user token cannot carry developer application claims.
func credentialVersionOf(body claims, policy classPolicy) (int64, error) {
	if !policy.credentialVersion {
		if body.CredentialVersion != nil {
			return 0, invalid("unexpected credential version claim")
		}

		return 0, nil
	}

	if body.CredentialVersion == nil || *body.CredentialVersion <= 0 {
		return 0, invalid("missing or invalid credential version claim")
	}

	return *body.CredentialVersion, nil
}
