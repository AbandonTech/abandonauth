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

// Verify checks a token's signature and every claim the service commits to, and
// returns what it says.
func (s *Signer) Verify(raw string) (Token, error) {
	if raw == "" {
		return Token{}, fmt.Errorf("%w: it is empty", ErrInvalid)
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
			return nil, errors.New("the token names no key")
		}

		signedClass, known := s.classForKeyID(identifier)
		if !known {
			return nil, errors.New("the token names a key this service does not sign with")
		}

		policy, err := s.policyFor(signedClass)
		if err != nil {
			return nil, err
		}

		class = signedClass

		return policy.key, nil
	})
	if err != nil {
		return Token{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}

	return s.verifyClaims(body, class)
}

// verifyClaims requires the body to be exactly what this service issues for the
// class the signing key named, claim by claim.
func (s *Signer) verifyClaims(body claims, class Class) (Token, error) {
	policy, err := s.policyFor(class)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}

	if body.TokenType != string(class) {
		return Token{}, fmt.Errorf("%w: its class does not match the key that signed it", ErrInvalid)
	}

	if body.Issuer != s.issuer {
		return Token{}, fmt.Errorf("%w: it was not issued by this service", ErrInvalid)
	}

	if body.Lifespan != lifespan {
		return Token{}, fmt.Errorf("%w: it does not carry the lifespan of an access token", ErrInvalid)
	}

	if body.Subject != body.UserID {
		return Token{}, fmt.Errorf("%w: it does not agree on who it speaks for", ErrInvalid)
	}

	subject, err := identifier(body.Subject)
	if err != nil {
		return Token{}, fmt.Errorf("%w: the subject is not an identifier", ErrInvalid)
	}

	audience, err := identifier(body.Audience)
	if err != nil {
		return Token{}, fmt.Errorf("%w: the audience is not an application", ErrInvalid)
	}

	if policy.internalAudience && audience != s.internalApplicationID {
		return Token{}, fmt.Errorf("%w: it was issued to an application that may not present it", ErrInvalid)
	}

	authEpoch, err := identifier(body.AuthEpoch)
	if err != nil {
		return Token{}, fmt.Errorf("%w: the authority epoch is not an identifier", ErrInvalid)
	}

	tokenID, err := identifier(body.TokenID)
	if err != nil {
		return Token{}, fmt.Errorf("%w: it cannot be identified, so it could not be withdrawn", ErrInvalid)
	}

	// The scope is compared as the one string this service writes, so a scope
	// that is unknown, repeated, reordered or spaced differently is refused
	// without being split up and read.
	scopes := s.scopesFor(class, audience)
	if body.Scope != strings.Join(scopes, " ") {
		return Token{}, fmt.Errorf("%w: it does not carry the scope of its class", ErrInvalid)
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

// identifier reads a claim that must be a UUID spelled the one way this service
// spells one, and that names something.
func identifier(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, err
	}

	if parsed == uuid.Nil {
		return uuid.Nil, errors.New("the identifier names nothing")
	}

	if parsed.String() != value {
		return uuid.Nil, errors.New("the identifier is not spelled canonically")
	}

	return parsed, nil
}

// verifyValidity checks that the token's interval is exactly the one this
// service issues, starting when it was issued and lasting the access lifetime,
// and that the clock is inside it.
func (s *Signer) verifyValidity(body claims) (time.Time, time.Time, error) {
	if body.IssuedAt == nil || body.NotBefore == nil || body.ExpiresAt == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it does not say when it is valid", ErrInvalid)
	}

	issuedAt := timeFromSeconds(*body.IssuedAt)
	notBefore := timeFromSeconds(*body.NotBefore)
	expiresAt := timeFromSeconds(*body.ExpiresAt)

	if !notBefore.Equal(issuedAt) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it is not valid from when it was issued", ErrInvalid)
	}

	if !expiresAt.Equal(issuedAt.Add(AccessLifetime)) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"%w: it does not live for exactly the access lifetime", ErrInvalid,
		)
	}

	now := s.now().UTC()

	if now.After(expiresAt.Add(MaxClockSkew)) {
		return time.Time{}, time.Time{}, ErrExpired
	}

	if now.Before(issuedAt.Add(-MaxClockSkew)) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it was issued in the future", ErrInvalid)
	}

	return issuedAt, expiresAt, nil
}

// credentialVersionOf reads the version an application token was issued
// against, and refuses a token of a class that carries none but has one: it
// would otherwise be a token about an application dressed as a person.
func credentialVersionOf(body claims, policy classPolicy) (int64, error) {
	if !policy.credentialVersion {
		if body.CredentialVersion != nil {
			return 0, fmt.Errorf("%w: it carries a credential version it has no use for", ErrInvalid)
		}

		return 0, nil
	}

	if body.CredentialVersion == nil || *body.CredentialVersion <= 0 {
		return 0, fmt.Errorf("%w: it does not say which credential it was issued against", ErrInvalid)
	}

	return *body.CredentialVersion, nil
}
