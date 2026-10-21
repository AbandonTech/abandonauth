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

// IssueUserAccess signs an access token authenticating a user to one audience
// application.
//
// A token whose audience is the AbandonAuth site carries the scope that
// authorizes managing developer applications; a token for any other audience
// authorizes identification only, so an application cannot use a token issued
// to it to manage its owner's account.
func (s *Signer) IssueUserAccess(subject, audience, authEpoch uuid.UUID) (string, Token, error) {
	if subject == uuid.Nil {
		return "", Token{}, errors.New("user ID is nil")
	}

	if audience == uuid.Nil {
		return "", Token{}, errors.New("audience application ID is nil")
	}

	return s.issue(UserAccess, subject, audience, authEpoch, 0)
}

// IssueDeveloperApplicationAccess signs an access token authenticating a
// developer application as the principal.
//
// The version is the application's credential version at the moment of issue.
// Resetting the application's refresh token raises it, which is what stops a
// token minted a moment before the reset from outliving it.
func (s *Signer) IssueDeveloperApplicationAccess(
	applicationID, authEpoch uuid.UUID, credentialVersion int64,
) (string, Token, error) {
	if applicationID == uuid.Nil {
		return "", Token{}, errors.New("developer application ID is nil")
	}

	if credentialVersion <= 0 {
		return "", Token{}, errors.New("credential version must be positive")
	}

	return s.issue(DeveloperApplicationAccess, applicationID, s.internalApplicationID, authEpoch, credentialVersion)
}

func (s *Signer) issue(
	class Class,
	subject, audience, authEpoch uuid.UUID,
	credentialVersion int64,
) (string, Token, error) {
	if authEpoch == uuid.Nil {
		return "", Token{}, errors.New("auth epoch is nil")
	}

	policy, err := s.policyFor(class)
	if err != nil {
		return "", Token{}, err
	}

	identifier, err := uuid.NewRandom()
	if err != nil {
		return "", Token{}, fmt.Errorf("generating token ID: %w", err)
	}

	scopes := s.scopesFor(class, audience)
	issuedAt := s.now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(AccessLifetime)

	body := claims{
		UserID:    subject.String(),
		Subject:   subject.String(),
		Issuer:    s.issuer,
		Audience:  audience.String(),
		Scope:     strings.Join(scopes, " "),
		Lifespan:  lifespan,
		TokenType: string(class),
		AuthEpoch: authEpoch.String(),
		TokenID:   identifier.String(),
		IssuedAt:  seconds(issuedAt),
		NotBefore: seconds(issuedAt),
		ExpiresAt: seconds(expiresAt),
	}

	if policy.credentialVersion {
		body.CredentialVersion = &credentialVersion
	}

	signed := jwt.NewWithClaims(signingMethod, body)
	signed.Header["kid"] = policy.keyID

	raw, err := signed.SignedString(policy.key)
	if err != nil {
		return "", Token{}, fmt.Errorf("signing token: %w", err)
	}

	return raw, Token{
		Class:             class,
		Subject:           subject,
		Audience:          audience,
		Scopes:            slices.Clone(scopes),
		AuthEpoch:         authEpoch,
		ID:                identifier,
		CredentialVersion: credentialVersion,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
	}, nil
}
