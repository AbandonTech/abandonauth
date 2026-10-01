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

// IssueUserAccess signs a token that speaks for a person to one application.
//
// A token for the AbandonAuth site itself carries the scope that manages
// developer applications; a token for any other application only identifies the
// person, so an application cannot use a token it was given to act on its
// owner's account.
func (s *Signer) IssueUserAccess(subject, audience, authEpoch uuid.UUID) (string, Token, error) {
	if subject == uuid.Nil {
		return "", Token{}, errors.New("a user token needs a subject")
	}

	if audience == uuid.Nil {
		return "", Token{}, errors.New("a user token needs an audience")
	}

	return s.issue(UserAccess, subject, audience, authEpoch, 0)
}

// IssueDeveloperApplicationAccess signs a token that speaks for an application.
//
// The version is the application's credential version at the moment of issue.
// Resetting the application's refresh token raises it, which is what stops a
// token minted a moment before the reset from outliving it.
func (s *Signer) IssueDeveloperApplicationAccess(
	applicationID, authEpoch uuid.UUID, credentialVersion int64,
) (string, Token, error) {
	if applicationID == uuid.Nil {
		return "", Token{}, errors.New("an application token needs an application")
	}

	if credentialVersion <= 0 {
		return "", Token{}, errors.New("an application token needs a credential version")
	}

	return s.issue(DeveloperApplicationAccess, applicationID, s.internalApplicationID, authEpoch, credentialVersion)
}

func (s *Signer) issue(
	class Class,
	subject, audience, authEpoch uuid.UUID,
	credentialVersion int64,
) (string, Token, error) {
	if authEpoch == uuid.Nil {
		return "", Token{}, errors.New("a token needs the authority epoch it is issued under")
	}

	policy, err := s.policyFor(class)
	if err != nil {
		return "", Token{}, err
	}

	identifier, err := uuid.NewRandom()
	if err != nil {
		return "", Token{}, fmt.Errorf("generating a token identifier: %w", err)
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
		return "", Token{}, fmt.Errorf("signing a token: %w", err)
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
