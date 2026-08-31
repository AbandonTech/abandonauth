// Package tokens issues and verifies the access tokens this service signs.
//
// A token proves who is calling for the next fifteen minutes and nothing more.
// It says which class it belongs to, which key signed it, who it was issued
// for, which application may present it, and under which authority epoch it was
// made; every one of those is checked on the way back in, and none of them is
// taken from the token's own choice of algorithm or key.
//
// What this package cannot decide is whether the authority behind a valid token
// still stands: whether the epoch is current, whether the token has been
// withdrawn, and whether the principal still exists. Those are database
// questions and belong to the caller.
package tokens

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/keyring"
)

// Class says what kind of principal a token speaks for. A token of one class is
// never accepted where the other is expected, because the two are signed with
// different keys and name their class explicitly.
type Class string

// The classes of token this service issues.
const (
	// UserAccess speaks for a person, to the application named in its audience.
	UserAccess Class = "user_access"
	// DeveloperApplicationAccess speaks for a developer application itself.
	DeveloperApplicationAccess Class = "developer_application_access"
)

// Key identifiers, written into every token's header and required on the way
// back in so that a token cannot be verified with the other class's key.
const (
	UserAccessKeyID      = "abandonauth-user-hs512-v1"
	DeveloperAccessKeyID = "abandonauth-developer-hs512-v1"
)

// AccessLifetime is how long a token is good for. It is fixed rather than
// configurable: a token cannot be withdrawn from the client that holds it, so
// its lifetime is the longest a withdrawal can take to have effect.
const AccessLifetime = 900 * time.Second

// MaxClockSkew is how far apart the clock that issued a token and the clock
// verifying it may be.
const MaxClockSkew = 30 * time.Second

// Scopes a token can carry.
const (
	// ScopeIdentify permits reading who the token speaks for.
	ScopeIdentify = "identify"
	// ScopeAbandonauth permits managing the caller's developer applications.
	ScopeAbandonauth = "abandonauth"
)

// signingMethod is stated rather than read from the token, so a token can never
// select how it is verified.
var signingMethod = jwt.SigningMethodHS512

// lifespan is the only accepted value of the lifespan claim. Values handed to a
// client for a single exchange are opaque and are not tokens, so a token that
// claims to be one of those is refused.
const lifespan = "long"

// Reasons a token is not accepted. Verify wraps one of them, and a caller that
// answers a request maps both to the same refusal unless it means to tell a
// client that its token has simply aged out.
var (
	ErrInvalid = errors.New("the token is not valid")
	ErrExpired = errors.New("the token has expired")
)

// Token is what a verified token says.
type Token struct {
	Class    Class
	Subject  uuid.UUID
	Audience uuid.UUID

	// Scopes are the exact words the token carries, in the order it carries
	// them.
	Scopes []string

	// AuthEpoch is the authority the token was issued under. A caller compares
	// it against the epoch the database holds now.
	AuthEpoch uuid.UUID

	// ID identifies the token so it can be withdrawn before it expires.
	ID uuid.UUID

	// CredentialVersion is the version of the application's refresh token this
	// token was issued against, and is zero for a token issued to a person.
	CredentialVersion int64

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// HasScope reports whether the token carries a scope, compared as a whole word.
func (t Token) HasScope(scope string) bool {
	if scope == "" {
		return false
	}

	for _, carried := range t.Scopes {
		if carried == scope {
			return true
		}
	}

	return false
}

// Options are what a signer needs to issue and verify tokens.
type Options struct {
	// Issuer is the origin this service is reached at, written into every token
	// and required to match on the way back in.
	Issuer string

	// InternalApplicationID is the developer application that represents the
	// AbandonAuth site. It is the audience of every application token and
	// decides how much scope a person's token carries.
	InternalApplicationID uuid.UUID

	Keys keyring.Keyring

	// Now is the clock, so a test can place a token before, inside or after its
	// validity. It defaults to the wall clock.
	Now func() time.Time
}

// Signer issues and verifies tokens.
type Signer struct {
	issuer                string
	internalApplicationID uuid.UUID
	userKey               []byte
	developerKey          []byte
	now                   func() time.Time
}

// NewSigner builds the signer from the keys and identity of the service.
func NewSigner(options Options) (*Signer, error) {
	if options.Issuer == "" {
		return nil, errors.New("tokens need an issuer")
	}

	if options.InternalApplicationID == uuid.Nil {
		return nil, errors.New("tokens need the internal application to be identified")
	}

	userKey := options.Keys.UserAccessSigning()
	developerKey := options.Keys.DeveloperAccessSigning()

	if len(userKey) == 0 || len(developerKey) == 0 {
		return nil, errors.New("tokens need signing keys")
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}

	return &Signer{
		issuer:                options.Issuer,
		internalApplicationID: options.InternalApplicationID,
		userKey:               userKey,
		developerKey:          developerKey,
		now:                   now,
	}, nil
}

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

	scopes := []string{ScopeIdentify}
	if audience == s.internalApplicationID {
		scopes = []string{ScopeAbandonauth, ScopeIdentify}
	}

	return s.issue(UserAccess, subject, audience, authEpoch, scopes, 0)
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

	return s.issue(
		DeveloperApplicationAccess,
		applicationID,
		s.internalApplicationID,
		authEpoch,
		[]string{ScopeAbandonauth, ScopeIdentify},
		credentialVersion,
	)
}

func (s *Signer) issue(
	class Class,
	subject, audience, authEpoch uuid.UUID,
	scopes []string,
	credentialVersion int64,
) (string, Token, error) {
	if authEpoch == uuid.Nil {
		return "", Token{}, errors.New("a token needs the authority epoch it is issued under")
	}

	identifier, err := uuid.NewRandom()
	if err != nil {
		return "", Token{}, fmt.Errorf("generating a token identifier: %w", err)
	}

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

	if credentialVersion > 0 {
		body.CredentialVersion = &credentialVersion
	}

	signed := jwt.NewWithClaims(signingMethod, body)
	signed.Header["kid"] = keyIDFor(class)

	key, err := s.keyFor(class)
	if err != nil {
		return "", Token{}, err
	}

	raw, err := signed.SignedString(key)
	if err != nil {
		return "", Token{}, fmt.Errorf("signing a token: %w", err)
	}

	return raw, Token{
		Class:             class,
		Subject:           subject,
		Audience:          audience,
		Scopes:            scopes,
		AuthEpoch:         authEpoch,
		ID:                identifier,
		CredentialVersion: credentialVersion,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
	}, nil
}

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

		switch identifier {
		case UserAccessKeyID:
			class = UserAccess
		case DeveloperAccessKeyID:
			class = DeveloperApplicationAccess
		default:
			return nil, errors.New("the token names a key this service does not sign with")
		}

		return s.keyFor(class)
	})
	if err != nil {
		return Token{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}

	return s.verifyClaims(body, class)
}

func (s *Signer) verifyClaims(body claims, class Class) (Token, error) {
	if body.TokenType != string(class) {
		return Token{}, fmt.Errorf("%w: its class does not match the key that signed it", ErrInvalid)
	}

	if body.Issuer != s.issuer {
		return Token{}, fmt.Errorf("%w: it was not issued by this service", ErrInvalid)
	}

	if body.Lifespan != lifespan {
		return Token{}, fmt.Errorf("%w: it does not carry the lifespan of an access token", ErrInvalid)
	}

	if body.Subject == "" || body.Subject != body.UserID {
		return Token{}, fmt.Errorf("%w: it does not agree on who it speaks for", ErrInvalid)
	}

	subject, err := uuid.Parse(body.Subject)
	if err != nil {
		return Token{}, fmt.Errorf("%w: the subject is not an identifier", ErrInvalid)
	}

	audience, err := uuid.Parse(body.Audience)
	if err != nil {
		return Token{}, fmt.Errorf("%w: the audience is not an application", ErrInvalid)
	}

	authEpoch, err := uuid.Parse(body.AuthEpoch)
	if err != nil {
		return Token{}, fmt.Errorf("%w: the authority epoch is not an identifier", ErrInvalid)
	}

	identifier, err := uuid.Parse(body.TokenID)
	if err != nil {
		return Token{}, fmt.Errorf("%w: it cannot be identified, so it could not be withdrawn", ErrInvalid)
	}

	if body.Scope == "" {
		return Token{}, fmt.Errorf("%w: it carries no scope", ErrInvalid)
	}

	version, err := credentialVersionOf(body, class)
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
		Scopes:            strings.Fields(body.Scope),
		AuthEpoch:         authEpoch,
		ID:                identifier,
		CredentialVersion: version,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
	}, nil
}

// verifyValidity checks that the token is inside its own window, that the
// window is no longer than an access token is allowed to live, and that it was
// not issued in the future.
func (s *Signer) verifyValidity(body claims) (time.Time, time.Time, error) {
	if body.IssuedAt == nil || body.NotBefore == nil || body.ExpiresAt == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it does not say when it is valid", ErrInvalid)
	}

	issuedAt := time.Unix(*body.IssuedAt, 0).UTC()
	notBefore := time.Unix(*body.NotBefore, 0).UTC()
	expiresAt := time.Unix(*body.ExpiresAt, 0).UTC()

	if expiresAt.Sub(issuedAt) > AccessLifetime {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"%w: it claims to live longer than an access token may", ErrInvalid,
		)
	}

	now := s.now().UTC()

	if now.After(expiresAt.Add(MaxClockSkew)) {
		return time.Time{}, time.Time{}, ErrExpired
	}

	if now.Before(notBefore.Add(-MaxClockSkew)) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it is not valid yet", ErrInvalid)
	}

	if now.Before(issuedAt.Add(-MaxClockSkew)) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it was issued in the future", ErrInvalid)
	}

	return issuedAt, expiresAt, nil
}

// credentialVersionOf reads the version an application token was issued
// against, and refuses a token of the other class that carries one: it would
// otherwise be a token about an application dressed as a person.
func credentialVersionOf(body claims, class Class) (int64, error) {
	if class != DeveloperApplicationAccess {
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

func (s *Signer) keyFor(class Class) ([]byte, error) {
	switch class {
	case UserAccess:
		return s.userKey, nil
	case DeveloperApplicationAccess:
		return s.developerKey, nil
	default:
		return nil, errors.New("there is no key for this class of token")
	}
}

func keyIDFor(class Class) string {
	if class == DeveloperApplicationAccess {
		return DeveloperAccessKeyID
	}

	return UserAccessKeyID
}

func seconds(at time.Time) *int64 {
	value := at.Unix()

	return &value
}

func timeFromSeconds(value int64) time.Time {
	return time.Unix(value, 0).UTC()
}
