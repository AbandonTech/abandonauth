// Package tokens issues and verifies the access tokens this service signs.
//
// A token proves who is calling for the next fifteen minutes and nothing more.
// It says which class it belongs to, which key signed it, who it was issued
// for, which application may present it, and under which authority epoch it was
// made; every one of those is checked on the way back in, and none of them is
// taken from the token's own choice of algorithm or key.
//
// Each class has exactly one shape: one key, one key identifier, one scope
// string for a given audience, one rule for its audience and one for its
// credential version, and a validity interval of exactly the access lifetime.
// A token is accepted only when it is that shape in full, so a token this
// service could not have issued is refused however it was signed.
//
// What this package cannot decide is whether the authority behind a valid token
// still stands: whether the epoch is current, whether the token has been
// withdrawn, and whether the principal still exists. Those are database
// questions and belong to the caller.
package tokens

import (
	"errors"
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
	classes               map[Class]classPolicy
	now                   func() time.Time
}

// classPolicy is the one shape a class of token has: what signs it, and what
// its claims must say.
type classPolicy struct {
	keyID string
	key   []byte

	// internalAudience requires the audience to be the AbandonAuth site.
	internalAudience bool

	// credentialVersion requires a positive credential version; without it the
	// claim must be absent.
	credentialVersion bool
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
		classes: map[Class]classPolicy{
			UserAccess: {keyID: UserAccessKeyID, key: userKey},
			DeveloperApplicationAccess: {
				keyID:             DeveloperAccessKeyID,
				key:               developerKey,
				internalAudience:  true,
				credentialVersion: true,
			},
		},
		now: now,
	}, nil
}

// policyFor returns the shape of a class, and refuses a class that has none:
// there is no key to sign or verify it with.
func (s *Signer) policyFor(class Class) (classPolicy, error) {
	policy, known := s.classes[class]
	if !known {
		return classPolicy{}, errors.New("there is no such class of token")
	}

	return policy, nil
}

// classForKeyID returns the class a key identifier signs, and refuses one this
// service does not sign with.
func (s *Signer) classForKeyID(keyID string) (Class, bool) {
	for class, policy := range s.classes {
		if policy.keyID == keyID {
			return class, true
		}
	}

	return "", false
}

// scopesFor is the one scope list a class carries for an audience. The site
// itself needs to manage applications; an application acting for a person only
// needs to identify them; an application acting for itself gets both.
func (s *Signer) scopesFor(class Class, audience uuid.UUID) []string {
	if class == DeveloperApplicationAccess || audience == s.internalApplicationID {
		return []string{ScopeAbandonauth, ScopeIdentify}
	}

	return []string{ScopeIdentify}
}

func seconds(at time.Time) *int64 {
	value := at.Unix()

	return &value
}

func timeFromSeconds(value int64) time.Time {
	return time.Unix(value, 0).UTC()
}
