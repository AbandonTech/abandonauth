// Package tokens issues and verifies the access tokens this service signs.
//
// An access token authenticates its principal for fifteen minutes and
// authorizes nothing beyond its scope. Its header and claims state its class,
// signing key ID, subject, audience and auth epoch; verification checks every
// one of them, and neither the algorithm nor the key is selected by the token.
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

// Class is the principal type an access token authenticates. A token of one
// class is never accepted where the other is expected, because the two are
// signed with different keys and carry their class in the token_type claim.
type Class string

// The classes of token this service issues.
const (
	// UserAccess authenticates a user to the application in its audience claim.
	UserAccess Class = "user_access"
	// DeveloperApplicationAccess authenticates a developer application as the
	// principal.
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
	// ScopeIdentify authorizes reading the authenticated principal's identity.
	ScopeIdentify = "identify"
	// ScopeAbandonauth permits managing the caller's developer applications.
	ScopeAbandonauth = "abandonauth"
)

// signingMethod is stated rather than read from the token, so a token can never
// select how it is verified.
var signingMethod = jwt.SigningMethodHS512

// lifespan is the only accepted value of the lifespan claim. One-time exchange
// codes are opaque values rather than JWTs, so any other lifespan is refused.
const lifespan = "long"

// Reasons a token is not accepted. Verify returns ErrExpired alone or wraps
// ErrInvalid with one package-owned reason; a caller answering a request maps
// both to the same refusal unless it reports expiry separately.
var (
	ErrInvalid = errors.New("invalid token")
	ErrExpired = errors.New("expired token")
)

// Token holds the verified claims of an access token.
type Token struct {
	Class    Class
	Subject  uuid.UUID
	Audience uuid.UUID

	// Scopes are the exact entries of the scope claim, in claim order.
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

// classPolicy is the one shape a class of token has: its signing key, and the
// claim values it requires.
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
		return nil, errors.New("missing issuer")
	}

	if options.InternalApplicationID == uuid.Nil {
		return nil, errors.New("missing internal application ID")
	}

	userKey := options.Keys.UserAccessSigning()
	developerKey := options.Keys.DeveloperAccessSigning()

	if len(userKey) == 0 || len(developerKey) == 0 {
		return nil, errors.New("missing signing key")
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
		return classPolicy{}, errors.New("unknown token class")
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

// scopesFor is the one scope list a class carries for an audience. A user token
// for the site authorizes application management; a user token for any other
// audience authorizes identification only; a developer application token
// authorizes both.
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
