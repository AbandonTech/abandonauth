// Package credentials creates and checks the secret values this service holds.
//
// Nothing here keeps a secret in a form it can be read back from. A password or
// an application's refresh token is stored as a bcrypt hash; a one-time code, a
// session and a CSRF token are stored as a digest under a label that says what
// they are for. Errors name the operation that failed and never the value.
package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashCost is the bcrypt work factor new hashes are made with. Raising it makes
// every stored hash more expensive to attack and every sign-in slower; hashes
// already stored keep the cost they were made with and still verify.
const HashCost = 12

// MaxSecretBytes is the longest secret bcrypt reads. It ignores everything past
// this length, so a longer value is refused rather than silently truncated to a
// prefix an attacker could guess instead.
const MaxSecretBytes = 72

// OpaqueValueBytes is the randomness in a value handed to a client. It is the
// full width of the digest the value is stored as, so guessing the value is no
// easier than guessing the digest.
const OpaqueValueBytes = 32

// DigestBytes is the width of a stored digest, which the columns holding them
// require exactly.
const DigestBytes = sha256.Size

// Reasons a secret cannot be used.
var (
	ErrEmptySecret   = errors.New("the secret is empty")
	ErrSecretTooLong = fmt.Errorf("the secret is longer than %d bytes", MaxSecretBytes)
)

// Domain says what a value is for. Digesting under a label keeps a value
// obtained as one kind of credential from being presented as another, because
// the digests do not match.
type Domain string

// The purposes a value can be digested for.
const (
	DomainAuthorizationState Domain = "abandonauth/oauth-state/v1"
	DomainBrowserBinding     Domain = "abandonauth/oauth-browser-binding/v1"
	DomainExchangeCode       Domain = "abandonauth/exchange-code/v1"
	DomainBrowserSession     Domain = "abandonauth/browser-session/v1"
	DomainCSRFToken          Domain = "abandonauth/csrf-token/v1"
	DomainIdentityNonce      Domain = "abandonauth/identity-token-nonce/v1"
)

// domainSeparator ends the label so that a long label and a short value cannot
// be spelled as a short label and a long value.
const domainSeparator = 0x00

// Hash returns the value a secret is stored as: bcrypt at HashCost. There is
// no other work factor a caller can choose.
func Hash(secret string) (string, error) {
	if secret == "" {
		return "", ErrEmptySecret
	}

	if len(secret) > MaxSecretBytes {
		return "", ErrSecretTooLong
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), HashCost)
	if err != nil {
		return "", fmt.Errorf("hashing a secret: %w", err)
	}

	return string(hashed), nil
}

// Matches reports whether a secret is the one a stored hash was made from.
//
// Every way of failing returns the same answer, so a caller cannot learn from
// it whether the stored value was a hash at all. The cost is the one recorded
// in the stored hash, so a hash made at another factor still verifies.
func Matches(secret, hashed string) bool {
	if secret == "" || hashed == "" || len(secret) > MaxSecretBytes {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(secret)) == nil
}

// NewOpaqueValue returns a fresh value to hand to a client.
func NewOpaqueValue() (string, error) {
	value := make([]byte, OpaqueValueBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generating a credential: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(value), nil
}

// Digest returns what a value is stored as when it is used for one purpose.
func Digest(domain Domain, value string) []byte {
	digest := sha256.New()
	digest.Write([]byte(domain))
	digest.Write([]byte{domainSeparator})
	digest.Write([]byte(value))

	return digest.Sum(nil)
}

// Equal reports whether two digests are the same, in time that does not depend
// on where they first differ.
//
// Two absent values are not equal: a lookup that returned nothing must not be
// able to satisfy a check by matching another nothing.
func Equal(first, second []byte) bool {
	if len(first) == 0 || len(second) == 0 {
		return false
	}

	return subtle.ConstantTimeCompare(first, second) == 1
}
