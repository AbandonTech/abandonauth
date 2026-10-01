// Package keyring derives the keys this service works with from the single root
// secret a deployment configures.
//
// One root secret is easy to store and to rotate, but using it directly for
// signing, encryption and pseudonymisation would let a value produced for one
// purpose be accepted by another. Each purpose therefore gets its own key,
// derived under a label that names it, and no key can be computed from another.
package keyring

import (
	"crypto/hkdf"
	"crypto/sha512"
	"errors"
	"fmt"
	"slices"
)

// Labels that separate the derived keys. Changing one withdraws every value
// produced under it, so they carry a version and are never reused.
const (
	labelUserAccessSigning      = "abandonauth/user-access/v1"
	labelDeveloperAccessSigning = "abandonauth/developer-application-access/v1"
	labelVerifierEncryption     = "abandonauth/oauth-verifier-encryption/v1"
	labelRateLimitPseudonym     = "abandonauth/rate-limit-key/v1"
)

// Key lengths, each set by the algorithm that consumes the key.
const (
	signingKeyBytes    = 64
	encryptionKeyBytes = 32
	pseudonymKeyBytes  = 32
)

// ErrNoRootSecret reports that nothing was given to derive keys from.
var ErrNoRootSecret = errors.New("the root secret is empty")

// Keyring holds the derived keys of one running service.
type Keyring struct {
	userAccessSigning      []byte
	developerAccessSigning []byte
	verifierEncryption     []byte
	rateLimitPseudonym     []byte
}

// New derives the keys from a root secret.
func New(rootSecret string) (Keyring, error) {
	if rootSecret == "" {
		return Keyring{}, ErrNoRootSecret
	}

	root := []byte(rootSecret)

	userAccess, err := derive(root, labelUserAccessSigning, signingKeyBytes)
	if err != nil {
		return Keyring{}, err
	}

	developerAccess, err := derive(root, labelDeveloperAccessSigning, signingKeyBytes)
	if err != nil {
		return Keyring{}, err
	}

	verifier, err := derive(root, labelVerifierEncryption, encryptionKeyBytes)
	if err != nil {
		return Keyring{}, err
	}

	pseudonym, err := derive(root, labelRateLimitPseudonym, pseudonymKeyBytes)
	if err != nil {
		return Keyring{}, err
	}

	return Keyring{
		userAccessSigning:      userAccess,
		developerAccessSigning: developerAccess,
		verifierEncryption:     verifier,
		rateLimitPseudonym:     pseudonym,
	}, nil
}

// UserAccessSigning returns the key that signs and verifies access tokens
// issued to a person.
func (k Keyring) UserAccessSigning() []byte {
	return slices.Clone(k.userAccessSigning)
}

// DeveloperAccessSigning returns the key that signs and verifies access tokens
// issued to a developer application.
func (k Keyring) DeveloperAccessSigning() []byte {
	return slices.Clone(k.developerAccessSigning)
}

// VerifierEncryption returns the key that encrypts the proof a login in
// progress holds until the provider returns.
func (k Keyring) VerifierEncryption() []byte {
	return slices.Clone(k.verifierEncryption)
}

// RateLimitPseudonym returns the key that turns a client address into the
// counted identifier, so no address is stored.
func (k Keyring) RateLimitPseudonym() []byte {
	return slices.Clone(k.rateLimitPseudonym)
}

func derive(root []byte, label string, length int) ([]byte, error) {
	key, err := hkdf.Key(sha512.New, root, nil, label, length)
	if err != nil {
		// The label and length are constants, so this cannot depend on request
		// input; it is reported rather than ignored because a key of the wrong
		// length must never be used.
		return nil, fmt.Errorf("deriving a key: %w", err)
	}

	return key, nil
}
