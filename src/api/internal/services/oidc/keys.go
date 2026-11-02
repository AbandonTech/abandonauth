// Package oidc signs and checks the tokens a public client receives: ID
// tokens, which identify a person to the client, and RFC 9068 access tokens,
// which a resource server validates locally.
//
// The two classes are signed by separate RSA keys whose public halves are
// published as separate key sets, so a key from one set never verifies a token
// of the other class, and neither key has anything to do with the HS512 keys
// behind this service's other tokens. Errors name the rule a value broke and
// never repeat the value.
package oidc

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// Limits on the signing key files. They are protocol constants, not settings.
const (
	// MaxKeyFileBytes is the largest key file accepted, several times a
	// 4096-bit key's PEM.
	MaxKeyFileBytes = 16384
	// MinModulusBits is the shortest RSA modulus accepted.
	MinModulusBits = 2048
)

// Reasons a signing key file is refused.
var (
	ErrKeyFileTooLarge  = fmt.Errorf("is larger than %d bytes", MaxKeyFileBytes)
	ErrKeyFileMalformed = errors.New("is not exactly one PEM PRIVATE KEY block")
	ErrKeyType          = errors.New("does not hold a PKCS #8 RSA private key")
	ErrKeyTooWeak       = fmt.Errorf("holds a key whose modulus is shorter than %d bits", MinModulusBits)
	ErrKeyShared        = errors.New("holds the same key as the ID token key file")
)

const (
	keyTypeRSA   = "RSA"
	keyUse       = "sig"
	keyAlgorithm = "RS256"
	pemBlockType = "PRIVATE KEY"
)

// rsaKey is a signing key and the identifier it is published under.
type rsaKey struct {
	id      string
	n       string
	e       string
	public  *rsa.PublicKey
	private *rsa.PrivateKey
}

// KeyRing is one purpose's key and its published public half.
type KeyRing struct {
	active    rsaKey
	published []byte
}

// SigningKeys are the two purposes' rings. Neither ring's key verifies the
// other purpose's tokens.
type SigningKeys struct {
	idToken     KeyRing
	accessToken KeyRing
}

// redactedKeys is how key sets render, so a configuration printed in an error
// or a log line carries no key.
const redactedKeys = "[signing keys]"

// String renders no key.
func (k SigningKeys) String() string { return redactedKeys }

// GoString renders no key.
func (k SigningKeys) GoString() string { return redactedKeys }

// String renders no key.
func (r KeyRing) String() string { return redactedKeys }

// GoString renders no key.
func (r KeyRing) GoString() string { return redactedKeys }

// IDToken is the ring ID tokens are signed and published with.
func (k SigningKeys) IDToken() KeyRing { return k.idToken }

// AccessToken is the ring access tokens are signed and published with.
func (k SigningKeys) AccessToken() KeyRing { return k.accessToken }

// ActiveKeyID names the key that signs, the RFC 7638 thumbprint of its public
// half.
func (r KeyRing) ActiveKeyID() string { return r.active.id }

// publishedKey is a key as a key set publishes it.
type publishedKey struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

// PublicJWKSet is the ring's public key as a JSON Web Key Set, with exactly the
// members a validator needs and no private member.
func (r KeyRing) PublicJWKSet() []byte {
	return bytes.Clone(r.published)
}

func publishKey(key rsaKey) ([]byte, error) {
	published, err := json.Marshal(struct {
		Keys []publishedKey `json:"keys"`
	}{[]publishedKey{{
		KeyID: key.id, KeyType: keyTypeRSA, Use: keyUse, Algorithm: keyAlgorithm, Modulus: key.n, Exponent: key.e,
	}}})
	if err != nil {
		return nil, fmt.Errorf("encoding a public key set: %w", err)
	}

	return published, nil
}

// verificationKey returns the public key a key identifier names in this ring.
func (r KeyRing) verificationKey(id string) (*rsa.PublicKey, bool) {
	if r.active.public == nil || id != r.active.id {
		return nil, false
	}

	return r.active.public, true
}

// ParseSigningKeys reads the two purposes' key files, each one PKCS #8 PEM
// block holding an RSA private key of at least 2048 bits, as `openssl genpkey`
// writes it. The two purposes must not share a key.
func ParseSigningKeys(idTokenFile, accessTokenFile []byte) (SigningKeys, error) {
	idToken, err := parseKeyRing(idTokenFile)
	if err != nil {
		return SigningKeys{}, fmt.Errorf("the ID token key file %w", err)
	}

	accessToken, err := parseKeyRing(accessTokenFile)
	if err != nil {
		return SigningKeys{}, fmt.Errorf("the access token key file %w", err)
	}

	if idToken.active.id == accessToken.active.id {
		return SigningKeys{}, fmt.Errorf("the access token key file %w", ErrKeyShared)
	}

	return SigningKeys{idToken: idToken, accessToken: accessToken}, nil
}

func parseKeyRing(file []byte) (KeyRing, error) {
	if len(file) > MaxKeyFileBytes {
		return KeyRing{}, ErrKeyFileTooLarge
	}

	block, rest := pem.Decode(file)
	if block == nil || block.Type != pemBlockType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return KeyRing{}, ErrKeyFileMalformed
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)

	if err != nil {
		return KeyRing{}, ErrKeyType
	}

	private, isRSA := parsed.(*rsa.PrivateKey)
	if !isRSA {
		return KeyRing{}, ErrKeyType
	}

	if private.N.BitLen() < MinModulusBits {
		return KeyRing{}, ErrKeyTooWeak
	}

	modulus := encodeUint(private.N)
	exponent := encodeUint(big.NewInt(int64(private.E)))

	key := rsaKey{
		id: Thumbprint(modulus, exponent), n: modulus, e: exponent, public: &private.PublicKey, private: private,
	}

	published, err := publishKey(key)
	if err != nil {
		return KeyRing{}, err
	}

	return KeyRing{active: key, published: published}, nil
}

// Thumbprint is the RFC 7638 thumbprint of an RSA key's public members, as
// unpadded base64url.
func Thumbprint(encodedModulus, encodedExponent string) string {
	canonical := `{"e":"` + encodedExponent + `","kty":"RSA","n":"` + encodedModulus + `"}`
	digest := sha256.Sum256([]byte(canonical))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func encodeUint(value *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(value.Bytes())
}
