package servertest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
)

// SigningKeySettings are the two signing key files a test wrote at run time.
// No key is checked in.
type SigningKeySettings struct {
	IDTokenFile        string
	AccessTokenFile    string
	IDTokenPEM         []byte
	AccessTokenPEM     []byte
	IDTokenPrivate     *rsa.PrivateKey
	AccessTokenPrivate *rsa.PrivateKey
}

// signingKeyMaterial is generated once per test binary: a key per purpose is
// slow to make and protects nothing, so every test shares the same two.
var signingKeyMaterial = sync.OnceValues(func() (SigningKeySettings, error) {
	idToken, err := rsa.GenerateKey(rand.Reader, oidc.MinModulusBits)
	if err != nil {
		return SigningKeySettings{}, err
	}

	accessToken, err := rsa.GenerateKey(rand.Reader, oidc.MinModulusBits)
	if err != nil {
		return SigningKeySettings{}, err
	}

	idTokenPEM, err := pkcs8PEM(idToken)
	if err != nil {
		return SigningKeySettings{}, err
	}

	accessTokenPEM, err := pkcs8PEM(accessToken)
	if err != nil {
		return SigningKeySettings{}, err
	}

	return SigningKeySettings{
		IDTokenPEM:         idTokenPEM,
		AccessTokenPEM:     accessTokenPEM,
		IDTokenPrivate:     idToken,
		AccessTokenPrivate: accessToken,
	}, nil
})

func pkcs8PEM(key *rsa.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

// SigningKeyFiles writes the shared test keys to files in a directory the test
// owns, which is removed when it ends.
func SigningKeyFiles(t testing.TB) SigningKeySettings {
	t.Helper()

	material, err := signingKeyMaterial()
	if err != nil {
		t.Fatalf("generating the test signing keys: %v", err)
	}

	directory := t.TempDir()
	material.IDTokenFile = filepath.Join(directory, "oidc-id-signing-key.pem")
	material.AccessTokenFile = filepath.Join(directory, "oauth-access-signing-key.pem")

	for path, contents := range map[string][]byte{
		material.IDTokenFile:     material.IDTokenPEM,
		material.AccessTokenFile: material.AccessTokenPEM,
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("writing a test signing key file: %v", err)
		}
	}

	return material
}

// IDTokenKeyID is the ID token key's RFC 7638 thumbprint.
func (s SigningKeySettings) IDTokenKeyID() string { return keyID(s.IDTokenPrivate) }

// AccessTokenKeyID is the access token key's RFC 7638 thumbprint.
func (s SigningKeySettings) AccessTokenKeyID() string { return keyID(s.AccessTokenPrivate) }

func keyID(key *rsa.PrivateKey) string {
	return oidc.Thumbprint(
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	)
}

// Apply puts the two key file paths into settings.
func (s SigningKeySettings) Apply(settings *config.Settings) {
	settings.IDTokenSigningKeysFile = s.IDTokenFile
	settings.AccessTokenSigningKeysFile = s.AccessTokenFile
}
