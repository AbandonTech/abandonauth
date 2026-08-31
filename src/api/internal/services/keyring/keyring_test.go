package keyring_test

import (
	"bytes"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/keyring"
)

const root = "placeholder-signing-secret-placeholder-signing-secret-placeholder"

func newKeyring(t *testing.T, secret string) keyring.Keyring {
	t.Helper()

	keys, err := keyring.New(secret)
	if err != nil {
		t.Fatalf("deriving keys: %v", err)
	}

	return keys
}

func allKeys(keys keyring.Keyring) map[string][]byte {
	return map[string][]byte{
		"user access signing":      keys.UserAccessSigning(),
		"developer access signing": keys.DeveloperAccessSigning(),
		"verifier encryption":      keys.VerifierEncryption(),
		"rate limit pseudonym":     keys.RateLimitPseudonym(),
	}
}

func TestKeysHaveTheLengthTheirAlgorithmNeeds(t *testing.T) {
	t.Parallel()

	keys := newKeyring(t, root)

	lengths := map[string]int{
		"user access signing":      64,
		"developer access signing": 64,
		"verifier encryption":      32,
		"rate limit pseudonym":     32,
	}

	for name, key := range allKeys(keys) {
		if len(key) != lengths[name] {
			t.Errorf("%s key is %d bytes, want %d", name, len(key), lengths[name])
		}
	}
}

// A key that could be used for two purposes would let a value produced for one
// be accepted by the other.
func TestEachPurposeGetsADistinctKey(t *testing.T) {
	t.Parallel()

	seen := make(map[string]string)

	for name, key := range allKeys(newKeyring(t, root)) {
		encoded := string(key)
		if other, duplicate := seen[encoded]; duplicate {
			t.Errorf("%s and %s share a key", name, other)
		}

		seen[encoded] = name
	}
}

func TestDerivationIsDeterministic(t *testing.T) {
	t.Parallel()

	first := allKeys(newKeyring(t, root))
	second := allKeys(newKeyring(t, root))

	for name, key := range first {
		if !bytes.Equal(key, second[name]) {
			t.Errorf("%s key changed between derivations", name)
		}
	}
}

// Rotating the root secret is how a deployment withdraws every signed value it
// has issued, so every derived key has to change with it.
func TestChangingTheRootChangesEveryKey(t *testing.T) {
	t.Parallel()

	original := allKeys(newKeyring(t, root))
	rotated := allKeys(newKeyring(t, root+"-rotated"))

	for name, key := range original {
		if bytes.Equal(key, rotated[name]) {
			t.Errorf("%s key survived a change of the root secret", name)
		}
	}
}

func TestAnEmptyRootIsRefused(t *testing.T) {
	t.Parallel()

	if _, err := keyring.New(""); err == nil {
		t.Fatal("an empty root secret was accepted")
	}
}

// The keyring hands out copies, so a caller that writes into the slice it was
// given cannot change what the next caller signs with.
func TestCallersCannotOverwriteAStoredKey(t *testing.T) {
	t.Parallel()

	keys := newKeyring(t, root)

	handed := keys.UserAccessSigning()
	for index := range handed {
		handed[index] = 0
	}

	if bytes.Equal(keys.UserAccessSigning(), handed) {
		t.Fatal("writing into a handed-out key changed the keyring")
	}
}
