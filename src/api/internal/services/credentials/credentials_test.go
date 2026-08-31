package credentials_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
)

// A hash of the word "placeholder" in the form the accounts table already
// holds: the $2b$ variant at cost 12. It is a hash of a value published here,
// so it protects nothing and reveals nothing.
const storedHashOfPlaceholder = "$2b$12$y1VEjPD3pK94NqbpzDZi9eKLEPpj6XMO5sykgHNASQbuVQsrPuxSC"

func TestAStoredHashStillAcceptsItsSecret(t *testing.T) {
	t.Parallel()

	if !credentials.Matches("placeholder", storedHashOfPlaceholder) {
		t.Error("a hash already in the accounts table no longer accepts its secret")
	}

	if credentials.Matches("Placeholder", storedHashOfPlaceholder) {
		t.Error("a stored hash accepted the wrong secret")
	}
}

func TestHashingProducesAValueThatOnlyItsSecretMatches(t *testing.T) {
	t.Parallel()

	hashed, err := credentials.Hash("placeholder-secret")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	if strings.Contains(hashed, "placeholder-secret") {
		t.Error("the hash contains the secret")
	}

	if !credentials.Matches("placeholder-secret", hashed) {
		t.Error("the hash does not accept the secret it was made from")
	}

	if credentials.Matches("placeholder-secre", hashed) {
		t.Error("the hash accepted a different secret")
	}
}

// Cost is what a hash costs an attacker who has the table. It is recorded in
// the hash itself, so it can be read back and must not silently fall.
func TestNewHashesUseTheConfiguredCost(t *testing.T) {
	t.Parallel()

	hashed, err := credentials.Hash("placeholder-secret")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	if want := "$2a$12$"; !strings.HasPrefix(hashed, want) {
		t.Errorf("hash prefix = %q, want %q", hashed[:min(len(hashed), len(want))], want)
	}
}

func TestTheSameSecretHashesDifferentlyEachTime(t *testing.T) {
	t.Parallel()

	first, err := credentials.Hash("placeholder-secret")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	second, err := credentials.Hash("placeholder-secret")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	if first == second {
		t.Error("two hashes of one secret are identical, so the salt is not random")
	}
}

func TestUnusableInputsAreRefusedWithoutRepeatingThem(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty":    "",
		"too long": strings.Repeat("x", credentials.MaxSecretBytes+1),
	}

	for name, secret := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := credentials.Hash(secret)
			if err == nil {
				t.Fatal("the secret was accepted")
			}

			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Error("the error repeats the secret")
			}
		})
	}
}

func TestMatchingRefusesAnythingThatIsNotAHashAndItsSecret(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		secret string
		hashed string
	}{
		"empty secret":     {"", storedHashOfPlaceholder},
		"empty hash":       {"placeholder", ""},
		"hash is not one":  {"placeholder", "placeholder"},
		"truncated hash":   {"placeholder", storedHashOfPlaceholder[:20]},
		"secret too long":  {strings.Repeat("x", credentials.MaxSecretBytes+1), storedHashOfPlaceholder},
		"secret is a hash": {storedHashOfPlaceholder, storedHashOfPlaceholder},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if credentials.Matches(test.secret, test.hashed) {
				t.Error("the pair was accepted")
			}
		})
	}
}

func TestOpaqueValuesAreUnguessableAndURLSafe(t *testing.T) {
	t.Parallel()

	const samples = 64

	seen := make(map[string]bool, samples)

	for range samples {
		value, err := credentials.NewOpaqueValue()
		if err != nil {
			t.Fatalf("generating a value: %v", err)
		}

		if seen[value] {
			t.Fatal("the same value was generated twice")
		}

		seen[value] = true

		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatalf("the value is not unpadded base64url: %v", err)
		}

		if len(decoded) != credentials.OpaqueValueBytes {
			t.Fatalf("the value carries %d bytes, want %d", len(decoded), credentials.OpaqueValueBytes)
		}
	}
}

// Every opaque value is stored as a digest, and the column it goes in demands
// exactly this width.
func TestDigestsAreThirtyTwoBytes(t *testing.T) {
	t.Parallel()

	digest := credentials.Digest(credentials.DomainBrowserSession, "placeholder")
	if len(digest) != credentials.DigestBytes {
		t.Fatalf("digest is %d bytes, want %d", len(digest), credentials.DigestBytes)
	}
}

// Without separation, a value observed as one kind of credential could be
// presented as another, because the stored digest would be the same.
func TestOneValueDigestsDifferentlyForEachPurpose(t *testing.T) {
	t.Parallel()

	domains := []credentials.Domain{
		credentials.DomainAuthorizationState,
		credentials.DomainBrowserBinding,
		credentials.DomainExchangeCode,
		credentials.DomainBrowserSession,
		credentials.DomainCSRFToken,
		credentials.DomainIdentityNonce,
	}

	seen := make(map[string]credentials.Domain, len(domains))

	for _, domain := range domains {
		digest := string(credentials.Digest(domain, "placeholder"))

		if other, duplicate := seen[digest]; duplicate {
			t.Errorf("%s and %s digest one value identically", domain, other)
		}

		seen[digest] = domain
	}
}

func TestDigestingIsDeterministicAndValueDependent(t *testing.T) {
	t.Parallel()

	first := credentials.Digest(credentials.DomainExchangeCode, "placeholder")
	again := credentials.Digest(credentials.DomainExchangeCode, "placeholder")
	other := credentials.Digest(credentials.DomainExchangeCode, "placeholder ")

	if !bytes.Equal(first, again) {
		t.Error("one value digested differently twice")
	}

	if bytes.Equal(first, other) {
		t.Error("two values share a digest")
	}
}

// The separator stops a domain and a value from running together, which would
// let one pair be spelled as another.
func TestADomainCannotBeSpelledAsPartOfTheValue(t *testing.T) {
	t.Parallel()

	first := credentials.Digest(credentials.Domain("a"), "bc")
	second := credentials.Digest(credentials.Domain("ab"), "c")

	if bytes.Equal(first, second) {
		t.Error("the domain and the value are not separated")
	}
}

func TestEqualComparesWholeValues(t *testing.T) {
	t.Parallel()

	digest := credentials.Digest(credentials.DomainCSRFToken, "placeholder")

	if !credentials.Equal(digest, credentials.Digest(credentials.DomainCSRFToken, "placeholder")) {
		t.Error("two digests of one value did not compare equal")
	}

	if credentials.Equal(digest, digest[:len(digest)-1]) {
		t.Error("a prefix compared equal to the whole digest")
	}

	if credentials.Equal(nil, nil) {
		t.Error("two absent values compared equal, which would accept a missing credential")
	}
}
