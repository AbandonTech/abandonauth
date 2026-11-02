package credentials_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
)

// A hash of the word "placeholder" in the form the accounts table already
// holds: the $2b$ variant at cost 12. It is a hash of a value published here,
// so it protects nothing and reveals nothing.
const storedHashOfPlaceholder = "$2b$12$y1VEjPD3pK94NqbpzDZi9eKLEPpj6XMO5sykgHNASQbuVQsrPuxSC"

func TestStoredHashStillAcceptsItsSecret(t *testing.T) {
	t.Parallel()

	if !credentials.Matches("placeholder", storedHashOfPlaceholder) {
		t.Error("a hash already in the accounts table no longer accepts its secret")
	}

	if credentials.Matches("Placeholder", storedHashOfPlaceholder) {
		t.Error("a stored hash accepted the wrong secret")
	}
}

func TestHashingProducesValueThatOnlyItsSecretMatches(t *testing.T) {
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
// the hash itself, so it can be read back and must not silently fall to
// bcrypt's own default, a factor nobody chose.
func TestHashingRecordsConfiguredCost(t *testing.T) {
	t.Parallel()

	hashed, err := credentials.Hash("placeholder-secret")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hashed))
	if err != nil {
		t.Fatalf("the hash records no cost: %v", err)
	}

	if cost != credentials.HashCost {
		t.Errorf("cost = %d, want %d", cost, credentials.HashCost)
	}
}

func TestSameSecretHashesDifferentlyEachTime(t *testing.T) {
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

func TestMatchingRefusesAnythingThatIsNotHashAndItsSecret(t *testing.T) {
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
func TestDomainCannotBeSpelledAsPartOfValue(t *testing.T) {
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

// Only a value with the exact shape this service hands out reaches a digest or
// a lookup; everything else is refused before either.
func TestOnlyOpaqueValuesOfIssuedShapeAreRecognised(t *testing.T) {
	t.Parallel()

	issued, err := credentials.NewOpaqueValue()
	if err != nil {
		t.Fatalf("generating a value: %v", err)
	}

	if !credentials.IsOpaqueValue(issued) {
		t.Fatal("an issued value is not recognised, so the refusals below prove nothing")
	}

	// The last of 43 characters carries two bits that must be zero; B sets one.
	trailingBits := issued[:42] + "B"

	for name, value := range map[string]string{
		"empty":                  "",
		"one character":          "A",
		"42 characters":          issued[:42],
		"44 characters":          issued + "A",
		"padded":                 issued[:42] + "=",
		"non-zero trailing bits": trailingBits,
		"standard base64":        "+" + issued[1:],
		"a slash":                "/" + issued[1:],
		"whitespace":             " " + issued[1:],
		"a control character":    "\x00" + issued[1:],
		"unicode":                "é" + issued[2:],
		"a URL delimiter":        "?" + issued[1:],
		"SQL text":               "'; DROP TABLE x; --" + issued[19:],
		"a JWT-looking value":    "eyJ" + issued[3:42] + ".",
		"a large body":           strings.Repeat(issued, 100),
	} {
		if credentials.IsOpaqueValue(value) {
			t.Errorf("%s was recognised", name)
		}
	}
}

func TestDigestDomainsAreDistinct(t *testing.T) {
	t.Parallel()

	domains := []credentials.Domain{
		credentials.DomainAuthorizationState, credentials.DomainBrowserBinding, credentials.DomainExchangeCode,
		credentials.DomainBrowserSession, credentials.DomainCSRFToken, credentials.DomainIdentityNonce,
		credentials.DomainAuthorizationPage, credentials.DomainNativeBrowserBinding,
		credentials.DomainNativeAuthorizationCode, credentials.DomainRefreshToken,
	}

	seen := make(map[string]credentials.Domain, len(domains))

	for _, domain := range domains {
		digest := string(credentials.Digest(domain, "one value"))
		if earlier, repeated := seen[digest]; repeated {
			t.Errorf("%s and %s digest a value alike", earlier, domain)
		}

		seen[digest] = domain
	}
}
