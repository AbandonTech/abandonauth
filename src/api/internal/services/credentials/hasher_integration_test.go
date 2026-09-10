//go:build integration

package credentials_test

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
)

// A service under test makes many credentials, none of which protect anything,
// so it hashes at the cheapest factor bcrypt has. It is still bcrypt and still
// refuses a secret it was not made from, so a journey that signs in proves what
// it proves in a deployment.
func TestTheInexpensiveHasherIsBcryptAtItsMinimumCost(t *testing.T) {
	t.Parallel()

	hasher := credentials.NewInexpensiveHasher()

	hashed, err := hasher.Hash("placeholder-secret")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hashed))
	if err != nil {
		t.Fatalf("the hash records no cost: %v", err)
	}

	if cost != bcrypt.MinCost {
		t.Errorf("cost = %d, want %d", cost, bcrypt.MinCost)
	}

	if !hasher.Matches("placeholder-secret", hashed) {
		t.Error("the hash does not accept the secret it was made from")
	}

	if hasher.Matches("placeholder-secre", hashed) {
		t.Error("the hash accepted a different secret")
	}
}
