package servertest

import (
	"golang.org/x/crypto/bcrypt"

	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
)

// testHasher stores credentials at bcrypt's minimum work factor. Every service
// under test registers an application before it starts and the journeys
// register and authenticate more; at HashCost under the race detector that
// alone spends the suite's time budget, and nothing hashed here outlives the
// test's own database.
type testHasher struct{}

func (testHasher) Hash(secret string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

// Matches is credentials.Matches, so a pair is refused for the same reasons and
// a hash at any recorded factor still verifies.
func (testHasher) Matches(secret, hashed string) bool {
	return credentials.Matches(secret, hashed)
}
