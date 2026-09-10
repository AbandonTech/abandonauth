//go:build integration

package servertest

import "github.com/abandontech/abandonauth/src/api/internal/services/credentials"

// testCredentialHasher is the cheapest factor bcrypt has. A service under test
// stores several credentials before a journey reaches the endpoint it is about,
// and at the deployed factor that alone spends the suite's whole budget.
func testCredentialHasher() credentials.Hasher {
	return credentials.NewInexpensiveHasher()
}
