//go:build integration

package credentials

import "golang.org/x/crypto/bcrypt"

// NewInexpensiveHasher returns a hasher at bcrypt's minimum work factor, for a
// service under test whose credentials protect nothing and last one test.
//
// It is compiled only under the integration tag, so no deployment or
// development binary can construct one.
func NewInexpensiveHasher() Hasher {
	return Hasher{cost: bcrypt.MinCost}
}
