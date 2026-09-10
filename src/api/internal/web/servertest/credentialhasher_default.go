//go:build !integration

package servertest

import "github.com/abandontech/abandonauth/src/api/internal/services/credentials"

// testCredentialHasher is the work factor a deployment stores secrets at. The
// inexpensive hasher is compiled only into an integration build, and this
// package has to build without it.
func testCredentialHasher() credentials.Hasher {
	return credentials.NewHasher()
}
