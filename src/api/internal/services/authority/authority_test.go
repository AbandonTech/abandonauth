package authority_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/authority"
)

// A withdrawal names the token it refuses. One that named nothing would record
// an entry that no token could ever be matched against, and would report
// success for having done nothing.
func TestATokenCannotBeWithdrawnWithoutBeingIdentified(t *testing.T) {
	t.Parallel()

	if err := authority.New(nil).Withdraw(t.Context(), uuid.Nil, time.Now().Add(time.Hour)); err == nil {
		t.Error("a token with no identifier was withdrawn anyway")
	}
}
