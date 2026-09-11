package applications

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
)

// An attempt against an application that does not exist is compared against
// this hash, so it has to cost what a stored credential costs: a value bcrypt
// cannot read, or one at a lower factor, would make the refusal faster than a
// wrong credential's and say which of the two it was.
func TestTheUnknownApplicationComparisonHashCostsWhatAStoredCredentialCosts(t *testing.T) {
	t.Parallel()

	cost, err := bcrypt.Cost([]byte(unknownApplicationComparisonHash))
	if err != nil {
		t.Fatalf("the comparison hash is not bcrypt: %v", err)
	}

	if cost != credentials.HashCost {
		t.Errorf("the comparison hash is at cost %d, want %d", cost, credentials.HashCost)
	}
}

// The comparison is real: its published input matches, which is what proves
// that a wrong credential is refused by bcrypt rather than by a hash nothing
// could ever match. What that match grants is proved through the endpoint.
func TestTheUnknownApplicationComparisonHashWasMadeFromItsPublishedInput(t *testing.T) {
	t.Parallel()

	if !credentials.Matches(UnknownApplicationComparisonInput, unknownApplicationComparisonHash) {
		t.Error("the published input does not match the comparison hash")
	}

	if credentials.Matches(UnknownApplicationComparisonInput+"-", unknownApplicationComparisonHash) {
		t.Error("a different input matched the comparison hash")
	}
}
