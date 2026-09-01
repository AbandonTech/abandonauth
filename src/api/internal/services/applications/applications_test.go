package applications_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

// The refusal travels back to whoever submitted the list, so it says which
// entry was refused and which rule it broke, and never repeats the URI: that is
// another deployment's address.
func TestARefusedCallbackIsNamedByItsPositionAndReason(t *testing.T) {
	t.Parallel()

	const submitted = "http://relying.example.test/return"

	refused := applications.UnsafeCallbackError{Index: 2, Reason: urlpolicy.ErrInsecureTransport}
	message := refused.Error()

	if !strings.Contains(message, "2") {
		t.Errorf("the refusal does not say which entry was refused: %q", message)
	}

	if !strings.Contains(message, urlpolicy.ErrInsecureTransport.Error()) {
		t.Errorf("the refusal does not say which rule was broken: %q", message)
	}

	if strings.Contains(message, submitted) {
		t.Error("the refusal repeats the URI that was submitted")
	}
}

// A caller decides what to answer from the rule that was broken, so the policy
// error survives being named as one entry of a submitted list.
func TestARefusedCallbackKeepsTheRuleItBroke(t *testing.T) {
	t.Parallel()

	refused := error(applications.UnsafeCallbackError{Index: 0, Reason: urlpolicy.ErrReservedQueryKey})

	if !errors.Is(refused, urlpolicy.ErrReservedQueryKey) {
		t.Error("the rule that was broken cannot be read back from the refusal")
	}

	if errors.Is(refused, urlpolicy.ErrFragment) {
		t.Error("the refusal answers to a rule it did not break")
	}
}

// Nothing is registered under nothing. Deciding that takes no lookup, which is
// why the service here is built over no database at all: reaching one would
// fail rather than answer.
func TestAnEmptyCallbackIsNotRegistered(t *testing.T) {
	t.Parallel()

	registered, err := applications.New(nil).CallbackIsRegistered(t.Context(), uuid.New(), "")
	if err != nil {
		t.Fatalf("checking an empty callback URI: %v", err)
	}

	if registered {
		t.Error("an empty callback URI was treated as one an application registered")
	}
}
