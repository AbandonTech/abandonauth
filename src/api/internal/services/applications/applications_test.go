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
func TestRefusedCallbackIsNamedByItsPositionAndReason(t *testing.T) {
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
func TestRefusedCallbackKeepsRuleItBroke(t *testing.T) {
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
func TestEmptyCallbackIsNotRegistered(t *testing.T) {
	t.Parallel()

	service := applications.New(nil, nil)

	registered, err := service.CallbackIsRegistered(t.Context(), uuid.New(), "")
	if err != nil {
		t.Fatalf("checking an empty callback URI: %v", err)
	}

	if registered {
		t.Error("an empty callback URI was treated as one an application registered")
	}
}

func TestClientTypesAreExactlyTheTwoStandardValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"confidential", "public"} {
		if parsed, known := applications.ParseClientType(value); !known || string(parsed) != value {
			t.Errorf("%q was not recognised", value)
		}
	}

	for _, value := range []string{"", "Public", "CONFIDENTIAL", "native", "public ", "public-native"} {
		if _, known := applications.ParseClientType(value); known {
			t.Errorf("%q was recognised", value)
		}
	}
}

// Which callbacks an application may register follows its client type, and is
// decided before anything is stored, so a refusal needs no database.
func TestCallbackPolicyFollowsClientType(t *testing.T) {
	t.Parallel()

	service := applications.New(nil, nil)

	for name, refusal := range map[string]struct {
		clientType applications.ClientType
		uri        string
		reason     error
	}{
		"a confidential application given a portless loopback template": {
			applications.Confidential, "http://127.0.0.1/oauth/callback", urlpolicy.ErrMissingPort,
		},
		"a public client given an HTTPS callback": {
			applications.Public, "https://app.example.test/callback", urlpolicy.ErrNativeScheme,
		},
		"a public client given a registered port": {
			applications.Public, "http://127.0.0.1:8080/oauth/callback", urlpolicy.ErrNativePort,
		},
		"a public client given localhost": {
			applications.Public, "http://localhost/oauth/callback", urlpolicy.ErrNativeHost,
		},
		"a public client given a reserved key": {
			applications.Public, "http://[::1]/cb?iss=1", urlpolicy.ErrReservedQueryKey,
		},
	} {
		application := applications.Application{ID: uuid.New(), ClientType: refusal.clientType}

		err := service.ReplaceCallbackURIs(t.Context(), application, []string{refusal.uri})

		var unsafe applications.UnsafeCallbackError
		if !errors.As(err, &unsafe) || unsafe.Index != 0 || !errors.Is(err, refusal.reason) {
			t.Errorf("%s: refused with %v, want the first entry refused for %v", name, err, refusal.reason)
		}
	}
}
