package siteapplication_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/siteapplication"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

// Inputs that identify nothing, or a callback this service would refuse to
// return a browser to, are refused before the database is consulted: no pool
// is given, so reaching it would panic.
func TestUnusableInputIsRefusedBeforeDatabase(t *testing.T) {
	t.Parallel()

	const callback = "https://auth.example.test/api/ui"

	if _, err := siteapplication.Provision(t.Context(), nil, uuid.Nil, callback); !errors.Is(
		err, siteapplication.ErrNilApplicationID,
	) {
		t.Errorf("nil identifier: err = %v, want %v", err, siteapplication.ErrNilApplicationID)
	}

	refused := map[string]error{
		"https://auth.example.test//api/ui#fragment":           urlpolicy.ErrFragment,
		"http://auth.example.test/api/ui":                      urlpolicy.ErrInsecureTransport,
		"http://localhost/api/ui":                              urlpolicy.ErrMissingPort,
		"https://user:placeholder-password@auth.example.test/": urlpolicy.ErrUserInfo,
		"https://auth.example.test/api/ui?code=placeholder":    urlpolicy.ErrReservedQueryKey,
		"": urlpolicy.ErrEmpty,
	}

	for callback, reason := range refused {
		_, err := siteapplication.Provision(t.Context(), nil, uuid.New(), callback)
		if !errors.Is(err, reason) {
			t.Errorf("err = %v, want %v", err, reason)

			continue
		}

		if callback != "" && strings.Contains(err.Error(), callback) {
			t.Error("the refusal repeats the callback it refused")
		}
	}
}
