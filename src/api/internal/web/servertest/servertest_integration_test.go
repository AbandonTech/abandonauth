//go:build integration

package servertest_test

import (
	"net/http"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The harness decides what every endpoint test is run against, so a defect in it
// would quietly weaken them all rather than fail.

// Two services share nothing: the same person signing in to both is two
// accounts, and what one of them registers the other has never heard of.
func TestEachServiceGetsItsOwnDatabase(t *testing.T) {
	t.Parallel()

	first := servertest.New(t)
	second := servertest.New(t)

	if first.URL() == second.URL() {
		t.Error("two services were given the same address")
	}

	identity := first.Providers.Someone(oauth.Discord, "the same person")

	first.SignIn(identity)
	first.POSTJSON("/developer_application", map[string]string{"name": "registered on one"}, first.Protected).
		ExpectStatus(http.StatusOK)

	second.SignIn(identity)

	var listed []struct {
		Name string `json:"name"`
	}

	second.GET("/user/applications").ExpectStatus(http.StatusOK).DecodeInto(&listed)

	if len(listed) != 0 {
		t.Errorf("the second service knows about %d applications registered with the first", len(listed))
	}
}

// A redirect is part of what several endpoints promise, so it is handed to the
// test rather than followed behind its back.
func TestRedirectsAreReturnedRatherThanFollowed(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	response := service.GET("/")

	if response.Status != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want a redirect the test can inspect", response.Status)
	}
}

func TestTheConfigurationIsAvailableToTests(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	if got := service.Config.Site.String(); got != servertest.SiteOrigin {
		t.Errorf("site origin = %q, want %q", got, servertest.SiteOrigin)
	}

	if service.Config.InternalApplicationID != service.Site.ApplicationID {
		t.Errorf(
			"the service treats %q as its own application, but %q was registered for it",
			service.Config.InternalApplicationID, service.Site.ApplicationID,
		)
	}
}
