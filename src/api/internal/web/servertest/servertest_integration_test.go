//go:build integration

package servertest_test

import (
	"net/http"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The harness decides what every endpoint test is run against, so a defect in it
// would quietly weaken them all rather than fail.

func TestEachServiceGetsItsOwnDatabase(t *testing.T) {
	t.Parallel()

	first := servertest.New(t)
	second := servertest.New(t)

	if first.URL() == second.URL() {
		t.Error("two services were given the same address")
	}

	var users int

	if err := first.Pool.QueryRow(t.Context(), `SELECT count(*) FROM "User"`).Scan(&users); err != nil {
		t.Fatalf("reading the database: %v", err)
	}

	if users != 0 {
		t.Errorf("a new service started with %d users", users)
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

	if service.Config.InternalApplicationID.String() != servertest.InternalApplicationID {
		t.Errorf("internal application = %q", service.Config.InternalApplicationID)
	}
}
