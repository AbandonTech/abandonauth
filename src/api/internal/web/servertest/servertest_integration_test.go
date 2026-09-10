//go:build integration

package servertest_test

import (
	"net/http"
	"testing"

	"golang.org/x/crypto/bcrypt"

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

// Every endpoint helper is given the path below the API's route root, and the
// root is composed once. A journey written against a path that reached the
// service without it would prove nothing about what a caller can reach.
func TestAnEndpointPathReachesTheAPIsRouteRoot(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	if got, want := service.EndpointURL("/me"), service.URL()+"/api/me"; got != want {
		t.Errorf("EndpointURL(\"/me\") = %q, want %q", got, want)
	}

	service.GET("/openapi.json").ExpectStatus(http.StatusOK)
	service.AtExactTarget(http.MethodGet, "/api/openapi.json").ExpectStatus(http.StatusOK)
}

// The exact-target helper writes the whole target out, so a test can describe
// what this service does with one it does not serve. It adds nothing of its
// own; if it did, those tests would be describing a different request.
func TestTheExactTargetHelperAddsNothing(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.AtExactTarget(http.MethodGet, "/openapi.json").
		ExpectStatus(http.StatusNotFound).
		ExpectDetail("Not Found")
}

// Every service registers an application before it starts, and at the deployed
// work factor that alone exhausts the suite's time budget. The hash the harness
// left behind is where the cheaper factor is either in use or silently not.
func TestTheHarnessStoresCredentialsAtTheInexpensiveCost(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	var stored string

	err := service.Pool.QueryRow(t.Context(),
		`SELECT "refresh_token" FROM "DeveloperApplication" WHERE "id" = $1`, service.Site.ApplicationID,
	).Scan(&stored)
	if err != nil {
		t.Fatalf("reading the site application's credential: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(stored))
	if err != nil {
		t.Fatalf("the stored credential records no cost: %v", err)
	}

	if cost != bcrypt.MinCost {
		t.Errorf("the site application's credential was stored at cost %d, want %d", cost, bcrypt.MinCost)
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
