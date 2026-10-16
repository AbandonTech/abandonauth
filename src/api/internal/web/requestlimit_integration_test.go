//go:build integration && !devtools

package web_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// developerApplicationMutationLimit is the budget this service promises one
// signed-in user for changing developer applications, stated here rather than
// read back from the service, so that a change to it fails a test rather than
// moving its goal.
const developerApplicationMutationLimit = 20

// Creating, changing and deleting applications share one budget per user. When
// it is spent the user is told to come back later and how long to wait.
func TestChangingApplicationsRunsOut(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	// Registering spends the first change.
	application := service.RegisterApplication("an application")
	id := application.ID.String()

	changes := []func() *servertest.Response{
		func() *servertest.Response {
			return service.PATCHJSON("/developer_application/"+id+"/reset_token", nil, service.Protected)
		},
		func() *servertest.Response {
			return service.PATCHJSON(
				"/developer_application/"+id+"/callback_uris", []string{externalCallbackURI}, service.Protected,
			)
		},
		func() *servertest.Response {
			return service.POSTJSON("/developer_application", map[string]string{"name": "another"}, service.Protected)
		},
	}

	for spent := 1; spent < developerApplicationMutationLimit; spent++ {
		changes[spent%len(changes)]().ExpectStatus(http.StatusOK)
	}

	refused := service.DELETE("/developer_application/"+id, service.Protected).
		ExpectStatus(http.StatusTooManyRequests).
		ExpectDetail("Too many requests. Try again later.")

	seconds, err := strconv.Atoi(refused.Header.Get("Retry-After"))
	if err != nil || seconds < 1 {
		t.Errorf("Retry-After = %q, want whole seconds to wait", refused.Header.Get("Retry-After"))
	}
}

// A budget belongs to the user who spent it. Somebody else signed in to the same
// service is still served.
func TestSpentBudgetBelongsToOneUser(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a busy user"))

	for spent := 0; spent < developerApplicationMutationLimit; spent++ {
		service.RegisterApplication("an application")
	}

	service.POSTJSON("/developer_application", map[string]string{"name": "one too many"}, service.Protected).
		ExpectStatus(http.StatusTooManyRequests)

	service.SignIn(service.Providers.Someone(oauth.Discord, "somebody else"))
	service.RegisterApplication("an application of their own")
}

// A forwarding header names nobody to this service. A user who sends a new one
// with every request is still one user with one budget, and a bystander sending
// the same header spends nothing of theirs.
func TestForwardingHeadersDoNotChangeWhoIsCounted(t *testing.T) {
	t.Parallel()

	forwardedAs := func(address string) []func(*http.Request) {
		return []func(*http.Request){
			servertest.Header("X-Forwarded-For", address),
			servertest.Header("X-Real-IP", address),
		}
	}

	create := func(service *servertest.Service, address string) *servertest.Response {
		return service.POSTJSON(
			"/developer_application", map[string]string{"name": "an application"},
			append(forwardedAs(address), service.Protected)...,
		)
	}

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a user"))

	for spent := 0; spent < developerApplicationMutationLimit; spent++ {
		create(service, "198.51.100."+strconv.Itoa(spent)).ExpectStatus(http.StatusOK)
	}

	create(service, "203.0.113.1").ExpectStatus(http.StatusTooManyRequests)

	service.SignIn(service.Providers.Someone(oauth.Discord, "a bystander"))
	create(service, "198.51.100.0").ExpectStatus(http.StatusOK)
}

// Nothing a limit is keyed on is stored as it arrived: the user is kept only as
// a keyed hash.
func TestNoUserIdentifierIsKeptInClear(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	var counted, held int

	err := service.Pool.QueryRow(t.Context(),
		`SELECT count(*),
		        count(*) FILTER (WHERE position($1 in encode(bucket_key, 'escape')) > 0)
		 FROM rate_limit_bucket`,
		application.OwnerID.String(),
	).Scan(&counted, &held)
	if err != nil {
		t.Fatalf("reading what was counted: %v", err)
	}

	if counted == 0 {
		t.Fatal("registering an application counted nothing")
	}

	if held != 0 {
		t.Error("a user identifier was stored as it arrived")
	}
}
