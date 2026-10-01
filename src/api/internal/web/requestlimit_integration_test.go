//go:build integration && !devtools

package web_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The budgets this service promises, stated here rather than read back from the
// service, so that a change to one fails a test rather than moving its goal.
const (
	developerApplicationLoginLimit = 10
	loginExchangeLimit             = 20
	burnTokenLimit                 = 60
	providerCallbackLimit          = 30
)

// asClient makes requests look as though they came from one client behind the
// reverse proxy, which is how the deployment sees them.
func asClient(address string) func(*http.Request) {
	return servertest.Header("X-Forwarded-For", address)
}

// appendingHeader adds a header line rather than replacing one, which is what a
// proxy that appends to whatever it received does.
func appendingHeader(name, value string) func(*http.Request) {
	return func(request *http.Request) {
		request.Header.Add(name, value)
	}
}

// Guessing an application's credential is budgeted. When the budget is spent
// the caller is told to come back later and how long to wait.
func TestGuessingApplicationsCredentialRunsOut(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	guess := map[string]string{
		"id":            application.ID.String(),
		"refresh_token": "not-the-credential",
	}

	for attempt := 0; attempt < developerApplicationLoginLimit; attempt++ {
		service.POSTJSON("/developer_application/login", guess, asClient("198.51.100.10")).
			ExpectStatus(http.StatusUnauthorized)
	}

	refused := service.POSTJSON("/developer_application/login", guess, asClient("198.51.100.10")).
		ExpectStatus(http.StatusTooManyRequests).
		ExpectDetail("Too many requests. Try again later.")

	seconds, err := strconv.Atoi(refused.Header.Get("Retry-After"))
	if err != nil || seconds < 1 {
		t.Errorf("Retry-After = %q, want whole seconds to wait", refused.Header.Get("Retry-After"))
	}

	// The correct credential is refused too: the budget is spent, and a
	// successful attempt is not a way around it.
	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}, asClient("198.51.100.10")).ExpectStatus(http.StatusTooManyRequests)
}

// An application identifier is public. Somebody spending its budget must not be
// able to lock the application out of its own sign-in.
func TestSpendingBudgetAgainstApplicationDoesNotLockItOut(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	for attempt := 0; attempt <= developerApplicationLoginLimit; attempt++ {
		service.POSTJSON("/developer_application/login", map[string]string{
			"id":            application.ID.String(),
			"refresh_token": "not-the-credential",
		}, asClient("198.51.100.20"))
	}

	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}, asClient("203.0.113.20")).ExpectStatus(http.StatusOK)
}

// The forwarded address is only believed from the proxy. A client that sends
// one itself is still counted as itself, or it would have a new identity per
// request.
func TestForwardedAddressIsOnlyBelievedFromProxy(t *testing.T) {
	t.Parallel()

	service := servertest.New(t,
		servertest.WithSetting(func(settings *config.Settings) {
			settings.TrustedProxyCIDRs = "203.0.113.0/24"
		}),
	)

	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))
	application := service.RegisterApplication("an application")

	for attempt := 0; attempt < developerApplicationLoginLimit; attempt++ {
		service.POSTJSON("/developer_application/login", map[string]string{
			"id":            application.ID.String(),
			"refresh_token": "not-the-credential",
		}, asClient("198.51.100."+strconv.Itoa(attempt))).
			ExpectStatus(http.StatusUnauthorized)
	}

	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": "not-the-credential",
	}, asClient("198.51.100.200")).ExpectStatus(http.StatusTooManyRequests)
}

// A proxy that appends the client it saw to whatever the client sent leaves the
// client's own value first, in the same field or on a line of its own. The
// address the request is counted against is the one the proxy appended, so a
// client varying what it sends still has one budget.
func TestClientCannotChooseItsIdentityByPrependingToForwardedChain(t *testing.T) {
	t.Parallel()

	shapes := map[string]func(attempt int) []func(*http.Request){
		"in the same field": func(attempt int) []func(*http.Request) {
			return []func(*http.Request){
				asClient("198.51.100." + strconv.Itoa(attempt) + ", 203.0.113.77"),
			}
		},
		"on a later line": func(attempt int) []func(*http.Request) {
			return []func(*http.Request){
				asClient("198.51.100." + strconv.Itoa(attempt)),
				appendingHeader("X-Forwarded-For", "203.0.113.77"),
			}
		},
	}

	for name, chain := range shapes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))
			application := service.RegisterApplication("an application")

			guess := map[string]string{
				"id":            application.ID.String(),
				"refresh_token": "not-the-credential",
			}

			for attempt := 0; attempt < developerApplicationLoginLimit; attempt++ {
				service.POSTJSON("/developer_application/login", guess, chain(attempt)...).
					ExpectStatus(http.StatusUnauthorized)
			}

			service.POSTJSON("/developer_application/login", guess, chain(developerApplicationLoginLimit)...).
				ExpectStatus(http.StatusTooManyRequests)

			// The budget belongs to the appended client alone: another client
			// behind the same proxy is still served.
			service.POSTJSON("/developer_application/login", guess, asClient("203.0.113.78")).
				ExpectStatus(http.StatusUnauthorized)
		})
	}
}

// Guessing a one-time code is budgeted per client, whether or not the code was
// ever going to work.
func TestGuessingOneTimeCodesRunsOut(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application")
	token := applicationAccessToken(t, service, application.ID, application.RefreshToken)

	for attempt := 0; attempt < loginExchangeLimit; attempt++ {
		service.POSTRaw("/login", "",
			servertest.Bearer(token),
			servertest.Header("exchange-token", "not-a-code"),
			asClient("198.51.100.30"),
		).ExpectStatus(http.StatusUnauthorized)
	}

	service.POSTRaw("/login", "",
		servertest.Bearer(token),
		servertest.Header("exchange-token", "not-a-code"),
		asClient("198.51.100.30"),
	).ExpectStatus(http.StatusTooManyRequests)

	service.POSTRaw("/login", "",
		servertest.Bearer(token),
		servertest.Header("exchange-token", "not-a-code"),
		asClient("198.51.100.31"),
	).ExpectStatus(http.StatusUnauthorized)
}

// A public budget is spent before the request is read, so sending something
// this service cannot read is not a way to make attempts free.
func TestRequestThatCannotBeReadStillSpendsItsBudget(t *testing.T) {
	t.Parallel()

	endpoints := map[string]struct {
		limit int
		path  string
	}{
		"spending a one-time code": {limit: loginExchangeLimit, path: "/login"},
		"withdrawing a credential": {limit: burnTokenLimit, path: "/burn-token"},
	}

	for name, endpoint := range endpoints {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)

			unreadable := []func(*http.Request){
				servertest.Header("Content-Type", "application/json"),
				asClient("198.51.100.50"),
			}

			for attempt := 0; attempt < endpoint.limit; attempt++ {
				service.POSTRaw(endpoint.path, "{", unreadable...).
					ExpectStatus(http.StatusUnprocessableEntity)
			}

			service.POSTRaw(endpoint.path, "{", unreadable...).
				ExpectStatus(http.StatusTooManyRequests).
				ExpectDetail("Too many requests. Try again later.")
		})
	}
}

// Nothing a limit is keyed on is stored as it arrived: the client address is
// kept only as a keyed hash.
func TestNoClientAddressIsKeptInClear(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/burn-token", map[string]string{"token": "a value"}, asClient("198.51.100.40")).
		ExpectStatus(http.StatusOK)

	var held int

	err := service.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM rate_limit_bucket WHERE position('198.51.100.40' in encode(bucket_key, 'escape')) > 0`,
	).Scan(&held)
	if err != nil {
		t.Fatalf("reading what was counted: %v", err)
	}

	if held != 0 {
		t.Error("a client address was stored as it arrived")
	}
}
