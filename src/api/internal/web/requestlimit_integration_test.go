//go:build integration

package web_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// asClient makes requests look as though they came from one client behind the
// reverse proxy, which is how the deployment sees them.
func asClient(address string) func(*http.Request) {
	return servertest.Header("X-Forwarded-For", address)
}

// Guessing an application's credential is budgeted. When the budget is spent
// the caller is told to come back later and how long to wait.
func TestGuessingAnApplicationsCredentialRunsOut(t *testing.T) {
	t.Parallel()

	service := servertest.New(t, servertest.WithSteadyClock())
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	policy, known := ratelimit.PolicyFor(ratelimit.DeveloperApplicationLogin)
	if !known {
		t.Fatal("developer application sign-in has no budget")
	}

	guess := map[string]string{
		"id":            application.ID.String(),
		"refresh_token": "not-the-credential",
	}

	for attempt := int64(0); attempt < policy.Limit; attempt++ {
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
func TestSpendingABudgetAgainstAnApplicationDoesNotLockItOut(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	policy, _ := ratelimit.PolicyFor(ratelimit.DeveloperApplicationLogin)

	for attempt := int64(0); attempt <= policy.Limit; attempt++ {
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
func TestAForwardedAddressIsOnlyBelievedFromTheProxy(t *testing.T) {
	t.Parallel()

	service := servertest.New(t,
		servertest.WithSetting(func(settings *config.Settings) {
			settings.TrustedProxyCIDRs = "203.0.113.0/24"
		}),
		servertest.WithSteadyClock(),
	)

	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))
	application := service.RegisterApplication("an application")

	policy, _ := ratelimit.PolicyFor(ratelimit.DeveloperApplicationLogin)

	for attempt := int64(0); attempt < policy.Limit; attempt++ {
		service.POSTJSON("/developer_application/login", map[string]string{
			"id":            application.ID.String(),
			"refresh_token": "not-the-credential",
		}, asClient("198.51.100."+strconv.FormatInt(attempt, 10))).
			ExpectStatus(http.StatusUnauthorized)
	}

	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": "not-the-credential",
	}, asClient("198.51.100.200")).ExpectStatus(http.StatusTooManyRequests)
}

// Guessing a one-time code is budgeted per client, whether or not the code was
// ever going to work.
func TestGuessingOneTimeCodesRunsOut(t *testing.T) {
	t.Parallel()

	service := servertest.New(t, servertest.WithSteadyClock())
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application")
	token := applicationAccessToken(t, service, application.ID, application.RefreshToken)

	policy, _ := ratelimit.PolicyFor(ratelimit.LoginExchange)

	for attempt := int64(0); attempt < policy.Limit; attempt++ {
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

// Nothing a limit is keyed on is stored as it arrived: the client address is
// kept only as a keyed hash.
func TestNoClientAddressIsKeptInTheClear(t *testing.T) {
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
