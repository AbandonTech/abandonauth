//go:build integration && !devtools

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/siteapplication"
	"github.com/abandontech/abandonauth/src/api/internal/web"
)

// freeAddress reserves a port and releases it, so the address given to a
// command is one nothing else on the machine is using. A command binds the
// address it is configured with, so it cannot be handed an open listener.
func freeAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}

	address := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("releasing the reserved port: %v", err)
	}

	return address
}

// operationalSettings describe a service that can actually start: a database of
// its own, and placeholders for everything else that must be present and valid.
func operationalSettings(t *testing.T, databaseURL, address string) config.Config {
	t.Helper()

	const origin = "https://api.auth.example.test"

	configuration, err := config.Load(config.Settings{
		BindAddress:           address,
		DatabaseURL:           databaseURL,
		SigningSecret:         "placeholder-signing-secret-placeholder-signing-secret-placeholder",
		SigningAlgorithm:      config.SigningAlgorithm,
		ExchangeCodeSeconds:   config.DefaultExchangeCodeSeconds,
		BrowserSessionSeconds: config.DefaultBrowserSessionSeconds,
		InternalApplicationID: uuid.New().String(),
		SiteURL:               "https://auth.example.test",
		APIURL:                origin,
		DiscordClientID:       "discord-client-id",
		DiscordClientSecret:   "discord-client-secret-placeholder",
		DiscordCallback:       origin + web.APIRoot + "/ui/discord-callback",
		GitHubClientID:        "github-client-id",
		GitHubClientSecret:    "github-client-secret-placeholder",
		GitHubCallback:        origin + web.APIRoot + "/ui/github-callback",
		GoogleClientID:        "google-client-id",
		GoogleClientSecret:    "google-client-secret-placeholder",
		GoogleCallback:        origin + web.APIRoot + "/google",
		TrustedProxyCIDRs:     config.DefaultTrustedProxyCIDRs,
	})
	if err != nil {
		t.Fatalf("the test configuration is not valid: %v", err)
	}

	return configuration
}

// Serving answers against a database the deployment migrated, and leaves every
// table and every recorded row exactly as it found them.
func TestServingAnswersPreparedDatabaseWithoutChangingIt(t *testing.T) {
	t.Parallel()

	pool, databaseURL := testdatabase.NewMigratedWithURL(t)
	before := tableContents(t, pool)

	serveAndAskRouteRoot(t, databaseURL)

	if after := tableContents(t, pool); after != before {
		t.Errorf("serving changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// The application carries no schema, so serving an empty database creates
// nothing in it; its requests are refused instead.
func TestServingLeavesEmptyDatabaseEmpty(t *testing.T) {
	t.Parallel()

	pool, databaseURL := testdatabase.NewWithURL(t)

	serveAndAskRouteRoot(t, databaseURL)

	if after := tableContents(t, pool); after != "" {
		t.Errorf("serving created tables in an empty database:\n%s", after)
	}
}

// serveAndAskRouteRoot serves the database until the route root has answered,
// then stops serving.
func serveAndAskRouteRoot(t *testing.T, databaseURL string) {
	t.Helper()

	address := freeAddress(t)

	ctx, stop := context.WithCancel(t.Context())

	stopped := make(chan error, 1)

	go func() { stopped <- service{}.Serve(ctx, operationalSettings(t, databaseURL, address)) }()

	waitUntilAccepting(t, address)

	// The API's route root is served by every build and needs no credential, so
	// it proves the service is answering rather than merely listening. Its
	// redirect is the answer under test, so it is read rather than followed.
	client := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	response, err := client.Get("http://" + address + web.APIRoot + "/")
	if err != nil {
		stop()
		t.Fatalf("asking the running service for its route root: %v", err)
	}

	_ = response.Body.Close()

	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("the route root answered %d, want %d", response.StatusCode, http.StatusTemporaryRedirect)
	}

	stop()

	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("serving ended with %v, want a clean stop", err)
		}
	case <-time.After(settleTimeout):
		t.Fatal("serving did not stop when its context was cancelled")
	}
}

// tableContents renders every public table and how many rows it holds.
func tableContents(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()

	rows, err := pool.Query(t.Context(),
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`)
	if err != nil {
		t.Fatalf("listing tables: %v", err)
	}

	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("listing tables: %v", err)
	}

	var rendered strings.Builder

	for _, table := range tables {
		var count int64

		if err := pool.QueryRow(t.Context(),
			fmt.Sprintf(`SELECT count(*) FROM %s`, pgx.Identifier{table}.Sanitize()),
		).Scan(&count); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}

		fmt.Fprintf(&rendered, "%s %d\n", table, count)
	}

	return rendered.String()
}

// Serving reports an address it cannot bind at once, naming the address, after
// the database is ready and before anything else is started for it.
func TestServingReportsAddressItCannotBind(t *testing.T) {
	t.Parallel()

	_, databaseURL := testdatabase.NewMigratedWithURL(t)

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupying a port: %v", err)
	}

	defer func() { _ = occupied.Close() }()

	address := occupied.Addr().String()

	ended := make(chan error, 1)

	go func() { ended <- service{}.Serve(t.Context(), operationalSettings(t, databaseURL, address)) }()

	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("serving started on an address already in use")
		}

		if !strings.Contains(err.Error(), address) {
			t.Errorf("the failure does not name the address: %v", err)
		}
	case <-time.After(settleTimeout):
		t.Fatal("serving did not report the address it could not bind")
	}
}

// Serving refuses to start against a database it cannot open, rather than
// listening and failing every request.
func TestServingRefusesDatabaseItCannotOpen(t *testing.T) {
	t.Parallel()

	unreachable := "postgres://placeholder:placeholder@127.0.0.1:1/placeholder?sslmode=disable&connect_timeout=1"

	err := service{}.Serve(t.Context(), operationalSettings(t, unreachable, freeAddress(t)))
	if err == nil {
		t.Fatal("serving started against a database it could not open")
	}
}

// Maintenance is what a failed deployment is switched to. It opens no database
// connection, so it answers even when the reason for the failure is the
// database itself.
func TestMaintenanceAnswersEveryRequestWithoutDatabase(t *testing.T) {
	t.Parallel()

	address := freeAddress(t)

	ctx, stop := context.WithCancel(t.Context())

	stopped := make(chan error, 1)

	go func() { stopped <- service{}.Maintenance(ctx, address) }()

	waitUntilAccepting(t, address)

	response, err := http.Get("http://" + address + "/developer_application")
	if err != nil {
		t.Fatalf("asking the maintenance listener: %v", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("maintenance answered %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}

	if response.Header.Get("Retry-After") == "" {
		t.Error("maintenance did not say when to come back")
	}

	stop()

	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("maintenance ended with %v, want a clean stop", err)
		}
	case <-time.After(settleTimeout):
		t.Fatal("maintenance did not stop when its context was cancelled")
	}
}

// Rotating the authority is how every credential this service has issued is
// withdrawn at once.
func TestRotatingAuthoritySucceedsOnMigratedDatabase(t *testing.T) {
	t.Parallel()

	pool, databaseURL := testdatabase.NewMigratedWithURL(t)

	configuration := operationalSettings(t, databaseURL, freeAddress(t))

	var before uuid.UUID
	if err := pool.QueryRow(t.Context(), "SELECT epoch FROM auth_epoch").Scan(&before); err != nil {
		t.Fatalf("reading the authority in force: %v", err)
	}

	if err := (service{}).RotateAuthority(t.Context(), configuration); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	var after uuid.UUID
	if err := pool.QueryRow(t.Context(), "SELECT epoch FROM auth_epoch").Scan(&after); err != nil {
		t.Fatalf("reading the authority after rotation: %v", err)
	}

	if after == before {
		t.Error("the authority in force did not change, so nothing was withdrawn")
	}
}

// Rotating against a database it cannot reach reports the failure rather than
// leaving the caller believing every credential was withdrawn.
func TestRotatingAuthorityReportsDatabaseItCannotOpen(t *testing.T) {
	t.Parallel()

	unreachable := "postgres://placeholder:placeholder@127.0.0.1:1/placeholder?sslmode=disable&connect_timeout=1"

	err := service{}.RotateAuthority(t.Context(), operationalSettings(t, unreachable, freeAddress(t)))
	if err == nil {
		t.Fatal("rotating reported success against a database it could not open")
	}
}

// databaseSecret holds a test database's address the way the command does.
func databaseSecret(t *testing.T, databaseURL string) config.Secret {
	t.Helper()

	secret, err := config.ParseDatabaseURL(databaseURL)
	if err != nil {
		t.Fatalf("the test database address is not valid: %v", err)
	}

	return secret
}

// Provisioning a migrated database creates the site's owner, application and
// callback once; provisioning it again reports the application present and
// changes nothing.
func TestProvisioningCreatesSiteApplicationOnce(t *testing.T) {
	t.Parallel()

	pool, databaseURL := testdatabase.NewMigratedWithURL(t)
	applicationID := uuid.New()
	callback := "https://auth.example.test" + web.SiteEntryPath

	outcome, err := service{}.Provision(t.Context(), databaseSecret(t, databaseURL), applicationID, callback)
	if err != nil {
		t.Fatalf("provisioning: %v", err)
	}

	if outcome != siteapplication.Created {
		t.Errorf("outcome = %v, want Created", outcome)
	}

	created := tableContents(t, pool)

	for _, want := range []string{"User 1\n", "DeveloperApplication 1\n", "CallbackUri 1\n"} {
		if !strings.Contains(created, want) {
			t.Errorf("provisioning did not leave %q:\n%s", strings.TrimSpace(want), created)
		}
	}

	var registered bool
	if err := pool.QueryRow(t.Context(),
		`SELECT EXISTS (SELECT 1 FROM "CallbackUri" WHERE "developer_application_id" = $1 AND "uri" = $2)`,
		applicationID, callback,
	).Scan(&registered); err != nil {
		t.Fatalf("reading the registered callback: %v", err)
	}

	if !registered {
		t.Error("the site's callback is not registered to the provisioned application")
	}

	outcome, err = service{}.Provision(t.Context(), databaseSecret(t, databaseURL), applicationID, callback)
	if err != nil {
		t.Fatalf("provisioning again: %v", err)
	}

	if outcome != siteapplication.AlreadyPresent {
		t.Errorf("outcome = %v, want AlreadyPresent", outcome)
	}

	if again := tableContents(t, pool); again != created {
		t.Errorf("provisioning again changed the database:\nbefore:\n%s\nafter:\n%s", created, again)
	}
}

// A database the migrations have not prepared is refused, and left as empty as
// it was found.
func TestProvisioningRefusesUnpreparedDatabase(t *testing.T) {
	t.Parallel()

	pool, databaseURL := testdatabase.NewWithURL(t)

	_, err := service{}.Provision(
		t.Context(), databaseSecret(t, databaseURL), uuid.New(), "https://auth.example.test"+web.SiteEntryPath,
	)
	if err == nil {
		t.Fatal("provisioning reported success against a database without the schema")
	}

	if after := tableContents(t, pool); after != "" {
		t.Errorf("provisioning created tables in an empty database:\n%s", after)
	}
}

// Provisioning against a database it cannot reach fails, and the failure does
// not carry the database password.
func TestProvisioningReportsDatabaseItCannotOpen(t *testing.T) {
	t.Parallel()

	const password = "placeholder-unreachable-password"

	unreachable := "postgres://placeholder:" + password +
		"@127.0.0.1:1/placeholder?sslmode=disable&connect_timeout=1"

	_, err := service{}.Provision(
		t.Context(), databaseSecret(t, unreachable), uuid.New(), "https://auth.example.test"+web.SiteEntryPath,
	)
	if err == nil {
		t.Fatal("provisioning reported success against a database it could not open")
	}

	if strings.Contains(err.Error(), password) {
		t.Error("the failure carries the database password")
	}
}
