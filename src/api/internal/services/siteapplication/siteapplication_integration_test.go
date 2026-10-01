//go:build integration && !devtools

package siteapplication_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/siteapplication"
)

const siteCallback = "https://auth.example.test/api/ui"

// databaseState renders every account, application and callback, with each
// stored credential reduced to a digest so a failure prints no hash.
func databaseState(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()

	statements := []string{
		`SELECT 'user ' || "id" || ' ' || "username" FROM "User" ORDER BY "id"`,
		`SELECT 'application ' || "id" || ' ' || "owner_id" || ' ' || "name" || ' ' ||
			md5("refresh_token") || ' ' || "credential_version"
		 FROM "DeveloperApplication" ORDER BY "id"`,
		`SELECT 'callback ' || "developer_application_id" || ' ' || "uri" FROM "CallbackUri" ORDER BY "id"`,
		`SELECT 'discord ' || "user_id" FROM "DiscordAccount" ORDER BY "id"`,
		`SELECT 'github ' || "user_id" FROM "GitHubAccount" ORDER BY "id"`,
		`SELECT 'google ' || "user_id" FROM "GoogleAccount" ORDER BY "id"`,
		`SELECT 'password ' || "user_id" FROM "PasswordAccount" ORDER BY "id"`,
	}

	var rendered strings.Builder

	for _, statement := range statements {
		rows, err := pool.Query(t.Context(), statement)
		if err != nil {
			t.Fatalf("reading the database: %v", err)
		}

		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("reading the database: %v", err)
		}

		for _, line := range lines {
			fmt.Fprintln(&rendered, line)
		}
	}

	return rendered.String()
}

func count(t *testing.T, pool *pgxpool.Pool, statement string, arguments ...any) int {
	t.Helper()

	var found int
	if err := pool.QueryRow(t.Context(), statement, arguments...).Scan(&found); err != nil {
		t.Fatalf("counting rows: %v", err)
	}

	return found
}

// A migrated database without the configured identifier gains exactly one
// owner nobody can sign in as, the site's application under that identifier,
// and the site's exact callback.
func TestProvisioningCreatesSiteApplication(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	applicationID := uuid.New()

	outcome, err := siteapplication.Provision(t.Context(), pool, applicationID, siteCallback)
	if err != nil {
		t.Fatalf("provisioning: %v", err)
	}

	if outcome != siteapplication.Created {
		t.Errorf("outcome = %v, want Created", outcome)
	}

	registry := applications.New(pool, nil)

	application, err := registry.Get(t.Context(), applicationID)
	if err != nil {
		t.Fatalf("reading the provisioned application: %v", err)
	}

	if application.Name != "AbandonAuth" {
		t.Errorf("application name = %q, want AbandonAuth", application.Name)
	}

	owner, err := accounts.New(pool).Get(t.Context(), application.OwnerID)
	if err != nil {
		t.Fatalf("reading the application's owner: %v", err)
	}

	if owner.Username != "abandonauth" {
		t.Errorf("owner username = %q, want abandonauth", owner.Username)
	}

	callbacks, err := registry.CallbackURIs(t.Context(), applicationID)
	if err != nil {
		t.Fatalf("listing the application's callbacks: %v", err)
	}

	if len(callbacks) != 1 || callbacks[0] != siteCallback {
		t.Errorf("callbacks = %q, want exactly %q", callbacks, siteCallback)
	}

	if users := count(t, pool, `SELECT count(*) FROM "User"`); users != 1 {
		t.Errorf("%d accounts exist, want only the owner", users)
	}

	for _, table := range []string{"DiscordAccount", "GitHubAccount", "GoogleAccount", "PasswordAccount"} {
		statement := fmt.Sprintf(`SELECT count(*) FROM %s WHERE "user_id" = $1`, pgx.Identifier{table}.Sanitize())
		if held := count(t, pool, statement, owner.ID); held != 0 {
			t.Errorf("the owner holds a %s, so someone could sign in as it", table)
		}
	}

	var stored string
	if err := pool.QueryRow(t.Context(),
		`SELECT "refresh_token" FROM "DeveloperApplication" WHERE "id" = $1`, applicationID,
	).Scan(&stored); err != nil {
		t.Fatalf("reading the stored credential: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(stored))
	if err != nil {
		t.Fatal("the stored credential is not a bcrypt hash")
	}

	if cost != credentials.HashCost {
		t.Errorf("the stored credential has cost %d, want %d", cost, credentials.HashCost)
	}
}

// Provisioning an identifier that is already provisioned writes nothing, even
// when it is asked for a different callback.
func TestRepeatedProvisioningChangesNothing(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	applicationID := uuid.New()

	if _, err := siteapplication.Provision(t.Context(), pool, applicationID, siteCallback); err != nil {
		t.Fatalf("provisioning: %v", err)
	}

	before := databaseState(t, pool)

	outcome, err := siteapplication.Provision(t.Context(), pool, applicationID, "https://elsewhere.example.test/api/ui")
	if err != nil {
		t.Fatalf("provisioning again: %v", err)
	}

	if outcome != siteapplication.AlreadyPresent {
		t.Errorf("outcome = %v, want AlreadyPresent", outcome)
	}

	if after := databaseState(t, pool); after != before {
		t.Errorf("provisioning again changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// Only the identifier decides. An application under it that belongs to an
// account someone signs in as keeps its owner, callbacks, credential and
// credential version, and its owner keeps every power over it.
func TestApplicationOwnedByLoginAccountIsLeftUnchanged(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)

	owner, err := accounts.New(pool).Resolve(t.Context(), accounts.Identity{
		Provider: oauth.Discord, ID: "4815162342", Username: "a developer",
	})
	if err != nil {
		t.Fatalf("creating the developer's account: %v", err)
	}

	registry := applications.New(pool, nil)

	application, token, err := registry.Create(t.Context(), owner.ID, "A developer's application")
	if err != nil {
		t.Fatalf("creating the developer's application: %v", err)
	}

	const registered = "https://app.example.test/callback"
	if err := registry.ReplaceCallbackURIs(t.Context(), application.ID, []string{registered}); err != nil {
		t.Fatalf("registering the developer's callback: %v", err)
	}

	before := databaseState(t, pool)

	outcome, err := siteapplication.Provision(t.Context(), pool, application.ID, siteCallback)
	if err != nil {
		t.Fatalf("provisioning: %v", err)
	}

	if outcome != siteapplication.AlreadyPresent {
		t.Errorf("outcome = %v, want AlreadyPresent", outcome)
	}

	if after := databaseState(t, pool); after != before {
		t.Errorf("provisioning changed an existing application:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	authenticated, err := registry.Authenticate(t.Context(), application.ID, token)
	if err != nil {
		t.Fatalf("the developer's credential stopped authenticating: %v", err)
	}

	if authenticated.CredentialVersion != application.CredentialVersion {
		t.Errorf("credential version = %d, want %d", authenticated.CredentialVersion, application.CredentialVersion)
	}

	if _, err := registry.OwnedBy(t.Context(), application.ID, owner.ID); err != nil {
		t.Fatalf("the developer no longer owns the application: %v", err)
	}

	if err := registry.ReplaceCallbackURIs(
		t.Context(), application.ID, []string{"https://app.example.test/other"},
	); err != nil {
		t.Errorf("the developer can no longer replace the callbacks: %v", err)
	}

	if _, err := registry.Delete(t.Context(), application.ID); err != nil {
		t.Errorf("the developer can no longer delete the application: %v", err)
	}
}

// competingProvisioner holds a complete owner, application and callback under
// the identifier, uncommitted, so a provisioning that has already found the
// identifier free waits on it at the application insert.
func competingProvisioner(t *testing.T, pool *pgxpool.Pool, applicationID uuid.UUID) (pgx.Tx, uuid.UUID) {
	t.Helper()

	competitor, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("beginning the competing transaction: %v", err)
	}

	t.Cleanup(func() { _ = competitor.Rollback(context.WithoutCancel(t.Context())) })

	var ownerID uuid.UUID
	if err := competitor.QueryRow(t.Context(),
		`INSERT INTO "User" ("username") VALUES ('abandonauth') RETURNING "id"`,
	).Scan(&ownerID); err != nil {
		t.Fatalf("writing the competing owner: %v", err)
	}

	if _, err := competitor.Exec(t.Context(),
		`INSERT INTO "DeveloperApplication" ("id", "owner_id", "refresh_token", "name")
		 VALUES ($1, $2, 'placeholder-hash', 'AbandonAuth')`, applicationID, ownerID,
	); err != nil {
		t.Fatalf("writing the competing application: %v", err)
	}

	if _, err := competitor.Exec(t.Context(),
		`INSERT INTO "CallbackUri" ("developer_application_id", "uri") VALUES ($1, $2)`,
		applicationID, siteCallback,
	); err != nil {
		t.Fatalf("writing the competing callback: %v", err)
	}

	return competitor, ownerID
}

// Two provisioners that both find the identifier free leave one complete set:
// the one that loses the application insert succeeds without writing, and its
// owner goes with its rollback.
func TestConcurrentProvisionersLeaveOneSiteApplication(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	applicationID := uuid.New()

	competitor, winningOwner := competingProvisioner(t, pool, applicationID)

	type result struct {
		outcome siteapplication.Outcome
		err     error
	}

	provisioned := make(chan result, 1)

	go func() {
		outcome, err := siteapplication.Provision(t.Context(), pool, applicationID, siteCallback)
		provisioned <- result{outcome, err}
	}()

	if err := testdatabase.AwaitLockWaiters(t.Context(), pool, 1); err != nil {
		t.Fatalf("waiting for provisioning to block on the identifier: %v", err)
	}

	if err := competitor.Commit(t.Context()); err != nil {
		t.Fatalf("committing the competing provisioner: %v", err)
	}

	loser := <-provisioned
	if loser.err != nil {
		t.Fatalf("the provisioner that lost the identifier failed: %v", loser.err)
	}

	if loser.outcome != siteapplication.AlreadyPresent {
		t.Errorf("outcome = %v, want AlreadyPresent", loser.outcome)
	}

	if users := count(t, pool, `SELECT count(*) FROM "User"`); users != 1 {
		t.Errorf("%d accounts exist, want only the winner's owner", users)
	}

	if owners := count(t, pool,
		`SELECT count(*) FROM "DeveloperApplication" WHERE "id" = $1 AND "owner_id" = $2`,
		applicationID, winningOwner,
	); owners != 1 {
		t.Error("the application does not belong to the winner's owner")
	}

	if callbacks := count(t, pool, `SELECT count(*) FROM "CallbackUri"`); callbacks != 1 {
		t.Errorf("%d callbacks exist, want the winner's one", callbacks)
	}
}

// A provisioning cancelled after it has written the owner, while it waits on
// the identifier, leaves no owner, application or callback, and holds nothing
// that stops the next provisioning.
func TestCancelledProvisioningLeavesNothing(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	applicationID := uuid.New()

	competitor, _ := competingProvisioner(t, pool, applicationID)

	ctx, cancel := context.WithCancel(t.Context())

	provisioned := make(chan error, 1)

	go func() {
		_, err := siteapplication.Provision(ctx, pool, applicationID, siteCallback)
		provisioned <- err
	}()

	if err := testdatabase.AwaitLockWaiters(t.Context(), pool, 1); err != nil {
		t.Fatalf("waiting for provisioning to block on the identifier: %v", err)
	}

	cancel()

	if err := <-provisioned; err == nil {
		t.Fatal("a cancelled provisioning reported success")
	}

	if err := competitor.Rollback(t.Context()); err != nil {
		t.Fatalf("abandoning the competing provisioner: %v", err)
	}

	if state := databaseState(t, pool); state != "" {
		t.Errorf("the cancelled provisioning left rows behind:\n%s", state)
	}

	outcome, err := siteapplication.Provision(t.Context(), pool, applicationID, siteCallback)
	if err != nil {
		t.Fatalf("provisioning after the cancelled attempt: %v", err)
	}

	if outcome != siteapplication.Created {
		t.Errorf("outcome = %v, want Created", outcome)
	}
}
