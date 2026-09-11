//go:build integration && !devtools

package database_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/authority"
	"github.com/abandontech/abandonauth/src/api/internal/services/keyring"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/sessions"
)

// rotationRootSecret is a placeholder the test derives its keys from. It is long
// enough for the derivation and stands for nothing a deployment holds.
const rotationRootSecret = "placeholder-rotation-secret-placeholder-rotation-secret-placeholder"

// Rotating the authority makes one promise: nothing this service was holding
// for anybody is honoured afterwards, and the value every credential is
// measured against is no longer the one they were stamped with.
func TestRotatingTheAuthorityWithdrawsEverythingOutstanding(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	ctx := t.Context()

	keys, err := keyring.New(rotationRootSecret)
	if err != nil {
		t.Fatalf("deriving the test keys: %v", err)
	}

	person, err := accounts.New(pool).Resolve(ctx, accounts.Identity{
		Provider: oauth.Discord,
		ID:       "1",
		Username: "someone",
	})
	if err != nil {
		t.Fatalf("registering an account: %v", err)
	}

	registry := applications.New(pool)

	application, _, err := registry.Create(ctx, person.ID, "an application")
	if err != nil {
		t.Fatalf("registering an application: %v", err)
	}

	logins, err := oauth.NewStore(pool, keys.VerifierEncryption())
	if err != nil {
		t.Fatalf("preparing the login store: %v", err)
	}

	started, err := logins.Begin(
		ctx, oauth.Discord, application.ID, "https://relying.example.test/return", "",
	)
	if err != nil {
		t.Fatalf("starting a login: %v", err)
	}

	codes, err := oauth.NewExchangeCodes(pool, 2*time.Minute)
	if err != nil {
		t.Fatalf("preparing the one-time codes: %v", err)
	}

	code, err := codes.Issue(ctx, person.ID, application.ID, oauth.Discord)
	if err != nil {
		t.Fatalf("issuing a one-time code: %v", err)
	}

	browserSessions, err := sessions.NewStore(pool, sessions.Options{Lifetime: 24 * time.Hour})
	if err != nil {
		t.Fatalf("preparing the session store: %v", err)
	}

	issued, err := browserSessions.Create(ctx, person.ID)
	if err != nil {
		t.Fatalf("signing a browser in: %v", err)
	}

	register := authority.New(pool)

	before, err := register.Current(ctx)
	if err != nil {
		t.Fatalf("reading the authority: %v", err)
	}

	withdrawn := uuid.New()
	if err := register.Withdraw(ctx, withdrawn, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("withdrawing a token: %v", err)
	}

	rotation, err := database.RotateAuthority(ctx, pool)
	if err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	want := database.AuthorityRotation{
		AbandonedLogins:    1,
		AbandonedExchanges: 1,
		EndedSessions:      1,
		ClearedRevocations: 1,
	}

	if rotation != want {
		t.Errorf("the rotation reported %+v, want %+v", rotation, want)
	}

	after, err := register.Current(ctx)
	if err != nil {
		t.Fatalf("reading the authority after the rotation: %v", err)
	}

	if after == before {
		t.Error("the authority did not change, so every credential stamped with it still stands")
	}

	if _, err := logins.Consume(
		ctx, oauth.Discord, started.State, started.BrowserBinding,
	); !errors.Is(err, oauth.ErrNoSuchLogin) {
		t.Errorf("a login in progress outlived the rotation: %v", err)
	}

	if _, err := codes.Redeem(ctx, code, application.ID); !errors.Is(err, oauth.ErrNoSuchCode) {
		t.Errorf("a one-time code outlived the rotation: %v", err)
	}

	if _, err := browserSessions.Lookup(ctx, issued.Value); !errors.Is(err, sessions.ErrNoSuchSession) {
		t.Errorf("a browser session outlived the rotation: %v", err)
	}

	// The withdrawals are cleared because there is nothing left for them to
	// refuse: a token one of them named carries the authority that has just
	// been replaced, and the epoch check refuses it on its own.
	stillWithdrawn, err := register.IsWithdrawn(ctx, withdrawn)
	if err != nil {
		t.Fatalf("reading whether a token was withdrawn: %v", err)
	}

	if stillWithdrawn {
		t.Error("a withdrawal was reported as cleared while it was still recorded")
	}
}
