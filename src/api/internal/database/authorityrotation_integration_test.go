//go:build integration && !devtools

package database_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

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

// rotationSettleTimeout bounds how long a rotation may take to report after it
// was cancelled or its lock was released.
const rotationSettleTimeout = 10 * time.Second

// everythingWithdrawn is what a rotation reports after withdrawing exactly what
// issueOutstanding created.
var everythingWithdrawn = database.AuthorityRotation{
	AbandonedLogins:    1,
	AbandonedExchanges: 1,
	EndedSessions:      1,
	ClearedRevocations: 1,
}

// outstanding is one of every credential class a rotation must withdraw.
type outstanding struct {
	register    *authority.Authority
	logins      *oauth.Store
	codes       *oauth.ExchangeCodes
	sessions    *sessions.Store
	application uuid.UUID
	login       oauth.Start
	code        string
	session     string
	withdrawn   uuid.UUID
}

func issueOutstanding(t *testing.T, pool *pgxpool.Pool) outstanding {
	t.Helper()

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

	application, _, err := applications.New(pool, nil).Create(ctx, person.ID, "an application")
	if err != nil {
		t.Fatalf("registering an application: %v", err)
	}

	issued := outstanding{register: authority.New(pool), application: application.ID}

	if issued.logins, err = oauth.NewStore(pool, keys.VerifierEncryption()); err != nil {
		t.Fatalf("preparing the login store: %v", err)
	}

	if issued.login, err = issued.logins.Begin(
		ctx, oauth.Discord, application.ID, "https://relying.example.test/return", "",
	); err != nil {
		t.Fatalf("starting a login: %v", err)
	}

	if issued.codes, err = oauth.NewExchangeCodes(pool, 2*time.Minute); err != nil {
		t.Fatalf("preparing the one-time codes: %v", err)
	}

	if issued.code, err = issued.codes.Issue(ctx, person.ID, application.ID, oauth.Discord); err != nil {
		t.Fatalf("issuing a one-time code: %v", err)
	}

	if issued.sessions, err = sessions.NewStore(pool, sessions.Options{Lifetime: 24 * time.Hour}); err != nil {
		t.Fatalf("preparing the session store: %v", err)
	}

	session, err := issued.sessions.Create(ctx, person.ID)
	if err != nil {
		t.Fatalf("signing a browser in: %v", err)
	}

	issued.session = session.Value

	issued.withdrawn = uuid.New()
	if err := issued.register.Withdraw(ctx, issued.withdrawn, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("withdrawing a token: %v", err)
	}

	return issued
}

func (o outstanding) current(t *testing.T) uuid.UUID {
	t.Helper()

	epoch, err := o.register.Current(t.Context())
	if err != nil {
		t.Fatalf("reading the authority: %v", err)
	}

	return epoch
}

// expectNothingHonoured states the one promise a completed rotation makes about
// what it withdrew.
func (o outstanding) expectNothingHonoured(t *testing.T, before uuid.UUID) {
	t.Helper()

	ctx := t.Context()

	if o.current(t) == before {
		t.Error("the authority did not change, so every credential stamped with it still stands")
	}

	if _, err := o.logins.Consume(
		ctx, oauth.Discord, o.login.State, o.login.BrowserBinding,
	); !errors.Is(err, oauth.ErrNoSuchLogin) {
		t.Errorf("a login in progress outlived the rotation: %v", err)
	}

	if _, err := o.codes.Redeem(ctx, o.code, o.application); !errors.Is(err, oauth.ErrNoSuchCode) {
		t.Errorf("a one-time code outlived the rotation: %v", err)
	}

	if _, err := o.sessions.Lookup(ctx, o.session); !errors.Is(err, sessions.ErrNoSuchSession) {
		t.Errorf("a browser session outlived the rotation: %v", err)
	}

	// The withdrawals are cleared because there is nothing left for them to
	// refuse: a token one of them named carries the authority that has just
	// been replaced, and the epoch check refuses it on its own.
	stillWithdrawn, err := o.register.IsWithdrawn(ctx, o.withdrawn)
	if err != nil {
		t.Fatalf("reading whether a token was withdrawn: %v", err)
	}

	if stillWithdrawn {
		t.Error("a withdrawal was reported as cleared while it was still recorded")
	}
}

// Rotating the authority makes one promise: nothing this service was holding
// for anybody is honoured afterwards, and the value every credential is
// measured against is no longer the one they were stamped with.
func TestRotatingAuthorityWithdrawsEverythingOutstanding(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	issued := issueOutstanding(t, pool)
	before := issued.current(t)

	rotation, err := database.RotateAuthority(t.Context(), pool)
	if err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	if rotation != everythingWithdrawn {
		t.Errorf("the rotation reported %+v, want %+v", rotation, everythingWithdrawn)
	}

	issued.expectNothingHonoured(t, before)
}

// Anything else replacing authority-bound state holds the auth epoch's row, so
// a rotation waits for it rather than interleaving; a rotation abandoned while
// waiting changes nothing, and one waiting when the row is released completes.
func TestRotatingAuthorityWaitsForAuthorityRowLock(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	ctx := t.Context()
	issued := issueOutstanding(t, pool)
	before := issued.current(t)

	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("starting the transaction that holds the authority: %v", err)
	}

	defer func() { _ = holder.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := holder.Exec(ctx, `SELECT epoch FROM auth_epoch WHERE singleton FOR UPDATE`); err != nil {
		t.Fatalf("holding the authority: %v", err)
	}

	abandoned, abandon := context.WithCancel(ctx)
	defer abandon()

	cancelled := rotateInBackground(abandoned, pool)

	if err := testdatabase.AwaitLockWaiters(ctx, pool, 1); err != nil {
		t.Fatalf("the rotation never waited for the authority: %v", err)
	}

	abandon()

	if result := awaitRotation(t, cancelled); result.err == nil {
		t.Fatalf("a rotation abandoned while waiting reported success: %+v", result.rotation)
	}

	if issued.current(t) != before {
		t.Error("a rotation abandoned while waiting replaced the authority")
	}

	waiting := rotateInBackground(ctx, pool)

	if err := testdatabase.AwaitLockWaiters(ctx, pool, 1); err != nil {
		t.Fatalf("the second rotation never waited for the authority: %v", err)
	}

	select {
	case result := <-waiting:
		t.Fatalf("a rotation finished while the authority was held: %+v, %v", result.rotation, result.err)
	default:
	}

	if err := holder.Rollback(ctx); err != nil {
		t.Fatalf("releasing the authority: %v", err)
	}

	result := awaitRotation(t, waiting)
	if result.err != nil {
		t.Fatalf("the rotation waiting for the authority failed once it was released: %v", result.err)
	}

	// Every class is still counted, so the abandoned rotation deleted nothing.
	if result.rotation != everythingWithdrawn {
		t.Errorf("the rotation reported %+v, want %+v", result.rotation, everythingWithdrawn)
	}

	issued.expectNothingHonoured(t, before)
}

type rotationResult struct {
	rotation database.AuthorityRotation
	err      error
}

func rotateInBackground(ctx context.Context, pool *pgxpool.Pool) <-chan rotationResult {
	finished := make(chan rotationResult, 1)

	go func() {
		rotation, err := database.RotateAuthority(ctx, pool)
		finished <- rotationResult{rotation: rotation, err: err}
	}()

	return finished
}

func awaitRotation(t *testing.T, finished <-chan rotationResult) rotationResult {
	t.Helper()

	select {
	case result := <-finished:
		return result
	case <-time.After(rotationSettleTimeout):
		t.Fatal("the rotation never reported")

		return rotationResult{}
	}
}
