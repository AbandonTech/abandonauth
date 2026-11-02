//go:build integration && !devtools

package database_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/keyring"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// nativeTemplate is the loopback callback the test's public client registers.
const nativeTemplate = "http://127.0.0.1/oauth/callback"

// nativeRedirect is that template with a port the client chose at run time.
const nativeRedirect = "http://127.0.0.1:49152/oauth/callback"

// nativeServices are the services a public client's authorization goes
// through, over one database, with one person and one public client.
type nativeServices struct {
	pool         *pgxpool.Pool
	applications *applications.Applications
	accounts     *accounts.Accounts
	requests     *oauth.AuthorizationRequests
	codes        *oauth.AuthorizationCodes
	refresh      *oauth.RefreshTokens
	subjects     *oauth.PairwiseSubjects
	issuer       *oidc.Issuer
	verifier     *oidc.AccessTokenVerifier

	person uuid.UUID
	client applications.Application
}

func newNativeServices(t *testing.T, pool *pgxpool.Pool) nativeServices {
	t.Helper()

	return newNativeServicesDrawing(t, pool, nil)
}

func newNativeServicesDrawing(t *testing.T, pool *pgxpool.Pool, drawSubject func() (string, error)) nativeServices {
	t.Helper()

	ctx := t.Context()

	derived, err := keyring.New(rotationRootSecret)
	if err != nil {
		t.Fatalf("deriving the test keys: %v", err)
	}

	logins, err := oauth.NewStore(pool, derived.VerifierEncryption())
	if err != nil {
		t.Fatalf("preparing the login store: %v", err)
	}

	material := servertest.SigningKeyFiles(t)

	keys, err := oidc.ParseSigningKeys(material.IDTokenPEM, material.AccessTokenPEM)
	if err != nil {
		t.Fatalf("reading the test signing keys: %v", err)
	}

	issuer, err := oidc.NewIssuer(servertest.OpenIDIssuer, keys, nil)
	if err != nil {
		t.Fatalf("building the issuer: %v", err)
	}

	subjects := oauth.NewPairwiseSubjects(pool, drawSubject)

	services := nativeServices{
		pool:         pool,
		applications: applications.New(pool, nil),
		accounts:     accounts.New(pool),
		requests:     oauth.NewAuthorizationRequests(pool, logins),
		codes:        oauth.NewAuthorizationCodes(pool, subjects),
		refresh:      oauth.NewRefreshTokens(pool),
		subjects:     subjects,
		issuer:       issuer,
		verifier:     oidc.NewAccessTokenVerifier(servertest.OpenIDIssuer, keys, nil),
	}

	services.person = services.newPerson(t, "1")

	if services.client, _, err = services.applications.Create(
		ctx, services.person, "an installed application", applications.Public,
	); err != nil {
		t.Fatalf("registering a public client: %v", err)
	}

	if err := services.applications.ReplaceCallbackURIs(ctx, services.client, []string{nativeTemplate}); err != nil {
		t.Fatalf("registering the loopback template: %v", err)
	}

	return services
}

func (s nativeServices) newPerson(t *testing.T, providerID string) uuid.UUID {
	t.Helper()

	person, err := s.accounts.Resolve(t.Context(), accounts.Identity{
		Provider: oauth.GitHub, ID: providerID, Username: "person " + providerID,
	})
	if err != nil {
		t.Fatalf("registering a person: %v", err)
	}

	return person.ID
}

// sign is the token signer a token endpoint would pass.
func (s nativeServices) sign(grant oauth.Grant) (oauth.SignedTokens, error) {
	access, _, err := s.issuer.IssueAccessToken(oidc.Access{
		Subject: grant.Subject, ClientID: grant.ClientID, Scopes: grant.Scopes, AuthEpoch: grant.AuthEpoch,
	})
	if err != nil {
		return oauth.SignedTokens{}, err
	}

	identity := oidc.Identity{Subject: grant.Subject, ClientID: grant.ClientID, AuthTime: grant.AuthTime, Nonce: grant.Nonce}
	if grant.Scopes.Has(oidc.ScopeProfile) {
		identity.Username = &grant.Username
	}

	id, err := s.issuer.IssueIDToken(identity)
	if err != nil {
		return oauth.SignedTokens{}, err
	}

	return oauth.SignedTokens{AccessToken: access, IDToken: id}, nil
}

// pending is an authorization begun for the test's client.
type pending struct {
	oauth.Begun

	verifier string
	state    string
}

func (s nativeServices) begin(t *testing.T, scopes oidc.Scopes, heldBinding string) pending {
	t.Helper()

	verifier := strings.Repeat("v", 43) + uuid.NewString()[:8]
	challenge, _ := oauth.ChallengeForVerifier(verifier)
	state := strings.Repeat("s", 43)

	begun, err := s.requests.Begin(t.Context(), oauth.AuthorizationRequest{
		ApplicationID: s.client.ID,
		RedirectURI:   nativeRedirect,
		Scopes:        scopes,
		ClientState:   state,
		ClientNonce:   strings.Repeat("n", 43),
		CodeChallenge: challenge,
		HeldBinding:   heldBinding,
	})
	if err != nil {
		t.Fatalf("beginning an authorization: %v", err)
	}

	return pending{Begun: begun, verifier: verifier, state: state}
}

// authorize takes a begun authorization through Discord to its code, as the
// provider callback would for a person this service resolved.
func (s nativeServices) authorize(t *testing.T, begun pending, person uuid.UUID) string {
	t.Helper()

	ctx := t.Context()

	started, err := s.requests.BeginProvider(ctx, begun.PageHandle, begun.BrowserBinding, oauth.Discord)
	if err != nil {
		t.Fatalf("choosing a provider: %v", err)
	}

	login, err := s.requests.ConsumeProvider(ctx, oauth.Discord, started.State, begun.BrowserBinding)
	if err != nil {
		t.Fatalf("returning from the provider: %v", err)
	}

	if login.Native == nil || login.Native.RedirectURI != nativeRedirect || login.Native.ClientState != begun.state ||
		login.CallbackURI != "" || login.Verifier == "" {
		t.Fatalf("the provider sign-in does not continue the authorization: %+v", login.Native)
	}

	code, err := s.requests.CompleteProvider(ctx, *login.Native, person)
	if err != nil {
		t.Fatalf("completing the authorization: %v", err)
	}

	return code
}

func (s nativeServices) redeem(t *testing.T, code, verifier string) oauth.IssuedTokens {
	t.Helper()

	issued, err := s.codes.Redeem(t.Context(), oauth.Redemption{
		ClientID: s.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: verifier,
	}, s.sign)
	if err != nil {
		t.Fatalf("redeeming the code: %v", err)
	}

	return issued
}

func (s nativeServices) signIn(t *testing.T, scopes oidc.Scopes, person uuid.UUID) oauth.IssuedTokens {
	t.Helper()

	begun := s.begin(t, scopes, "")

	return s.redeem(t, s.authorize(t, begun, person), begun.verifier)
}

func (s nativeServices) subjectOf(t *testing.T, issued oauth.IssuedTokens) string {
	t.Helper()

	claims, err := s.verifier.Verify(issued.AccessToken)
	if err != nil {
		t.Fatalf("the issued access token is refused: %v", err)
	}

	return claims.Subject
}

// A public client holds no credential, and the table itself refuses one, so a
// build that knows nothing of client types cannot give it one either.
func TestPublicClientHoldsNoCredentialAnywhere(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	public, token, err := services.applications.Create(ctx, services.person, "another installed application", applications.Public)
	if err != nil || token != "" || public.ClientType != applications.Public {
		t.Fatalf("creating a public client returned a credential or failed: %v", err)
	}

	confidential, secret, err := services.applications.Create(ctx, services.person, "a server", applications.Confidential)
	if err != nil || secret == "" {
		t.Fatalf("creating a confidential application: %v", err)
	}

	for _, presented := range []string{secret, applications.UnknownApplicationComparisonInput, "x"} {
		if _, err := services.applications.Authenticate(ctx, public.ID, presented); !errors.Is(
			err, applications.ErrInvalidCredential,
		) {
			t.Errorf("a public client authenticated: %v", err)
		}
	}

	if _, _, err := services.applications.ReplaceCredential(ctx, public.ID); !errors.Is(
		err, applications.ErrPublicClientHasNoCredential,
	) {
		t.Errorf("a public client's credential was reset: %v", err)
	}

	if _, err := services.applications.Authenticate(ctx, confidential.ID, secret); err != nil {
		t.Errorf("a confidential application no longer authenticates: %v", err)
	}

	// The reset a build without client types issues, against each row.
	const reset = `UPDATE "DeveloperApplication"
		SET "refresh_token" = $2, "credential_version" = "credential_version" + 1 WHERE "id" = $1`

	if _, err := pool.Exec(ctx, reset, public.ID, "$2a$12$placeholderplaceholderplaceholderplaceholderplacehol"); err == nil {
		t.Error("the table accepted a credential for a public client")
	}

	if _, err := pool.Exec(ctx, reset, confidential.ID, "$2a$12$placeholderplaceholderplaceholderplaceholderplacehol"); err != nil {
		t.Errorf("the table refused a confidential application's reset: %v", err)
	}

	if _, err := services.applications.PublicClient(ctx, confidential.ID); !errors.Is(err, applications.ErrNoSuchApplication) {
		t.Errorf("a confidential application was treated as a public client: %v", err)
	}

	if found, err := services.applications.PublicClient(ctx, public.ID); err != nil || found.ClientType != applications.Public {
		t.Errorf("a public client was not found: %v", err)
	}

	listed, err := services.applications.ListByOwner(ctx, services.person)
	if err != nil || len(listed) != 3 {
		t.Fatalf("listing the owner's applications: %v", err)
	}

	if redirect, matched, err := services.applications.NativeRedirect(ctx, services.client, nativeRedirect); err != nil ||
		!matched || redirect != nativeRedirect {
		t.Errorf("the registered template does not match its redirect: %v", err)
	}

	if _, matched, _ := services.applications.NativeRedirect(ctx, services.client, "http://127.0.0.1:1/other"); matched {
		t.Error("an unregistered redirect matched")
	}

	if _, matched, _ := services.applications.NativeRedirect(ctx, confidential, nativeRedirect); matched {
		t.Error("a confidential application matched a loopback redirect")
	}
}

// One authorization, from its page to its tokens, with every binding enforced
// along the way and every credential spent once.
func TestNativeAuthorizationIssuesBoundTokensOnce(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()
	scopes := oidc.ScopeOpenID | oidc.ScopeProfile | oidc.ScopeOfflineAccess

	begun := services.begin(t, scopes, "")

	viewed, err := services.requests.View(ctx, begun.PageHandle, begun.BrowserBinding)
	if err != nil || viewed.ApplicationName != "an installed application" || viewed.Scopes != scopes {
		t.Fatalf("viewing the authorization: %+v, %v", viewed, err)
	}

	otherBrowser := services.begin(t, oidc.ScopeOpenID, "").BrowserBinding

	if _, err := services.requests.View(ctx, begun.PageHandle, otherBrowser); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("another browser viewed the authorization: %v", err)
	}

	if _, err := services.requests.BeginProvider(ctx, begun.PageHandle, otherBrowser, oauth.Discord); !errors.Is(
		err, oauth.ErrNoSuchAuthorization,
	) {
		t.Errorf("another browser chose a provider: %v", err)
	}

	code := services.authorize(t, begun, services.person)

	if _, err := services.requests.View(ctx, begun.PageHandle, begun.BrowserBinding); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("a spent page was viewed again: %v", err)
	}

	for name, wrong := range map[string]oauth.Redemption{
		"a wrong verifier": {ClientID: services.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: strings.Repeat("w", 43)},
		"another port":     {ClientID: services.client.ID, Code: code, RedirectURI: "http://127.0.0.1:49153/oauth/callback", Verifier: begun.verifier},
		"another client":   {ClientID: uuid.New(), Code: code, RedirectURI: nativeRedirect, Verifier: begun.verifier},
	} {
		if _, err := services.codes.Redeem(ctx, wrong, services.sign); !errors.Is(err, oauth.ErrInvalidGrant) {
			t.Errorf("%s redeemed the code: %v", name, err)
		}
	}

	issued := services.redeem(t, code, begun.verifier)

	if issued.Scopes != scopes || issued.RefreshToken == "" || issued.RefreshExpiresIn <= 0 ||
		issued.RefreshExpiresIn > 2592000 || issued.IDToken == "" {
		t.Errorf("the token set is not the granted one: %+v", issued.Scopes)
	}

	if _, err := services.codes.Redeem(ctx, oauth.Redemption{
		ClientID: services.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: begun.verifier,
	}, services.sign); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Errorf("a code was redeemed twice: %v", err)
	}

	subject := services.subjectOf(t, issued)
	if subject == services.person.String() || len(subject) != 43 {
		t.Errorf("the subject is not a pairwise subject")
	}

	if again := services.subjectOf(t, services.signIn(t, oidc.ScopeOpenID, services.person)); again != subject {
		t.Error("the subject changed between sign-ins")
	}

	other := services.newPerson(t, "2")
	if services.subjectOf(t, services.signIn(t, oidc.ScopeOpenID, other)) == subject {
		t.Error("two people share a subject at one application")
	}

	claims, _ := services.verifier.Verify(issued.AccessToken)

	holder, err := services.subjects.Holder(ctx, services.client.ID, subject, claims.Identifier(), uuid.MustParse(claims.AuthEpoch))
	if err != nil || holder.Username != "person 1" {
		t.Errorf("the access token's holder was not resolved: %v", err)
	}

	if _, err := services.subjects.Holder(ctx, services.client.ID, subject, claims.Identifier(), uuid.New()); !errors.Is(
		err, oauth.ErrAccessNotGranted,
	) {
		t.Errorf("a token of another authority resolved: %v", err)
	}
}

// Refresh tokens rotate once each, a reused one ends its family, and a refresh
// can narrow its grant but never widen it.
func TestRefreshTokensRotateOnceAndReuseEndsFamily(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	issued := services.signIn(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, services.person)
	first := issued.RefreshToken

	widened := oidc.ScopeOpenID | oidc.ScopeProfile | oidc.ScopeOfflineAccess
	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: first, Scopes: &widened}, services.sign); !errors.Is(
		err, oauth.ErrScopeNotGranted,
	) {
		t.Errorf("a refresh widened its grant: %v", err)
	}

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: uuid.New(), Token: first}, services.sign); !errors.Is(
		err, oauth.ErrInvalidGrant,
	) {
		t.Errorf("another client rotated the token: %v", err)
	}

	rotated, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: first}, services.sign)
	if err != nil || rotated.RefreshToken == "" || rotated.RefreshToken == first || rotated.RefreshExpiresIn > 2592000 {
		t.Fatalf("rotating the refresh token: %v", err)
	}

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: first}, services.sign); !errors.Is(
		err, oauth.ErrInvalidGrant,
	) {
		t.Errorf("a consumed refresh token was accepted: %v", err)
	}

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: rotated.RefreshToken}, services.sign); !errors.Is(
		err, oauth.ErrInvalidGrant,
	) {
		t.Errorf("the family outlived the reuse of one of its tokens: %v", err)
	}

	narrowing := services.signIn(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, services.person)
	onlyOpenID := oidc.ScopeOpenID

	narrowed, err := services.refresh.Rotate(ctx, oauth.Refresh{
		ClientID: services.client.ID, Token: narrowing.RefreshToken, Scopes: &onlyOpenID,
	}, services.sign)
	if err != nil || narrowed.RefreshToken != "" || narrowed.Scopes != oidc.ScopeOpenID {
		t.Fatalf("narrowing away offline access: %v", err)
	}

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: narrowing.RefreshToken}, services.sign); !errors.Is(
		err, oauth.ErrInvalidGrant,
	) {
		t.Errorf("narrowing away offline access left the family usable: %v", err)
	}

	revoked := services.signIn(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, services.person)

	if err := services.refresh.Revoke(ctx, uuid.New(), revoked.RefreshToken); err != nil {
		t.Fatalf("revoking for another client: %v", err)
	}

	if err := services.refresh.Revoke(ctx, services.client.ID, revoked.RefreshToken); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: revoked.RefreshToken}, services.sign); !errors.Is(
		err, oauth.ErrInvalidGrant,
	) {
		t.Errorf("a revoked family was rotated: %v", err)
	}

	failing := func(oauth.Grant) (oauth.SignedTokens, error) {
		return oauth.SignedTokens{}, errors.New("signing failed")
	}

	unsigned := services.signIn(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, services.person)
	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: unsigned.RefreshToken}, failing); err == nil {
		t.Fatal("a refresh succeeded without its tokens")
	}

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: unsigned.RefreshToken}, services.sign); err != nil {
		t.Errorf("a refresh that could not sign consumed its token: %v", err)
	}
}

// A code whose tokens could not be signed is left for a retry.
func TestUnsignedRedemptionLeavesCodeUsable(t *testing.T) {
	t.Parallel()

	services := newNativeServices(t, testdatabase.NewMigrated(t))
	begun := services.begin(t, oidc.ScopeOpenID, "")
	code := services.authorize(t, begun, services.person)

	if _, err := services.codes.Redeem(t.Context(), oauth.Redemption{
		ClientID: services.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: begun.verifier,
	}, func(oauth.Grant) (oauth.SignedTokens, error) {
		return oauth.SignedTokens{}, errors.New("signing failed")
	}); err == nil {
		t.Fatal("a redemption succeeded without its tokens")
	}

	services.redeem(t, code, begun.verifier)
}

// A code whose subject could not be resolved is left for a retry, and the
// failure is reported as a failure, never as a refused grant.
func TestRedemptionFailingPartwayLeavesCodeUsable(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	begun := services.begin(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, "")
	code := services.authorize(t, begun, services.person)

	testdatabase.Execute(t, pool, `ALTER TABLE oauth_pairwise_subject RENAME TO unreachable`)

	if _, err := services.codes.Redeem(t.Context(), oauth.Redemption{
		ClientID: services.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: begun.verifier,
	}, services.sign); err == nil || errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("a redemption without its subject store reported %v, want a failure", err)
	}

	testdatabase.Execute(t, pool, `ALTER TABLE unreachable RENAME TO oauth_pairwise_subject`)

	if issued := services.redeem(t, code, begun.verifier); issued.RefreshToken == "" {
		t.Error("the retried redemption issued no refresh token for an offline grant")
	}
}

// Every operation reports a database it cannot reach as a failure: never as a
// refusal a caller would answer as the client's fault, and never as a grant.
func TestNativeOperationsReportUnreachableDatabase(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()
	// Well formed, so every operation reaches the database.
	opaque := strings.Repeat("A", 43)

	logins, err := oauth.NewStore(pool, make([]byte, 32))
	if err != nil {
		t.Fatalf("preparing the login store: %v", err)
	}

	exchanges, err := oauth.NewExchangeCodes(pool, time.Minute)
	if err != nil {
		t.Fatalf("preparing the one-time codes: %v", err)
	}

	pool.Close()

	refusals := []error{
		oauth.ErrNoSuchAuthorization, oauth.ErrNoSuchLogin, oauth.ErrInvalidGrant, oauth.ErrAccessNotGranted,
		oauth.ErrNoSuchCode, oauth.ErrAuthorizationCapacity,
	}

	for name, operation := range map[string]func() error{
		"begin an authorization": func() error {
			_, err := services.requests.Begin(ctx, oauth.AuthorizationRequest{
				ApplicationID: services.client.ID, RedirectURI: nativeRedirect, Scopes: oidc.ScopeOpenID,
				ClientState: opaque, ClientNonce: opaque, CodeChallenge: opaque,
			})

			return err
		},
		"view an authorization": func() error {
			_, err := services.requests.View(ctx, opaque, opaque)

			return err
		},
		"choose a provider": func() error {
			_, err := services.requests.BeginProvider(ctx, opaque, opaque, oauth.GitHub)

			return err
		},
		"cancel an authorization": func() error {
			_, err := services.requests.Cancel(ctx, opaque, opaque)

			return err
		},
		"consume a provider sign-in": func() error {
			_, err := services.requests.ConsumeProvider(ctx, oauth.GitHub, opaque, opaque)

			return err
		},
		"complete an authorization": func() error {
			_, err := services.requests.CompleteProvider(ctx, oauth.NativeContinuation{AuthorizationID: uuid.New()}, services.person)

			return err
		},
		"sweep authorizations": func() error {
			_, err := services.requests.Forget(ctx)

			return err
		},
		"redeem a code": func() error {
			_, err := services.codes.Redeem(ctx, oauth.Redemption{
				ClientID: services.client.ID, Code: opaque, RedirectURI: nativeRedirect, Verifier: opaque,
			}, services.sign)

			return err
		},
		"rotate a refresh token": func() error {
			_, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: opaque}, services.sign)

			return err
		},
		"revoke a refresh token": func() error {
			return services.refresh.Revoke(ctx, services.client.ID, opaque)
		},
		"sweep families": func() error {
			_, err := services.refresh.Forget(ctx)

			return err
		},
		"resolve an access token's holder": func() error {
			_, err := services.subjects.Holder(ctx, services.client.ID, opaque, uuid.New(), uuid.New())

			return err
		},
		"revoke an access token": func() error {
			return services.subjects.RevokeAccessToken(ctx, oauth.AccessRevocation{
				ClientID: services.client.ID, Subject: opaque, TokenID: uuid.New(), ExpiresAt: time.Now().Add(time.Minute),
			})
		},
		"sweep revocations": func() error {
			_, err := services.subjects.ForgetRevocations(ctx)

			return err
		},
		"begin a confidential login": func() error {
			_, err := logins.Begin(ctx, oauth.GitHub, services.client.ID, "https://relying.example.test/return", "")

			return err
		},
		"consume a confidential login": func() error {
			_, err := logins.Consume(ctx, oauth.GitHub, opaque, opaque)

			return err
		},
		"sweep logins": func() error {
			_, err := logins.Forget(ctx)

			return err
		},
		"issue a one-time code": func() error {
			_, err := exchanges.Issue(ctx, services.person, services.client.ID, oauth.GitHub)

			return err
		},
		"redeem a one-time code": func() error {
			_, err := exchanges.Redeem(ctx, opaque, services.client.ID)

			return err
		},
		"sweep one-time codes": func() error {
			_, err := exchanges.Forget(ctx)

			return err
		},
	} {
		err := operation()
		if err == nil {
			t.Errorf("%s: succeeded without a database", name)

			continue
		}

		for _, refusal := range refusals {
			if errors.Is(err, refusal) {
				t.Errorf("%s: reported an unreachable database as %v", name, refusal)
			}
		}
	}
}

// Of a provider choice and a cancellation racing for one authorization, and of
// two redemptions racing for one code, exactly one wins.
func TestRacingTransitionsHaveExactlyOneWinner(t *testing.T) {
	t.Parallel()

	services := newNativeServices(t, testdatabase.NewMigrated(t))
	ctx := t.Context()

	for range 5 {
		begun := services.begin(t, oidc.ScopeOpenID, "")

		var (
			waiting sync.WaitGroup
			chose   error
			denied  error
		)

		waiting.Add(2)

		go func() {
			defer waiting.Done()

			_, chose = services.requests.BeginProvider(ctx, begun.PageHandle, begun.BrowserBinding, oauth.GitHub)
		}()

		go func() {
			defer waiting.Done()

			_, denied = services.requests.Cancel(ctx, begun.PageHandle, begun.BrowserBinding)
		}()

		waiting.Wait()

		if (chose == nil) == (denied == nil) {
			t.Fatalf("choice and cancellation both reported %v and %v", chose, denied)
		}
	}

	begun := services.begin(t, oidc.ScopeOpenID, "")
	code := services.authorize(t, begun, services.person)
	results := make(chan error, 4)

	for range 4 {
		go func() {
			_, err := services.codes.Redeem(ctx, oauth.Redemption{
				ClientID: services.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: begun.verifier,
			}, services.sign)
			results <- err
		}()
	}

	succeeded := 0

	for range 4 {
		if err := <-results; err == nil {
			succeeded++
		} else if !errors.Is(err, oauth.ErrInvalidGrant) {
			t.Errorf("a racing redemption failed for another reason: %v", err)
		}
	}

	if succeeded != 1 {
		t.Errorf("%d racing redemptions succeeded, want 1", succeeded)
	}
}

// seedAuthorizations fills the capacity with valid authorizations, as many
// browsers starting them would, without spending a minute doing so.
func seedAuthorizations(t *testing.T, pool *pgxpool.Pool, client uuid.UUID, count int) {
	t.Helper()

	testdatabase.Execute(t, pool, `INSERT INTO oauth_native_authorization (
			application_id, browser_binding_hash, redirect_uri, scopes, client_state, client_nonce,
			code_challenge, stage, page_handle_hash, auth_epoch, expires_at)
		SELECT $1, sha256(('b' || g)::bytea), 'http://127.0.0.1:1/oauth/callback', 'openid',
			repeat('s', 43), repeat('n', 43), repeat('c', 43), 'page', sha256(('h' || g)::bytea),
			(SELECT epoch FROM auth_epoch), CURRENT_TIMESTAMP + interval '5 minutes'
		FROM generate_series(1, $2::int) g`, client, count)
}

func countAuthorizations(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()

	var held int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM oauth_native_authorization`).Scan(&held); err != nil {
		t.Fatalf("counting authorizations: %v", err)
	}

	return held
}

// The service never holds more than its fixed number of authorizations, two
// workers racing for the last slot get one between them, and expiry, rotation
// and terminal use give slots back.
func TestAuthorizationCapacityIsExactAndRecovers(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	seedAuthorizations(t, pool, services.client.ID, oauth.NativeAuthorizationCapacity-1)

	results := make(chan error, 2)

	for range 2 {
		go func() {
			_, err := services.requests.Begin(ctx, oauth.AuthorizationRequest{
				ApplicationID: services.client.ID, RedirectURI: nativeRedirect, Scopes: oidc.ScopeOpenID,
				ClientState: strings.Repeat("s", 43), ClientNonce: strings.Repeat("n", 43),
				CodeChallenge: strings.Repeat("c", 43),
			})
			results <- err
		}()
	}

	refusals := 0

	for range 2 {
		if err := <-results; errors.Is(err, oauth.ErrAuthorizationCapacity) {
			refusals++
		} else if err != nil {
			t.Fatalf("a racing authorization failed for another reason: %v", err)
		}
	}

	if refusals != 1 || countAuthorizations(t, pool) != oauth.NativeAuthorizationCapacity {
		t.Fatalf("racing for the last slot: %d refused, %d held", refusals, countAuthorizations(t, pool))
	}

	testdatabase.Execute(t, pool, `UPDATE oauth_native_authorization
		SET created_at = created_at - interval '10 minutes', expires_at = expires_at - interval '10 minutes'
		WHERE id IN (SELECT id FROM oauth_native_authorization ORDER BY id LIMIT 2)`)

	services.begin(t, oidc.ScopeOpenID, "")

	if held := countAuthorizations(t, pool); held != oauth.NativeAuthorizationCapacity-1 {
		t.Errorf("expired authorizations were not reclaimed: %d held", held)
	}

	if _, err := database.RotateAuthority(ctx, pool); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	if held := countAuthorizations(t, pool); held != 0 {
		t.Errorf("rotation left %d authorizations holding slots", held)
	}

	begun := services.begin(t, oidc.ScopeOpenID, "")
	if _, err := services.requests.Cancel(ctx, begun.PageHandle, begun.BrowserBinding); err != nil {
		t.Fatalf("cancelling: %v", err)
	}

	services.signIn(t, oidc.ScopeOpenID, services.person)

	if held := countAuthorizations(t, pool); held != 0 {
		t.Errorf("cancellation and redemption left %d authorizations holding slots", held)
	}
}

// One person keeps at most ten offline sessions with one application; the
// eleventh replaces the least recently created, and nobody else's is touched.
func TestOfflineSessionsAreBoundedPerPersonAndApplication(t *testing.T) {
	t.Parallel()

	services := newNativeServices(t, testdatabase.NewMigrated(t))
	ctx := t.Context()
	offline := oidc.ScopeOpenID | oidc.ScopeOfflineAccess

	bystander := services.signIn(t, offline, services.newPerson(t, "3"))

	tokens := make([]string, 0, 11)
	for range 11 {
		tokens = append(tokens, services.signIn(t, offline, services.person).RefreshToken)
	}

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: tokens[0]}, services.sign); !errors.Is(
		err, oauth.ErrInvalidGrant,
	) {
		t.Errorf("the least recently created session outlived the eleventh: %v", err)
	}

	for _, token := range append(tokens[1:], bystander.RefreshToken) {
		if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: token}, services.sign); err != nil {
			t.Errorf("a session that should remain was refused: %v", err)
		}
	}
}

// One person keeps at most a thousand unexpired revoked access tokens with one
// application; expired ones are reclaimed first, a repeat costs nothing, and
// nobody else's room is spent.
func TestAccessTokenRevocationsAreBoundedPerPersonAndApplication(t *testing.T) {
	t.Parallel()

	services := newNativeServices(t, testdatabase.NewMigrated(t))
	ctx := t.Context()

	signedIn := services.signIn(t, oidc.ScopeOpenID, services.person)
	subject := services.subjectOf(t, signedIn)
	bystander := services.subjectOf(t, services.signIn(t, oidc.ScopeOpenID, services.newPerson(t, "4")))

	claims, err := services.verifier.Verify(signedIn.AccessToken)
	if err != nil {
		t.Fatalf("the issued access token is refused: %v", err)
	}

	epoch := uuid.MustParse(claims.AuthEpoch)

	if _, err := services.subjects.Holder(ctx, services.client.ID, subject, uuid.New(), epoch); err != nil {
		t.Fatalf("an unrevoked token's holder was not resolved, so the refusal below proves nothing: %v", err)
	}

	revoke := func(subject string, expiresAt time.Time) (uuid.UUID, error) {
		identifier := uuid.New()

		return identifier, services.subjects.RevokeAccessToken(ctx, oauth.AccessRevocation{
			ClientID: services.client.ID, Subject: subject, TokenID: identifier, ExpiresAt: expiresAt,
		})
	}

	later := time.Now().Add(time.Hour)

	for range 5 {
		if _, err := revoke(subject, time.Now().Add(-time.Minute)); err != nil {
			t.Fatalf("recording an expired revocation: %v", err)
		}
	}

	var last uuid.UUID

	for index := range oauth.MaxAccessTokenRevocations {
		identifier, err := revoke(subject, later)
		if err != nil {
			t.Fatalf("revocation %d of the allowance was refused: %v", index+1, err)
		}

		last = identifier
	}

	if _, err := revoke(subject, later); !errors.Is(err, oauth.ErrRevocationCapacity) {
		t.Errorf("a revocation beyond the ceiling = %v", err)
	}

	if err := services.subjects.RevokeAccessToken(ctx, oauth.AccessRevocation{
		ClientID: services.client.ID, Subject: subject, TokenID: last, ExpiresAt: later,
	}); err != nil {
		t.Errorf("repeating a recorded revocation = %v", err)
	}

	if _, err := revoke(bystander, later); err != nil {
		t.Errorf("another person's revocation was refused: %v", err)
	}

	if err := services.subjects.RevokeAccessToken(ctx, oauth.AccessRevocation{
		ClientID: services.client.ID, Subject: strings.Repeat("z", 43), TokenID: uuid.New(), ExpiresAt: later,
	}); err != nil {
		t.Errorf("revoking for an unknown subject = %v, want nothing to record", err)
	}

	if _, err := services.subjects.Holder(ctx, services.client.ID, subject, last, epoch); !errors.Is(
		err, oauth.ErrAccessNotGranted,
	) {
		t.Errorf("a revoked token's holder resolved: %v", err)
	}
}

// A subject drawn twice is never assigned to a second person, a fresh draw is
// tried at most three times, and issuance fails rather than continuing.
func TestSubjectCollisionsRetryThenFailClosed(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)

	// Each ends in a character whose two unused bits are zero, as every value
	// this service draws does.
	taken := strings.Repeat("T", 42) + "A"
	fresh := strings.Repeat("F", 42) + "A"

	always := newNativeServicesDrawing(t, pool, func() (string, error) { return taken, nil })
	first := always.subjectOf(t, always.signIn(t, oidc.ScopeOpenID, always.person))

	if first != taken {
		t.Fatalf("the first person was not given the drawn subject")
	}

	var draws int

	other := always.newPerson(t, "5")
	begun := always.begin(t, oidc.ScopeOpenID, "")
	code := always.authorize(t, begun, other)

	counting := oauth.NewAuthorizationCodes(pool, oauth.NewPairwiseSubjects(pool, func() (string, error) {
		draws++

		return taken, nil
	}))

	if _, err := counting.Redeem(t.Context(), oauth.Redemption{
		ClientID: always.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: begun.verifier,
	}, always.sign); !errors.Is(err, oauth.ErrSubjectUnavailable) {
		t.Fatalf("a colliding subject was issued: %v", err)
	}

	if draws != 3 {
		t.Errorf("drew %d subjects, want exactly 3", draws)
	}

	sequence := []string{taken, taken, fresh}
	recovering := oauth.NewAuthorizationCodes(pool, oauth.NewPairwiseSubjects(pool, func() (string, error) {
		next := sequence[0]
		sequence = sequence[1:]

		return next, nil
	}))

	issued, err := recovering.Redeem(t.Context(), oauth.Redemption{
		ClientID: always.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: begun.verifier,
	}, always.sign)
	if err != nil {
		t.Fatalf("a fresh third draw was not issued: %v", err)
	}

	if always.subjectOf(t, issued) != fresh {
		t.Error("the second person was not given the fresh subject")
	}
}

// Every native change holds the authority shared, so a held rotation stops it,
// and a held change stops a rotation, but changes do not stop one another.
func TestNativeChangesAndRotationAreOrderedByAuthorityLock(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	sharer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("starting a sharing transaction: %v", err)
	}

	defer func() { _ = sharer.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := sharer.Exec(ctx, `SELECT epoch FROM auth_epoch WHERE singleton FOR SHARE`); err != nil {
		t.Fatalf("sharing the authority: %v", err)
	}

	services.begin(t, oidc.ScopeOpenID, "")

	rotating := rotateInBackground(ctx, pool)

	if err := testdatabase.AwaitLockWaiters(ctx, pool, 1); err != nil {
		t.Fatalf("the rotation never waited for a sharing change: %v", err)
	}

	if err := sharer.Rollback(ctx); err != nil {
		t.Fatalf("releasing the authority: %v", err)
	}

	if result := awaitRotation(t, rotating); result.err != nil || result.rotation.AbandonedNativeAuthorizations != 1 {
		t.Fatalf("the rotation after the change: %+v, %v", result.rotation, result.err)
	}

	rotator, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("starting a rotating transaction: %v", err)
	}

	defer func() { _ = rotator.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := rotator.Exec(ctx, `SELECT epoch FROM auth_epoch WHERE singleton FOR UPDATE`); err != nil {
		t.Fatalf("holding the authority: %v", err)
	}

	beginning := make(chan error, 1)

	go func() {
		_, err := services.requests.Begin(ctx, oauth.AuthorizationRequest{
			ApplicationID: services.client.ID, RedirectURI: nativeRedirect, Scopes: oidc.ScopeOpenID,
			ClientState: strings.Repeat("s", 43), ClientNonce: strings.Repeat("n", 43), CodeChallenge: strings.Repeat("c", 43),
		})
		beginning <- err
	}()

	if err := testdatabase.AwaitLockWaiters(ctx, pool, 1); err != nil {
		t.Fatalf("an authorization never waited for a held rotation: %v", err)
	}

	select {
	case err := <-beginning:
		t.Fatalf("an authorization began while a rotation held the authority: %v", err)
	default:
	}

	if _, err := rotator.Exec(ctx, `UPDATE auth_epoch SET epoch = gen_random_uuid() WHERE singleton`); err != nil {
		t.Fatalf("replacing the authority: %v", err)
	}

	if err := rotator.Commit(ctx); err != nil {
		t.Fatalf("committing the rotation: %v", err)
	}

	if err := <-beginning; err != nil {
		t.Fatalf("an authorization after the rotation failed: %v", err)
	}

	if held := countAuthorizations(t, pool); held != 1 {
		t.Errorf("%d authorizations held after the rotation, want the one begun after it", held)
	}
}

// Rotation between a provider sign-in's consumption and its code leaves no code.
func TestRotationDuringProviderSignInIssuesNoCode(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	begun := services.begin(t, oidc.ScopeOpenID, "")

	started, err := services.requests.BeginProvider(ctx, begun.PageHandle, begun.BrowserBinding, oauth.Google)
	if err != nil {
		t.Fatalf("choosing a provider: %v", err)
	}

	if started.Nonce == "" || started.Challenge == "" {
		t.Error("a Google sign-in continuing an authorization lost its nonce or challenge")
	}

	login, err := services.requests.ConsumeProvider(ctx, oauth.Google, started.State, begun.BrowserBinding)
	if err != nil {
		t.Fatalf("returning from the provider: %v", err)
	}

	if _, err := database.RotateAuthority(ctx, pool); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	if _, err := services.requests.CompleteProvider(ctx, *login.Native, services.person); !errors.Is(
		err, oauth.ErrNoSuchAuthorization,
	) {
		t.Errorf("a code was issued after the rotation: %v", err)
	}

	again := services.begin(t, oidc.ScopeOpenID, "")

	started, err = services.requests.BeginProvider(ctx, again.PageHandle, again.BrowserBinding, oauth.Steam)
	if err != nil {
		t.Fatalf("choosing Steam: %v", err)
	}

	login, err = services.requests.ConsumeProvider(ctx, oauth.Steam, started.State, again.BrowserBinding)
	if err != nil || login.Verifier != "" {
		t.Fatalf("returning from Steam: %v", err)
	}

	if _, err := services.requests.ConsumeProvider(ctx, oauth.Steam, started.State, again.BrowserBinding); !errors.Is(
		err, oauth.ErrNoSuchLogin,
	) {
		t.Errorf("a provider sign-in was consumed twice: %v", err)
	}

	if code, err := services.requests.CompleteProvider(ctx, *login.Native, uuid.Nil); err != nil || code != "" {
		t.Fatalf("ending an authorization the provider refused: %v", err)
	}

	if held := countAuthorizations(t, pool); held != 0 {
		t.Errorf("a refused authorization still holds its slot")
	}
}

// Expired authorizations, ended offline sessions and outlived revocations are
// removed by the sweeps, a bounded number at a time.
func TestNativeRecordsAreSweptOnceTheyEnd(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	services.begin(t, oidc.ScopeOpenID, "")
	issued := services.signIn(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, services.person)
	subject := services.subjectOf(t, issued)

	if err := services.subjects.RevokeAccessToken(ctx, oauth.AccessRevocation{
		ClientID: services.client.ID, Subject: subject, TokenID: uuid.New(), ExpiresAt: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatalf("recording a revocation: %v", err)
	}

	for name, forget := range map[string]func(context.Context) (int64, error){
		"authorizations": services.requests.Forget,
		"families":       services.refresh.Forget,
	} {
		if removed, err := forget(ctx); err != nil || removed != 0 {
			t.Errorf("%s: a sweep removed %d live records: %v", name, removed, err)
		}
	}

	testdatabase.Execute(t, pool, `UPDATE oauth_native_authorization
		SET created_at = created_at - interval '10 minutes', expires_at = expires_at - interval '10 minutes'`)
	testdatabase.Execute(t, pool, `UPDATE oauth_refresh_family SET active_until = CURRENT_TIMESTAMP - interval '1 second'`)

	for name, forget := range map[string]func(context.Context) (int64, error){
		"authorizations": services.requests.Forget,
		"families":       services.refresh.Forget,
		"revocations":    services.subjects.ForgetRevocations,
	} {
		if removed, err := forget(ctx); err != nil || removed != 1 {
			t.Errorf("%s: a sweep removed %d ended records, want 1: %v", name, removed, err)
		}
	}

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: issued.RefreshToken}, services.sign); !errors.Is(
		err, oauth.ErrInvalidGrant,
	) {
		t.Errorf("a swept family was rotated: %v", err)
	}
}
