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
	clientUsers  *oauth.PublicClientUsers
	issuer       *oidc.Issuer
	verifier     *oidc.AccessTokenVerifier

	person uuid.UUID
	client applications.Application
}

func newNativeServices(t *testing.T, pool *pgxpool.Pool) nativeServices {
	t.Helper()

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

	clientUsers := oauth.NewPublicClientUsers(pool)

	services := nativeServices{
		pool:         pool,
		applications: applications.New(pool, nil),
		accounts:     accounts.New(pool),
		requests:     oauth.NewAuthorizationRequests(pool, logins),
		codes:        oauth.NewAuthorizationCodes(pool, clientUsers),
		refresh:      oauth.NewRefreshTokens(pool),
		clientUsers:  clientUsers,
		issuer:       issuer,
		verifier:     oidc.NewAccessTokenVerifier(servertest.OpenIDIssuer, keys, nil),
	}

	services.person = services.newPerson(t, "1")
	services.client = services.newPublicClient(t, "an installed application")

	return services
}

func (s nativeServices) newPublicClient(t *testing.T, name string) applications.Application {
	t.Helper()

	client, _, err := s.applications.Create(t.Context(), s.person, name, applications.Public)
	if err != nil {
		t.Fatalf("registering a public client: %v", err)
	}

	if err := s.applications.ReplaceCallbackURIs(t.Context(), client, []string{nativeTemplate}); err != nil {
		t.Fatalf("registering the loopback template: %v", err)
	}

	return client
}

// at is the same services driving another public client.
func (s nativeServices) at(client applications.Application) nativeServices {
	s.client = client

	return s
}

// countClientUsers counts the relationships recorded between one public client
// and one person.
func countClientUsers(t *testing.T, pool *pgxpool.Pool, client, person uuid.UUID) int {
	t.Helper()

	var held int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM oauth_public_client_user
		WHERE application_id = $1 AND user_id = $2`, client, person).Scan(&held); err != nil {
		t.Fatalf("counting public-client users: %v", err)
	}

	return held
}

// countRevocations counts the access token revocations recorded for one person.
func countRevocations(t *testing.T, pool *pgxpool.Pool, person uuid.UUID) int {
	t.Helper()

	var held int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM oauth_access_token_revocation
		WHERE user_id = $1`, person).Scan(&held); err != nil {
		t.Fatalf("counting revocations: %v", err)
	}

	return held
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
		Subject: grant.UserID, ClientID: grant.ClientID, Scopes: grant.Scopes, AuthEpoch: grant.AuthEpoch,
	})
	if err != nil {
		return oauth.SignedTokens{}, err
	}

	identity := oidc.Identity{Subject: grant.UserID, ClientID: grant.ClientID, AuthTime: grant.AuthTime, Nonce: grant.Nonce}
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

// reachConsent takes a begun authorization through Discord to its consent, as the
// provider callback would for a person this service resolved.
func (s nativeServices) reachConsent(t *testing.T, begun pending, person uuid.UUID) string {
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

	handle, err := s.requests.BeginConsent(ctx, *login.Native, person)
	if err != nil {
		t.Fatalf("beginning the consent: %v", err)
	}

	return handle
}

// authorize takes a begun authorization through the person's approval to its
// code.
func (s nativeServices) authorize(t *testing.T, begun pending, person uuid.UUID) string {
	t.Helper()

	returned, code, err := s.requests.AllowConsent(t.Context(), s.reachConsent(t, begun, person), begun.BrowserBinding)
	if err != nil {
		t.Fatalf("allowing the consent: %v", err)
	}

	if returned.RedirectURI != nativeRedirect || returned.ClientState != begun.state {
		t.Fatalf("the approval returns to %+v", returned)
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

func (s nativeServices) subjectOf(t *testing.T, issued oauth.IssuedTokens) uuid.UUID {
	t.Helper()

	claims, err := s.verifier.Verify(issued.AccessToken)
	if err != nil {
		t.Fatalf("the issued access token is refused: %v", err)
	}

	return claims.SubjectIdentifier()
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
	if err != nil || viewed.ApplicationName != "an installed application" {
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
	if subject != services.person {
		t.Errorf("the subject is %s, want the user identifier %s", subject, services.person)
	}

	if again := services.subjectOf(t, services.signIn(t, oidc.ScopeOpenID, services.person)); again != subject {
		t.Error("the subject changed between sign-ins")
	}

	other := services.newPerson(t, "2")
	if services.subjectOf(t, services.signIn(t, oidc.ScopeOpenID, other)) != other {
		t.Error("another person was not named by their own user identifier")
	}

	claims, _ := services.verifier.Verify(issued.AccessToken)

	epoch := uuid.MustParse(claims.AuthEpoch)

	holder, err := services.clientUsers.Holder(ctx, services.client.ID, subject, claims.Identifier(), epoch)
	if err != nil || holder.Username != "person 1" {
		t.Errorf("the access token's holder was not resolved: %v", err)
	}

	if _, err := services.clientUsers.Holder(ctx, services.client.ID, subject, claims.Identifier(), uuid.New()); !errors.Is(
		err, oauth.ErrAccessNotGranted,
	) {
		t.Errorf("a token of another authority resolved: %v", err)
	}

	unserved := services.newPublicClient(t, "an application the person never used")
	stranger := services.newPerson(t, "7")

	for name, pair := range map[string][2]uuid.UUID{
		"another public client": {unserved.ID, subject},
		"a person never served": {services.client.ID, stranger},
		"an unknown user":       {services.client.ID, uuid.New()},
		"the nil user":          {services.client.ID, uuid.Nil},
		"an unknown client":     {uuid.New(), subject},
	} {
		if _, err := services.clientUsers.Holder(ctx, pair[0], pair[1], claims.Identifier(), epoch); !errors.Is(
			err, oauth.ErrAccessNotGranted,
		) {
			t.Errorf("%s resolved a holder: %v", name, err)
		}
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

	if services.subjectOf(t, rotated) != services.person {
		t.Error("a rotation changed the subject")
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

	if services.subjectOf(t, narrowed) != services.person {
		t.Error("narrowing changed the subject")
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

// A code whose relationship could not be recorded is left for a retry, nothing
// of its grant is kept, and the failure is reported as a failure, never as a
// refused grant.
func TestRedemptionFailingPartwayLeavesCodeUsable(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	begun := services.begin(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, "")
	code := services.authorize(t, begun, services.person)

	testdatabase.Execute(t, pool, `ALTER TABLE oauth_public_client_user RENAME TO unreachable`)

	if _, err := services.codes.Redeem(t.Context(), oauth.Redemption{
		ClientID: services.client.ID, Code: code, RedirectURI: nativeRedirect, Verifier: begun.verifier,
	}, services.sign); err == nil || errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("a redemption without its relationship store reported %v, want a failure", err)
	}

	testdatabase.Execute(t, pool, `ALTER TABLE unreachable RENAME TO oauth_public_client_user`)

	var families int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM oauth_refresh_family`).Scan(&families); err != nil ||
		families != 0 || countClientUsers(t, pool, services.client.ID, services.person) != 0 {
		t.Fatalf("a failed redemption kept %d offline grants or a relationship: %v", families, err)
	}

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
		"consume a provider sign-in": func() error {
			_, err := services.requests.ConsumeProvider(ctx, oauth.GitHub, opaque, opaque)

			return err
		},
		"begin a consent": func() error {
			_, err := services.requests.BeginConsent(ctx, oauth.NativeContinuation{AuthorizationID: uuid.New()}, services.person)

			return err
		},
		"end at the provider": func() error {
			return services.requests.EndProvider(ctx, oauth.NativeContinuation{AuthorizationID: uuid.New()})
		},
		"view a consent": func() error {
			_, err := services.requests.ViewConsent(ctx, opaque, opaque)

			return err
		},
		"allow a consent": func() error {
			_, _, err := services.requests.AllowConsent(ctx, opaque, opaque)

			return err
		},
		"cancel a consent": func() error {
			_, err := services.requests.CancelConsent(ctx, opaque, opaque)

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
			_, err := services.clientUsers.Holder(ctx, services.client.ID, services.person, uuid.New(), uuid.New())

			return err
		},
		"revoke an access token": func() error {
			return services.clientUsers.RevokeAccessToken(ctx, oauth.AccessRevocation{
				ClientID: services.client.ID, UserID: services.person, TokenID: uuid.New(), ExpiresAt: time.Now().Add(time.Minute),
			})
		},
		"sweep revocations": func() error {
			_, err := services.clientUsers.ForgetRevocations(ctx)

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

// Of two provider choices racing for one authorization, of an approval and a
// cancellation racing for one consent, of two approvals, and of two redemptions
// racing for one code, exactly one wins. A losing answer is the one refusal and
// leaves no second code.
func TestRacingTransitionsHaveExactlyOneWinner(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	for range 5 {
		begun := services.begin(t, oidc.ScopeOpenID, "")

		var (
			waiting sync.WaitGroup
			first   error
			second  error
		)

		waiting.Add(2)

		go func() {
			defer waiting.Done()

			_, first = services.requests.BeginProvider(ctx, begun.PageHandle, begun.BrowserBinding, oauth.GitHub)
		}()

		go func() {
			defer waiting.Done()

			_, second = services.requests.BeginProvider(ctx, begun.PageHandle, begun.BrowserBinding, oauth.Google)
		}()

		waiting.Wait()

		if (first == nil) == (second == nil) {
			t.Fatalf("two choices both reported %v and %v", first, second)
		}
	}

	answers := map[string]func(handle, binding string) error{
		"an approval": func(handle, binding string) error {
			_, _, err := services.requests.AllowConsent(ctx, handle, binding)

			return err
		},
		"a cancellation": func(handle, binding string) error {
			_, err := services.requests.CancelConsent(ctx, handle, binding)

			return err
		},
	}

	for _, pair := range [][2]string{{"an approval", "a cancellation"}, {"an approval", "an approval"}} {
		for range 5 {
			begun := services.begin(t, oidc.ScopeOpenID, "")
			handle := services.reachConsent(t, begun, services.person)

			var (
				waiting sync.WaitGroup
				results [2]error
			)

			for index, answer := range pair {
				waiting.Add(1)

				go func() {
					defer waiting.Done()

					results[index] = answers[answer](handle, begun.BrowserBinding)
				}()
			}

			waiting.Wait()

			if (results[0] == nil) == (results[1] == nil) {
				t.Fatalf("%v both reported %v", pair, results)
			}

			for _, result := range results {
				if result != nil && !errors.Is(result, oauth.ErrNoSuchAuthorization) {
					t.Errorf("a losing answer failed for another reason: %v", result)
				}
			}

			var codes int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM oauth_native_authorization_code`).Scan(&codes); err != nil {
				t.Fatalf("counting codes: %v", err)
			}

			if codes > 1 {
				t.Fatalf("%v left %d codes", pair, codes)
			}

			testdatabase.Execute(t, pool, `DELETE FROM oauth_native_authorization`)
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
	if _, err := services.requests.CancelConsent(ctx, services.reachConsent(t, begun, services.person), begun.BrowserBinding); err != nil {
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

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	signedIn := services.signIn(t, oidc.ScopeOpenID, services.person)
	subject := services.subjectOf(t, signedIn)
	bystander := services.subjectOf(t, services.signIn(t, oidc.ScopeOpenID, services.newPerson(t, "4")))

	claims, err := services.verifier.Verify(signedIn.AccessToken)
	if err != nil {
		t.Fatalf("the issued access token is refused: %v", err)
	}

	epoch := uuid.MustParse(claims.AuthEpoch)

	if _, err := services.clientUsers.Holder(ctx, services.client.ID, subject, uuid.New(), epoch); err != nil {
		t.Fatalf("an unrevoked token's holder was not resolved, so the refusal below proves nothing: %v", err)
	}

	revoke := func(subject uuid.UUID, expiresAt time.Time) (uuid.UUID, error) {
		identifier := uuid.New()

		return identifier, services.clientUsers.RevokeAccessToken(ctx, oauth.AccessRevocation{
			ClientID: services.client.ID, UserID: subject, TokenID: identifier, ExpiresAt: expiresAt,
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

	if err := services.clientUsers.RevokeAccessToken(ctx, oauth.AccessRevocation{
		ClientID: services.client.ID, UserID: subject, TokenID: last, ExpiresAt: later,
	}); err != nil {
		t.Errorf("repeating a recorded revocation = %v", err)
	}

	if _, err := revoke(bystander, later); err != nil {
		t.Errorf("another person's revocation was refused: %v", err)
	}

	unserved := services.newPublicClient(t, "an application the person never used")
	stranger := services.newPerson(t, "6")
	recorded := countRevocations(t, pool, subject)

	for name, revocation := range map[string]oauth.AccessRevocation{
		"an unknown user":          {ClientID: services.client.ID, UserID: uuid.New()},
		"a person never served":    {ClientID: services.client.ID, UserID: stranger},
		"another public client":    {ClientID: unserved.ID, UserID: subject},
		"an unknown public client": {ClientID: uuid.New(), UserID: subject},
	} {
		revocation.TokenID, revocation.ExpiresAt = uuid.New(), later

		if err := services.clientUsers.RevokeAccessToken(ctx, revocation); err != nil {
			t.Errorf("revoking for %s = %v, want nothing to record", name, err)
		}
	}

	if countRevocations(t, pool, subject) != recorded || countRevocations(t, pool, stranger) != 0 ||
		countClientUsers(t, pool, unserved.ID, subject) != 0 || countClientUsers(t, pool, services.client.ID, stranger) != 0 {
		t.Error("a revocation without the exact relationship recorded something")
	}

	if _, err := services.clientUsers.Holder(ctx, services.client.ID, subject, last, epoch); !errors.Is(
		err, oauth.ErrAccessNotGranted,
	) {
		t.Errorf("a revoked token's holder resolved: %v", err)
	}
}

// Concurrent issuances for one public client and one person converge on one
// relationship, and every other client and person keeps a relationship of its
// own.
func TestConcurrentIssuanceRecordsOneRelationshipPerPair(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()
	offline := oidc.ScopeOpenID | oidc.ScopeOfflineAccess

	const racing = 6

	begun := make([]pending, racing)
	codes := make([]string, racing)

	for index := range racing {
		begun[index] = services.begin(t, offline, "")
		codes[index] = services.authorize(t, begun[index], services.person)
	}

	results := make(chan error, racing)

	for index := range racing {
		go func() {
			issued, err := services.codes.Redeem(ctx, oauth.Redemption{
				ClientID: services.client.ID, Code: codes[index], RedirectURI: nativeRedirect,
				Verifier: begun[index].verifier,
			}, services.sign)
			if err == nil {
				claims, verifyErr := services.verifier.Verify(issued.AccessToken)
				if verifyErr != nil || claims.SubjectIdentifier() != services.person {
					err = errors.New("a racing issuance named another subject")
				}
			}

			results <- err
		}()
	}

	for range racing {
		if err := <-results; err != nil {
			t.Errorf("a racing issuance failed: %v", err)
		}
	}

	if held := countClientUsers(t, pool, services.client.ID, services.person); held != 1 {
		t.Errorf("racing issuances left %d relationships, want 1", held)
	}

	second := services.at(services.newPublicClient(t, "another installed application"))
	other := services.newPerson(t, "5")

	if second.subjectOf(t, second.signIn(t, oidc.ScopeOpenID, services.person)) != services.person {
		t.Error("another public client named the person by another subject")
	}

	if services.subjectOf(t, services.signIn(t, oidc.ScopeOpenID, other)) != other {
		t.Error("another person was not named by their own user identifier")
	}

	for name, count := range map[string]struct{ held, want int }{
		"the person at the first client":      {countClientUsers(t, pool, services.client.ID, services.person), 1},
		"the person at the second client":     {countClientUsers(t, pool, second.client.ID, services.person), 1},
		"another person at the first client":  {countClientUsers(t, pool, services.client.ID, other), 1},
		"another person at the second client": {countClientUsers(t, pool, second.client.ID, other), 0},
	} {
		if count.held != count.want {
			t.Errorf("%s: %d relationships, want %d", name, count.held, count.want)
		}
	}
}

// Once a public client's relationship with a person is gone, their offline
// grants rotate nothing, their access tokens name no holder, and revoking one
// records nothing.
func TestRemovedRelationshipGrantsNothing(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	issued := services.signIn(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, services.person)

	claims, err := services.verifier.Verify(issued.AccessToken)
	if err != nil {
		t.Fatalf("the issued access token is refused: %v", err)
	}

	epoch := uuid.MustParse(claims.AuthEpoch)

	if _, err := services.clientUsers.Holder(ctx, services.client.ID, services.person, claims.Identifier(), epoch); err != nil {
		t.Fatalf("the positive control was refused: %v", err)
	}

	testdatabase.Execute(t, pool, `DELETE FROM oauth_public_client_user WHERE application_id = $1 AND user_id = $2`,
		services.client.ID, services.person)

	if _, err := services.refresh.Rotate(ctx, oauth.Refresh{ClientID: services.client.ID, Token: issued.RefreshToken}, services.sign); !errors.Is(
		err, oauth.ErrInvalidGrant,
	) {
		t.Errorf("an offline grant outlived its relationship: %v", err)
	}

	if _, err := services.clientUsers.Holder(ctx, services.client.ID, services.person, claims.Identifier(), epoch); !errors.Is(
		err, oauth.ErrAccessNotGranted,
	) {
		t.Errorf("an access token outlived its relationship: %v", err)
	}

	if err := services.clientUsers.RevokeAccessToken(ctx, oauth.AccessRevocation{
		ClientID: services.client.ID, UserID: services.person, TokenID: claims.Identifier(), ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil || countRevocations(t, pool, services.person) != 0 ||
		countClientUsers(t, pool, services.client.ID, services.person) != 0 {
		t.Errorf("revoking without a relationship recorded something: %v", err)
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

// Provider completion creates a consent holding the person and the database's
// authentication time and grants the client nothing. Only the exact browser with
// the consent's own handle can read or answer it, reading twice is harmless, and
// Allow moves the person and that same time onto the code and clears the consent.
func TestConsentBindsPersonAndCreatesCodeOnlyOnAllow(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()
	scopes := oidc.ScopeOpenID | oidc.ScopeProfile

	begun := services.begin(t, scopes, "")
	other := services.begin(t, oidc.ScopeOpenID, "")

	selection, err := services.requests.View(ctx, begun.PageHandle, begun.BrowserBinding)
	if err != nil {
		t.Fatalf("viewing the authorization: %v", err)
	}

	handle := services.reachConsent(t, begun, services.person)

	var authenticated time.Time
	if err := pool.QueryRow(ctx, `SELECT consent_authenticated_at FROM oauth_native_authorization
		WHERE consent_user_id = $1`, services.person).Scan(&authenticated); err != nil {
		t.Fatalf("reading the consent: %v", err)
	}

	for table, want := range map[string]int{
		"oauth_native_authorization_code": 0, "oauth_public_client_user": 0, "oauth_refresh_family": 0,
	} {
		var held int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&held); err != nil || held != want {
			t.Errorf("%s holds %d rows before approval: %v", table, held, err)
		}
	}

	for range 2 {
		viewed, err := services.requests.ViewConsent(ctx, handle, begun.BrowserBinding)
		if err != nil || viewed.ApplicationName != "an installed application" || viewed.Scopes != scopes ||
			!viewed.ExpiresAt.Equal(selection.ExpiresAt) {
			t.Fatalf("viewing the consent: %+v, %v", viewed, err)
		}
	}

	for name, attempt := range map[string][2]string{
		"another browser":         {handle, other.BrowserBinding},
		"the page handle":         {begun.PageHandle, begun.BrowserBinding},
		"another page's handle":   {other.PageHandle, other.BrowserBinding},
		"the binding as a handle": {begun.BrowserBinding, begun.BrowserBinding},
	} {
		if _, err := services.requests.ViewConsent(ctx, attempt[0], attempt[1]); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
			t.Errorf("%s viewed the consent: %v", name, err)
		}

		if _, _, err := services.requests.AllowConsent(ctx, attempt[0], attempt[1]); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
			t.Errorf("%s allowed the consent: %v", name, err)
		}

		if _, err := services.requests.CancelConsent(ctx, attempt[0], attempt[1]); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
			t.Errorf("%s cancelled the consent: %v", name, err)
		}
	}

	if _, err := services.requests.View(ctx, handle, begun.BrowserBinding); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("a consent handle read the provider selection: %v", err)
	}

	if _, err := services.requests.BeginProvider(ctx, handle, begun.BrowserBinding, oauth.Discord); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("a consent handle chose a provider: %v", err)
	}

	returned, code, err := services.requests.AllowConsent(ctx, handle, begun.BrowserBinding)
	if err != nil || returned.RedirectURI != nativeRedirect || returned.ClientState != begun.state || code == "" {
		t.Fatalf("allowing the consent: %+v, %v", returned, err)
	}

	var (
		owner uuid.UUID
		when  time.Time
		stage string
		left  int
	)

	if err := pool.QueryRow(ctx, `SELECT c.user_id, c.authenticated_at, r.stage,
			(r.consent_handle_hash IS NOT NULL)::int + (r.consent_user_id IS NOT NULL)::int +
				(r.consent_authenticated_at IS NOT NULL)::int
		FROM oauth_native_authorization_code c
		JOIN oauth_native_authorization r ON r.id = c.authorization_id`).Scan(&owner, &when, &stage, &left); err != nil {
		t.Fatalf("reading the code: %v", err)
	}

	if owner != services.person || !when.Equal(authenticated) || stage != "code" || left != 0 {
		t.Errorf("the code is for %s at %v, its authorization at %q holding %d consent values", owner, when, stage, left)
	}

	if _, _, err := services.requests.AllowConsent(ctx, handle, begun.BrowserBinding); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("a consent was allowed twice: %v", err)
	}

	if issued := services.redeem(t, code, begun.verifier); services.subjectOf(t, issued) != services.person {
		t.Error("the code was not for the person who approved it")
	}
}

// Cancelling removes the authorization and grants nothing, while the person's
// account stays; deleting the person ends a consent that names them.
func TestCancelledOrOrphanedConsentGrantsNothing(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	person := services.newPerson(t, "9")

	begun := services.begin(t, oidc.ScopeOpenID|oidc.ScopeOfflineAccess, "")
	handle := services.reachConsent(t, begun, person)

	returned, err := services.requests.CancelConsent(ctx, handle, begun.BrowserBinding)
	if err != nil || returned.RedirectURI != nativeRedirect || returned.ClientState != begun.state {
		t.Fatalf("cancelling the consent: %+v, %v", returned, err)
	}

	if _, _, err := services.requests.AllowConsent(ctx, handle, begun.BrowserBinding); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("a cancelled consent was allowed: %v", err)
	}

	if countAuthorizations(t, pool) != 0 || countClientUsers(t, pool, services.client.ID, person) != 0 {
		t.Error("a cancelled consent left an authorization or a relationship")
	}

	var kept int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM "User" WHERE "id" = $1`, person).Scan(&kept); err != nil || kept != 1 {
		t.Errorf("the account did not stay: %d, %v", kept, err)
	}

	orphaned := services.begin(t, oidc.ScopeOpenID, "")
	orphanedHandle := services.reachConsent(t, orphaned, person)

	testdatabase.Execute(t, pool, `DELETE FROM "User" WHERE "id" = $1`, person)

	if _, _, err := services.requests.AllowConsent(ctx, orphanedHandle, orphaned.BrowserBinding); !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("a consent outlived its person: %v", err)
	}

	if countAuthorizations(t, pool) != 0 {
		t.Error("a consent's slot outlived its person")
	}
}

// An approval failing partway leaves no code and leaves the consent to answer
// again, and a failure is reported as a failure rather than a refusal.
func TestApprovalFailingPartwayLeavesConsentUsable(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	begun := services.begin(t, oidc.ScopeOpenID, "")
	handle := services.reachConsent(t, begun, services.person)

	testdatabase.Execute(t, pool, `ALTER TABLE oauth_native_authorization_code RENAME TO unreachable`)

	if _, _, err := services.requests.AllowConsent(ctx, handle, begun.BrowserBinding); err == nil ||
		errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Fatalf("an approval without its code store reported %v, want a failure", err)
	}

	testdatabase.Execute(t, pool, `ALTER TABLE unreachable RENAME TO oauth_native_authorization_code`)

	if _, err := services.requests.ViewConsent(ctx, handle, begun.BrowserBinding); err != nil {
		t.Fatalf("the failed approval consumed the consent: %v", err)
	}

	if _, _, err := services.requests.AllowConsent(ctx, handle, begun.BrowserBinding); err != nil {
		t.Errorf("the retried approval failed: %v", err)
	}
}

// A consent's handle, person and authentication time exist exactly while the
// authorization is at consent, whichever stage a statement tries to record them
// at, and the handle is one authorization's alone.
func TestConsentValuesExistOnlyAtConsentStage(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	services.begin(t, oidc.ScopeOpenID, "")

	const at = `UPDATE oauth_native_authorization SET stage = $1, page_handle_hash = NULL,
		consent_handle_hash = CASE WHEN $2 THEN sha256('h'::bytea) END,
		consent_user_id = CASE WHEN $3 THEN $5::uuid END,
		consent_authenticated_at = CASE WHEN $4 THEN CURRENT_TIMESTAMP END`

	for name, attempt := range map[string]struct {
		stage                 string
		handle, user, instant bool
	}{
		"consent without a handle":            {"consent", false, true, true},
		"consent without a person":            {"consent", true, false, true},
		"consent without an authentication":   {"consent", true, true, false},
		"consent with nothing":                {"consent", false, false, false},
		"the provider stage holding a handle": {"provider", true, false, false},
		"the provider stage holding a person": {"provider", false, true, false},
		"the provider stage holding a time":   {"provider", false, false, true},
		"the code stage holding every value":  {"code", true, true, true},
		"the code stage holding a handle":     {"code", true, false, false},
		"a stage the service does not have":   {"approved", true, true, true},
	} {
		if _, err := pool.Exec(ctx, at, attempt.stage, attempt.handle, attempt.user, attempt.instant, services.person); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	for name, attempt := range map[string]struct {
		stage                 string
		handle, user, instant bool
	}{
		"the provider stage holding nothing": {"provider", false, false, false},
		"consent holding every value":        {"consent", true, true, true},
		"the code stage holding nothing":     {"code", false, false, false},
	} {
		if _, err := pool.Exec(ctx, at, attempt.stage, attempt.handle, attempt.user, attempt.instant, services.person); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}

	testdatabase.Execute(t, pool, `DELETE FROM oauth_native_authorization`)

	first := services.begin(t, oidc.ScopeOpenID, "")
	second := services.begin(t, oidc.ScopeOpenID, "")
	services.reachConsent(t, first, services.person)
	services.reachConsent(t, second, services.person)

	if _, err := pool.Exec(ctx, `UPDATE oauth_native_authorization SET consent_handle_hash = sha256('same'::bytea)`); err == nil {
		t.Error("two authorizations held one consent handle")
	}
}

// A consent answer and a provider callback each wait for a rotation holding the
// authority lock, and then find that it withdrew what they came for: no code and
// no consent exist afterwards.
func TestConsentTransitionsWaitingOnRotationGrantNothing(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)
	services := newNativeServices(t, pool)
	ctx := t.Context()

	begun := services.begin(t, oidc.ScopeOpenID, "")
	handle := services.reachConsent(t, begun, services.person)

	atProvider := services.begin(t, oidc.ScopeOpenID, "")

	started, err := services.requests.BeginProvider(ctx, atProvider.PageHandle, atProvider.BrowserBinding, oauth.Discord)
	if err != nil {
		t.Fatalf("choosing a provider: %v", err)
	}

	login, err := services.requests.ConsumeProvider(ctx, oauth.Discord, started.State, atProvider.BrowserBinding)
	if err != nil {
		t.Fatalf("returning from the provider: %v", err)
	}

	rotator, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("starting a rotating transaction: %v", err)
	}

	defer func() { _ = rotator.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := rotator.Exec(ctx, `SELECT epoch FROM auth_epoch WHERE singleton FOR UPDATE`); err != nil {
		t.Fatalf("holding the authority: %v", err)
	}

	answering := make(chan error, 1)

	go func() {
		_, _, err := services.requests.AllowConsent(ctx, handle, begun.BrowserBinding)
		answering <- err
	}()

	continuing := make(chan error, 1)

	go func() {
		_, err := services.requests.BeginConsent(ctx, *login.Native, services.person)
		continuing <- err
	}()

	if err := testdatabase.AwaitLockWaiters(ctx, pool, 2); err != nil {
		t.Fatalf("an approval and a callback never waited for a held rotation: %v", err)
	}

	if _, err := rotator.Exec(ctx, `UPDATE auth_epoch SET epoch = gen_random_uuid() WHERE singleton`); err != nil {
		t.Fatalf("replacing the authority: %v", err)
	}

	if err := rotator.Commit(ctx); err != nil {
		t.Fatalf("committing the rotation: %v", err)
	}

	if err := <-answering; !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("an approval waiting on a rotation reported %v", err)
	}

	if err := <-continuing; !errors.Is(err, oauth.ErrNoSuchAuthorization) {
		t.Errorf("a callback waiting on a rotation reported %v", err)
	}

	var codes, consents int
	if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM oauth_native_authorization_code),
			(SELECT count(*) FROM oauth_native_authorization
				WHERE stage = 'consent' AND id = $1)`, login.Native.AuthorizationID).Scan(&codes, &consents); err != nil ||
		codes != 0 || consents != 0 {
		t.Errorf("transitions behind a rotation left %d codes and %d consents: %v", codes, consents, err)
	}
}

// Rotation between a provider sign-in's consumption and its consent leaves no
// consent, and a provider's refusal ends the authorization.
func TestRotationDuringProviderSignInBeginsNoConsent(t *testing.T) {
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

	if _, err := services.requests.BeginConsent(ctx, *login.Native, services.person); !errors.Is(
		err, oauth.ErrNoSuchAuthorization,
	) {
		t.Errorf("a consent began after the rotation: %v", err)
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

	if err := services.requests.EndProvider(ctx, *login.Native); err != nil {
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

	if err := services.clientUsers.RevokeAccessToken(ctx, oauth.AccessRevocation{
		ClientID: services.client.ID, UserID: subject, TokenID: uuid.New(), ExpiresAt: time.Now().Add(-time.Second),
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
		"revocations":    services.clientUsers.ForgetRevocations,
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
