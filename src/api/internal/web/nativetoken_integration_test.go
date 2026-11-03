//go:build integration && !devtools

package web_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

func validators(t *testing.T, service *servertest.Service) (*servertest.TokenValidator, *servertest.TokenValidator) {
	t.Helper()

	idTokens, err := service.IDTokenValidator(servertest.OpenIDIssuer, nil)
	if err != nil {
		t.Fatalf("building the ID token validator from discovery: %v", err)
	}

	accessTokens, err := service.AccessTokenValidator(servertest.OpenIDIssuer, nil)
	if err != nil {
		t.Fatalf("building the access token validator from discovery: %v", err)
	}

	return idTokens, accessTokens
}

// A code is exchanged for exactly the profiled token set: the members and
// headers the contract names, an ID token and an access token that external
// validators accept from the published key sets alone, the same pairwise
// subject in both, and nothing that names the AbandonAuth user.
func TestCodeExchangeIssuesExactlyTheProfiledTokens(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)

	person := service.Providers.Someone(oauth.Discord, "the person")
	pending := client.Pending(ipv4Template, 49152, "offline_access profile openid")
	code := client.SignInAs(pending, oauth.Discord, person)

	answer := client.Exchange(pending, code).ExpectStatus(http.StatusOK)

	if answer.Header.Get("Cache-Control") != "no-store" || answer.Header.Get("Pragma") != "no-cache" {
		t.Errorf("the token response may be cached: %v", answer.Header)
	}

	var members map[string]json.RawMessage
	answer.DecodeInto(&members)

	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}

	slices.Sort(names)

	if want := []string{
		"access_token", "expires_in", "id_token", "refresh_token", "refresh_token_expires_in", "scope", "token_type",
	}; !slices.Equal(names, want) {
		t.Errorf("token response members = %v, want %v", names, want)
	}

	var issued servertest.TokenSet
	answer.DecodeInto(&issued)

	if issued.TokenType != "Bearer" || issued.ExpiresIn != 900 || issued.Scope != "openid profile offline_access" ||
		len(issued.RefreshToken) != 43 || issued.RefreshTokenExpiresIn <= 2592000-60 ||
		issued.RefreshTokenExpiresIn > 2592000 {
		t.Errorf("the token set is %+v", issued)
	}

	idTokens, accessTokens := validators(t, service)

	identity, err := idTokens.ValidateIDToken(issued.IDToken, application.ID.String(), pending.Nonce)
	if err != nil {
		t.Fatalf("the ID token was refused by a validator built from discovery: %v", err)
	}

	access, err := accessTokens.ValidateAccessToken(issued.AccessToken, application.ID.String())
	if err != nil {
		t.Fatalf("the access token was refused by a validator built from discovery: %v", err)
	}

	if identity["preferred_username"] != "the person" || access["scope"] != "openid profile offline_access" {
		t.Errorf("the granted claims are %v and %v", identity, access)
	}

	if identity["sub"] != access["sub"] {
		t.Error("the two tokens name the person differently")
	}

	var userID string
	if err := service.Pool.QueryRow(t.Context(),
		`SELECT "id"::text FROM "User" WHERE "username" = 'the person'`).Scan(&userID); err != nil {
		t.Fatalf("finding the person: %v", err)
	}

	for _, token := range []string{issued.IDToken, issued.AccessToken} {
		for name, value := range servertest.DecodeClaims(token) {
			if text, isText := value.(string); isText && strings.Contains(text, userID) {
				t.Errorf("claim %s carries the AbandonAuth user identifier", name)
			}
		}
	}

	if _, err := idTokens.ValidateIDToken(issued.AccessToken, application.ID.String(), pending.Nonce); err == nil {
		t.Error("an access token was accepted as an ID token")
	}

	if _, err := accessTokens.ValidateAccessToken(issued.IDToken, application.ID.String()); err == nil {
		t.Error("an ID token was accepted as an access token")
	}

	if strings.Contains(service.Logs.String(), code) || strings.Contains(service.Logs.String(), issued.RefreshToken) ||
		strings.Contains(service.Logs.String(), pending.State) || strings.Contains(service.Logs.String(), pending.Verifier) {
		t.Error("a credential reached the log")
	}
}

// Every provider's sign-in ends in a native code for a public client, and
// never in a browser session or a confidential one-time code.
func TestEveryProviderEndsInNativeCode(t *testing.T) {
	t.Parallel()

	for _, provider := range oauth.Providers {
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			_, client := installedClient(t, service)

			sessions := countRows(t, service, "browser_session")

			pending := client.Pending(ipv4Template, 49152, "openid")
			started := client.BeginPublicSignIn(pending, provider)

			returned := service.FinishLogin(started, service.Providers.Someone(provider, "someone")).
				ExpectStatus(http.StatusSeeOther)
			expectPageHeaders(t, returned)

			if returned.Cookie(service.SessionCookieName()) != nil || countRows(t, service, "browser_session") != sessions {
				t.Error("a public sign-in created a browser session")
			}

			if codes := countRows(t, service, "oauth_exchange_code"); codes != 0 {
				t.Errorf("a public sign-in issued %d confidential codes", codes)
			}

			answer, err := pending.Read(returned.Header.Get("Location"), servertest.OpenIDIssuer)
			if err != nil {
				t.Fatalf("the client could not read its answer: %v", err)
			}

			client.Exchange(pending, answer.Code).ExpectStatus(http.StatusOK)
		})
	}
}

// A code is spent only by the exact client, redirect and verifier it was
// issued for; a wrong attempt leaves it for the rightful one; and it is spent
// once.
func TestCodeIsRedeemedOnlyByItsExactBinding(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	other := service.InstalledClient(service.RegisterPublicClient("another installed application", ipv4Template))
	confidential := service.RegisterApplication("a server-side application", externalCallbackURI)

	pending := client.Pending(ipv4Template, 49152, "openid")
	code := client.SignIn(pending, oauth.GitHub, "someone")

	attempt := func(change func(url.Values)) *servertest.Response {
		form := client.ExchangeForm(pending, code)
		change(form)

		return service.POSTForm("/oauth/token", form.Encode())
	}

	for name, change := range map[string]func(url.Values){
		"a wrong verifier":    func(v url.Values) { v.Set("code_verifier", strings.Repeat("w", 43)) },
		"another port":        func(v url.Values) { v.Set("redirect_uri", servertest.WithPort(ipv4Template, 49153)) },
		"the other loopback":  func(v url.Values) { v.Set("redirect_uri", servertest.WithPort(ipv6Template, 49152)) },
		"another client":      func(v url.Values) { v.Set("client_id", other.ClientID.String()) },
		"another code":        func(v url.Values) { v.Set("code", strings.Repeat("Z", 42)+"A") },
		"a non-canonical one": func(v url.Values) { v.Set("code", code[:42]+"B") },
	} {
		t.Run(name, func(t *testing.T) {
			expectOAuthError(t, attempt(change), http.StatusBadRequest, "invalid_grant")
		})
	}

	expectOAuthError(t, attempt(func(v url.Values) { v.Set("client_id", confidential.ID.String()) }),
		http.StatusBadRequest, "invalid_client")
	expectOAuthError(t, attempt(func(v url.Values) { v.Set("client_id", "00000000-0000-0000-0000-00000000dead") }),
		http.StatusBadRequest, "invalid_client")

	if answer := attempt(func(url.Values) {}); answer.Header.Get("WWW-Authenticate") != "" {
		t.Error("a token request was challenged to authenticate")
	}

	expectOAuthError(t, attempt(func(url.Values) {}), http.StatusBadRequest, "invalid_grant")

	// The rightful request above consumed the code; a fresh one shows the
	// wrong attempts did not.
	pending = client.Pending(ipv4Template, 49152, "openid")
	code = client.SignIn(pending, oauth.GitHub, "someone")

	for range 3 {
		attempt(func(v url.Values) { v.Set("code_verifier", strings.Repeat("w", 43)) })
	}

	client.Exchange(pending, code).ExpectStatus(http.StatusOK)
	expectOAuthError(t, client.Exchange(pending, code), http.StatusBadRequest, "invalid_grant")
}

// Of concurrent redemptions of one code exactly one is issued tokens.
func TestConcurrentRedemptionsIssueOneTokenSet(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	pending := client.Pending(ipv4Template, 49152, "openid offline_access")
	code := client.SignIn(pending, oauth.Discord, "someone")
	body := client.ExchangeForm(pending, code).Encode()

	statuses := make([]int, 6)

	var racing sync.WaitGroup

	for index := range statuses {
		racing.Add(1)

		go func() {
			defer racing.Done()

			statuses[index] = service.POSTForm("/oauth/token", body).Status
		}()
	}

	racing.Wait()

	if issued := slices.Index(statuses, http.StatusOK); issued == -1 ||
		slices.Index(statuses[issued+1:], http.StatusOK) != -1 {
		t.Errorf("statuses = %v, want exactly one 200", statuses)
	}

	if families := countRows(t, service, "oauth_refresh_family"); families != 1 {
		t.Errorf("%d offline grants were created, want one", families)
	}
}

// Refresh tokens rotate; presenting a consumed one ends the whole family; a
// refreshed ID token carries no nonce and keeps the authentication time.
func TestRefreshRotatesAndReuseEndsFamily(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)

	_, issued := client.Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "p"))

	var refreshed servertest.TokenSet

	answer := client.Refresh(issued.RefreshToken, "").ExpectStatus(http.StatusOK).DecodeInto(&refreshed)
	if answer.Header.Get("Cache-Control") != "no-store" || answer.Header.Get("Pragma") != "no-cache" {
		t.Error("the refresh response may be cached")
	}

	if refreshed.RefreshToken == "" || refreshed.RefreshToken == issued.RefreshToken ||
		refreshed.Scope != "openid offline_access" || refreshed.ExpiresIn != 900 {
		t.Errorf("the refresh answered %+v", refreshed)
	}

	idTokens, _ := validators(t, service)

	renewed, err := idTokens.ValidateIDToken(refreshed.IDToken, application.ID.String(), "")
	if err != nil {
		t.Fatalf("the refreshed ID token was refused: %v", err)
	}

	original := servertest.DecodeClaims(issued.IDToken)
	if renewed["auth_time"] != original["auth_time"] || renewed["sub"] != original["sub"] {
		t.Error("the refreshed ID token changed the authentication time or the subject")
	}

	expectOAuthError(t, client.Refresh(issued.RefreshToken, ""), http.StatusBadRequest, "invalid_grant")
	expectOAuthError(t, client.Refresh(refreshed.RefreshToken, ""), http.StatusBadRequest, "invalid_grant")
}

// A refresh can narrow its grant but never widen it, and narrowing away
// offline access ends the family without a replacement.
func TestRefreshNarrowsButNeverWidens(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	_, issued := client.Tokens(ipv4Template, "openid profile offline_access", service.Providers.Someone(oauth.Discord, "p"))

	_, narrow := client.Tokens(ipv4Template, "openid offline_access", service.Providers.Someone(oauth.Discord, "q"))
	expectOAuthError(t, client.Refresh(narrow.RefreshToken, "openid profile offline_access"),
		http.StatusBadRequest, "invalid_scope")

	var refreshed servertest.TokenSet

	client.Refresh(issued.RefreshToken, "offline_access openid").ExpectStatus(http.StatusOK).DecodeInto(&refreshed)

	if refreshed.Scope != "openid offline_access" {
		t.Errorf("scope = %q", refreshed.Scope)
	}

	if _, released := servertest.DecodeClaims(refreshed.IDToken)["preferred_username"]; released {
		t.Error("a username was released after profile was narrowed away")
	}

	var ended map[string]json.RawMessage

	client.Refresh(refreshed.RefreshToken, "openid").ExpectStatus(http.StatusOK).DecodeInto(&ended)

	if _, present := ended["refresh_token"]; present {
		t.Error("narrowing away offline_access issued another refresh token")
	}

	if _, present := ended["refresh_token_expires_in"]; present {
		t.Error("narrowing away offline_access stated a refresh lifetime")
	}

	expectOAuthError(t, client.Refresh(refreshed.RefreshToken, ""), http.StatusBadRequest, "invalid_grant")
}

// A code grant without offline_access issues no refresh token at all.
func TestCodeWithoutOfflineAccessIssuesNoRefreshToken(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	pending := client.Pending(ipv4Template, 49152, "openid")
	code := client.SignIn(pending, oauth.Discord, "someone")

	var members map[string]json.RawMessage

	client.Exchange(pending, code).ExpectStatus(http.StatusOK).DecodeInto(&members)

	if _, present := members["refresh_token"]; present {
		t.Error("a refresh token was issued without offline_access")
	}

	if countRows(t, service, "oauth_refresh_family") != 0 {
		t.Error("an offline grant was recorded without offline_access")
	}
}

// One person is the same subject at one application every time, a different
// one at every other application, and different from every other person.
func TestPairwiseSubjectsAreStableAndUnlinkable(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, first := installedClient(t, service)
	second := service.InstalledClient(service.RegisterPublicClient("another installed application", ipv4Template))

	person := service.Providers.Someone(oauth.Discord, "the person")
	stranger := service.Providers.Someone(oauth.Discord, "a stranger")

	subject := func(client *servertest.InstalledClient, identity providertest.Identity) string {
		_, issued := client.Tokens(ipv4Template, "openid profile", identity)

		subject, _ := servertest.DecodeClaims(issued.AccessToken)["sub"].(string)

		return subject
	}

	atFirst := subject(first, person)
	again := subject(first, person)
	atSecond := subject(second, person)
	strangerAtFirst := subject(first, stranger)

	if atFirst != again {
		t.Error("one person was two subjects at one application")
	}

	if atFirst == atSecond {
		t.Error("one person was the same subject at two applications")
	}

	if atFirst == strangerAtFirst {
		t.Error("two people were one subject at one application")
	}

	if _, err := database.RotateAuthority(t.Context(), service.Pool); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	if after := subject(first, person); after != atFirst {
		t.Error("rotating the authority changed a subject")
	}
}

// Fixed refusals at the endpoint itself, each the one-member OAuth body, never
// the repository's input refusal and never a description.
func TestTokenEndpointRefusesInOAuthTerms(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	pending := client.Pending(ipv4Template, 49152, "openid")
	valid := client.ExchangeForm(pending, strings.Repeat("C", 42)+"A")

	refusals := map[string]*servertest.Response{
		"a JSON body": service.POSTJSON("/oauth/token", map[string]string{"grant_type": "authorization_code"}),
		"an Authorization header": service.POSTForm("/oauth/token", valid.Encode(),
			servertest.Header("Authorization", "Basic Y2xpZW50OnNlY3JldA==")),
		"a client secret":  service.POSTForm("/oauth/token", valid.Encode()+"&client_secret=s"),
		"no body":          service.POSTForm("/oauth/token", ""),
		"query parameters": service.POSTForm("/oauth/token?"+valid.Encode(), ""),
	}

	for name, answer := range refusals {
		t.Run(name, func(t *testing.T) {
			expectOAuthError(t, answer, http.StatusBadRequest, "invalid_request")

			if strings.Contains(string(answer.Body), "error_description") || strings.Contains(string(answer.Body), "detail") {
				t.Errorf("the refusal is not an OAuth error: %s", answer.Body)
			}
		})
	}

	expectOAuthError(t, service.POSTForm("/oauth/token", "grant_type=password&client_id="+client.ClientID.String()),
		http.StatusBadRequest, "unsupported_grant_type")
}
