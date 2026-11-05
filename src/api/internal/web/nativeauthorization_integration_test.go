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
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The two portless loopback templates an installed client registers.
const (
	ipv4Template = "http://127.0.0.1/oauth/callback"
	ipv6Template = "http://[::1]/oauth/callback"
)

// installedClient registers a public client for a signed-in developer.
func installedClient(t *testing.T, service *servertest.Service) (servertest.Application, *servertest.InstalledClient) {
	t.Helper()

	service.SignInSomeone("the developer")

	application := service.RegisterPublicClient("an installed application", ipv4Template, ipv6Template)

	return application, service.InstalledClient(application)
}

func countRows(t *testing.T, service *servertest.Service, table string) int {
	t.Helper()

	var count int
	if err := service.Pool.QueryRow(t.Context(), `SELECT count(*) FROM `+table).Scan(&count); err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}

	return count
}

func expectPageHeaders(t *testing.T, answer *servertest.Response) {
	t.Helper()

	for header, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
	} {
		if got := answer.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func expectOAuthError(t *testing.T, answer *servertest.Response, status int, code string) {
	t.Helper()

	answer.ExpectStatus(status)

	if want := `{"error":"` + code + `"}` + "\n"; string(answer.Body) != want {
		t.Errorf("body = %q, want %q", answer.Body, want)
	}

	if answer.Header.Get("Cache-Control") != "no-store" || answer.Header.Get("Pragma") != "no-cache" {
		t.Errorf("the refusal may be cached: %v", answer.Header)
	}
}

// A successful authorization is an empty 303 to the site's page with the
// handle only in the fragment; the browser is bound by its own cookie; and the
// page learns only the application, the deadline and the providers.
func TestAuthorizationHandsBrowserToPageThroughFragment(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	pending := client.Pending(ipv4Template, 49152, "openid offline_access profile")

	began := time.Now()
	answer := client.Authorize(pending).ExpectStatus(http.StatusSeeOther)
	handle := service.PageHandle(answer)

	expectPageHeaders(t, answer)

	if answer.Header.Get("Pragma") != "no-cache" || len(answer.Body) != 0 {
		t.Errorf("the handoff carries a body or may be cached: %q", answer.Body)
	}

	location := answer.Header.Get("Location")
	if strings.Contains(location, "?") {
		t.Errorf("the handoff address has a query: %q", location)
	}

	for _, secret := range []string{pending.State, pending.Nonce, pending.Challenge, url.QueryEscape(pending.RedirectURI)} {
		if strings.Contains(location, secret) {
			t.Error("a client value travels in the handoff address")
		}
	}

	cookie := answer.Cookie(service.NativeLoginCookieName())
	if cookie == nil {
		t.Fatal("the browser was not bound")
	}

	if cookie.Name != "__Host-abandonauth_native_oauth" || !cookie.HttpOnly || !cookie.Secure ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 300 {
		t.Errorf("the binding cookie is not hardened: %+v", cookie)
	}

	if answer.Cookie(service.LoginCookieName()) != nil {
		t.Error("a public authorization set the confidential login's cookie")
	}

	view := service.GET("/oauth/authorization/" + handle).ExpectStatus(http.StatusOK)
	expectPageHeaders(t, view)

	var members map[string]json.RawMessage
	view.DecodeInto(&members)

	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}

	slices.Sort(names)

	if !slices.Equal(names, []string{"application_name", "expires_at", "providers"}) {
		t.Errorf("the page model has %v", names)
	}

	var page struct {
		ApplicationName string   `json:"application_name"`
		ExpiresAt       string   `json:"expires_at"`
		Providers       []string `json:"providers"`
	}

	view.DecodeInto(&page)

	if page.ApplicationName != "an installed application" ||
		!slices.Equal(page.Providers, []string{"discord", "github", "google", "steam"}) {
		t.Errorf("the page model is %+v", page)
	}

	deadline, err := time.Parse("2006-01-02T15:04:05Z", page.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q is not whole seconds in UTC: %v", page.ExpiresAt, err)
	}

	if until := deadline.Sub(began); until < 4*time.Minute || until > 5*time.Minute+time.Second {
		t.Errorf("the authorization lasts %v, want five minutes", until)
	}

	for _, secret := range []string{pending.State, pending.Nonce, pending.Challenge, "127.0.0.1"} {
		if strings.Contains(string(view.Body), secret) {
			t.Error("the page model discloses a client value")
		}
	}

	// Reading the page again is the same answer: reading consumes nothing.
	service.GET("/oauth/authorization/" + handle).ExpectStatus(http.StatusOK)
}

// Nothing is ever sent to an address the client did not register: a client or
// redirect that cannot be proven is refused directly, and nothing is stored.
func TestAuthorizationRefusesUnprovenClientOrRedirectDirectly(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)

	confidential := service.RegisterApplication("a server-side application", externalCallbackURI)
	deleted := service.RegisterPublicClient("a deleted client", ipv4Template)
	service.DELETE("/developer_application/"+deleted.ID.String(), service.Protected).ExpectStatus(http.StatusOK)

	pending := client.Pending(ipv4Template, 49152, "openid")

	query := func(change func(url.Values)) string {
		parameters := pending.Parameters(application.ID)
		change(parameters)

		return parameters.Encode()
	}

	for name, rawQuery := range map[string]string{
		"an unknown client":       query(func(v url.Values) { v.Set("client_id", "00000000-0000-0000-0000-00000000dead") }),
		"a confidential client":   query(func(v url.Values) { v.Set("client_id", confidential.ID.String()) }),
		"a deleted client":        query(func(v url.Values) { v.Set("client_id", deleted.ID.String()) }),
		"no port":                 query(func(v url.Values) { v.Set("redirect_uri", ipv4Template) }),
		"port zero":               query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:0/oauth/callback") }),
		"a port past 65535":       query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:65536/oauth/callback") }),
		"a leading-zero port":     query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:080/oauth/callback") }),
		"another loopback":        query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.2:1/oauth/callback") }),
		"localhost":               query(func(v url.Values) { v.Set("redirect_uri", "http://localhost:1/oauth/callback") }),
		"https":                   query(func(v url.Values) { v.Set("redirect_uri", "https://127.0.0.1:1/oauth/callback") }),
		"another path":            query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:1/oauth/other") }),
		"an added query":          query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:1/oauth/callback?x=1") }),
		"a fragment":              query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:1/oauth/callback#x") }),
		"an IPv4-mapped address":  query(func(v url.Values) { v.Set("redirect_uri", "http://[::ffff:127.0.0.1]:1/oauth/callback") }),
		"an abbreviated address":  query(func(v url.Values) { v.Set("redirect_uri", "http://127.1:1/oauth/callback") }),
		"a dot segment":           query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:1/oauth/../oauth/callback") }),
		"an encoded slash":        query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:1/oauth%2Fcallback") }),
		"credentials":             query(func(v url.Values) { v.Set("redirect_uri", "http://user@127.0.0.1:1/oauth/callback") }),
		"no redirect":             query(func(v url.Values) { v.Del("redirect_uri") }),
		"a repeated client":       query(func(v url.Values) { v.Add("client_id", application.ID.String()) }),
		"an unreadable query":     query(func(url.Values) {}) + "&x=%zz",
		"an encoded client name":  strings.Replace(query(func(url.Values) {}), "client_id=", "client%5Fid=", 1),
		"a response-splitting CR": query(func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:1/oauth/callback\r\nX: y") }),
	} {
		t.Run(name, func(t *testing.T) {
			answer := service.GET("/oauth/authorize?" + rawQuery)

			expectOAuthError(t, answer, http.StatusBadRequest, "invalid_request")
			expectPageHeaders(t, answer)

			if location := answer.Header.Get("Location"); location != "" {
				t.Errorf("an unproven request was redirected to %q", location)
			}

			if answer.Cookie(service.NativeLoginCookieName()) != nil {
				t.Error("an unproven request bound the browser")
			}
		})
	}

	if held := countRows(t, service, "oauth_native_authorization"); held != 0 {
		t.Errorf("refused requests left %d authorizations", held)
	}

	// The same request with a proven client and redirect is the positive
	// control, on either loopback address and on both extreme ports.
	for _, redirect := range []string{
		servertest.WithPort(ipv4Template, 1), servertest.WithPort(ipv6Template, 65535),
	} {
		parameters := pending.Parameters(application.ID)
		parameters.Set("redirect_uri", redirect)

		service.PageHandle(service.GET("/oauth/authorize?" + parameters.Encode()))
	}
}

// Once the client and the redirect are proven, a refusal is a 303 to exactly
// that redirect with only the error, the client's valid state and the issuer.
func TestAuthorizationRedirectsRefusalsToProvenRedirect(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)

	pending := client.Pending(ipv6Template, 50000, "openid")
	issuer := url.QueryEscape(servertest.OpenIDIssuer)

	tests := []struct {
		name   string
		change func(url.Values)
		want   string
	}{
		{"an implicit grant", func(v url.Values) { v.Set("response_type", "token") },
			"?error=unsupported_response_type&state=" + pending.State + "&iss=" + issuer},
		{"an unknown scope", func(v url.Values) { v.Set("scope", "openid email") },
			"?error=invalid_scope&state=" + pending.State + "&iss=" + issuer},
		{"the plain challenge method", func(v url.Values) { v.Set("code_challenge_method", "plain") },
			"?error=invalid_request&state=" + pending.State + "&iss=" + issuer},
		{"a state too short to echo", func(v url.Values) { v.Set("state", "short") },
			"?error=invalid_request&iss=" + issuer},
		{"a repeated state", func(v url.Values) { v.Add("state", pending.State) },
			"?error=invalid_request&iss=" + issuer},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameters := pending.Parameters(application.ID)
			test.change(parameters)

			answer := service.GET("/oauth/authorize?" + parameters.Encode()).ExpectStatus(http.StatusSeeOther)

			answer.ExpectRedirectTo(pending.RedirectURI + test.want)
			expectPageHeaders(t, answer)

			if len(answer.Body) != 0 || answer.Cookie(service.NativeLoginCookieName()) != nil {
				t.Error("a refused request has a body or bound the browser")
			}
		})
	}

	if held := countRows(t, service, "oauth_native_authorization"); held != 0 {
		t.Errorf("refused requests left %d authorizations", held)
	}
}

// The page's own requests are refused unless they carry exactly the site's
// origin and the browser's binding, and a refusal consumes nothing.
func TestAuthorizationPageRequestsNeedSiteOriginAndBinding(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	handle := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49152, "openid")))
	choose := "/oauth/authorization/" + handle + "/github"

	for name, origins := range map[string][]string{
		"no origin":            nil,
		"null":                 {"null"},
		"a trailing slash":     {servertest.SiteOrigin + "/"},
		"a path":               {servertest.SiteOrigin + "/authorize"},
		"another port":         {servertest.SiteOrigin + ":444"},
		"plain HTTP":           {"http://auth.example.test"},
		"the API's origin":     {servertest.APIOrigin},
		"two origins":          {servertest.SiteOrigin, servertest.SiteOrigin},
		"comma-joined origins": {servertest.SiteOrigin + ", " + servertest.SiteOrigin},
		"credentials":          {"https://user@auth.example.test"},
	} {
		t.Run(name, func(t *testing.T) {
			withOrigins := func(request *http.Request) {
				for _, origin := range origins {
					request.Header.Add("Origin", origin)
				}
			}

			answer := service.POSTForm(choose, "", withOrigins).
				ExpectStatus(http.StatusForbidden).
				ExpectDetail("Authorization request forbidden")
			expectPageHeaders(t, answer)
		})
	}

	binding := service.CookieValue(service.NativeLoginCookieName())
	service.Forget(service.NativeLoginCookieName())

	for name, cookies := range map[string]string{
		"no binding":           "",
		"another binding":      service.NativeLoginCookieName() + "=" + strings.Repeat("B", 42) + "A",
		"conflicting bindings": service.NativeLoginCookieName() + "=" + binding + "; " + service.NativeLoginCookieName() + "=" + strings.Repeat("B", 42) + "A",
		"a quoted binding":     service.NativeLoginCookieName() + `="` + binding + `"`,
		"the login cookie":     service.LoginCookieName() + "=" + binding,
	} {
		t.Run(name, func(t *testing.T) {
			carrying := func(request *http.Request) {
				service.FromSite(request)

				if cookies != "" {
					request.Header.Set("Cookie", cookies)
				}
			}

			service.GET("/oauth/authorization/"+handle, carrying).
				ExpectStatus(http.StatusNotFound).
				ExpectDetail("Authorization request unavailable")
			service.POSTForm(choose, "", carrying).
				ExpectStatus(http.StatusNotFound).
				ExpectDetail("Authorization request unavailable")
		})
	}

	// The genuine browser is the positive control, and nothing above consumed
	// the request.
	genuine := func(request *http.Request) {
		service.FromSite(request)
		request.Header.Set("Cookie", service.NativeLoginCookieName()+"="+binding)
	}

	service.POSTForm(choose, "", genuine).ExpectStatus(http.StatusSeeOther)

	for _, unknown := range []string{"twitter", "Discord", "cancel"} {
		service.POSTForm("/oauth/authorization/"+handle+"/"+unknown, "", genuine).
			ExpectStatus(http.StatusNotFound).
			ExpectDetail("Authorization request unavailable")
	}
}

// Provider selection offers no cancellation: the address that would name one is
// no provider, and asking for it ends nothing.
func TestProviderSelectionCannotBeCancelled(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	handle := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49152, "openid")))

	answer := service.POSTForm("/oauth/authorization/"+handle+"/cancel", "", service.FromSite).
		ExpectStatus(http.StatusNotFound).
		ExpectDetail("Authorization request unavailable")
	expectPageHeaders(t, answer)

	service.GET("/oauth/authorization/" + handle).ExpectStatus(http.StatusOK)
}

// A handle works once: of several choices exactly one finds it, and what is
// spent cannot be read or spent again.
func TestExactlyOneProviderChoiceWins(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	handle := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49152, "openid")))

	paths := []string{
		"/oauth/authorization/" + handle + "/discord",
		"/oauth/authorization/" + handle + "/google",
		"/oauth/authorization/" + handle + "/steam",
	}

	answers := make([]int, len(paths))

	var racing sync.WaitGroup

	for index, path := range paths {
		racing.Add(1)

		go func() {
			defer racing.Done()

			answers[index] = service.POSTForm(path, "", service.FromSite).Status
		}()
	}

	racing.Wait()

	won := 0

	for _, status := range answers {
		switch status {
		case http.StatusSeeOther:
			won++
		case http.StatusNotFound:
		default:
			t.Errorf("a racing request answered %d", status)
		}
	}

	if won != 1 {
		t.Errorf("%d of the racing requests won, want exactly one", won)
	}

	for _, path := range paths {
		service.POSTForm(path, "", service.FromSite).ExpectStatus(http.StatusNotFound)
	}

	service.GET("/oauth/authorization/" + handle).ExpectStatus(http.StatusNotFound)
}

// consentModel is exactly what the consent page is given.
type consentModel struct {
	ApplicationName string   `json:"application_name"`
	Scopes          []string `json:"scopes"`
	ExpiresAt       string   `json:"expires_at"`
}

func expectUnavailable(t *testing.T, answer *servertest.Response) {
	t.Helper()

	answer.ExpectStatus(http.StatusNotFound).ExpectDetail("Authorization request unavailable")
	expectPageHeaders(t, answer)
}

func expectForbidden(t *testing.T, answer *servertest.Response) {
	t.Helper()

	answer.ExpectStatus(http.StatusForbidden).ExpectDetail("Authorization request forbidden")
	expectPageHeaders(t, answer)
}

// expectNoGrant states that no client has been given anything: no code, no
// relationship with a person, no offline grant and no browser session beyond
// the ones a test started with.
func expectNoGrant(t *testing.T, service *servertest.Service, sessions int) {
	t.Helper()

	for table, want := range map[string]int{
		"oauth_native_authorization_code": 0,
		"oauth_public_client_user":        0,
		"oauth_refresh_family":            0,
		"oauth_exchange_code":             0,
		"browser_session":                 sessions,
	} {
		if held := countRows(t, service, table); held != want {
			t.Errorf("%s holds %d rows, want %d", table, held, want)
		}
	}
}

// The consent model states exactly what each scope set asks for, in canonical
// order whatever order was requested, and carries nothing else: no person, no
// client value. Reading it changes nothing, and the deadline is the one the
// authorization began with.
func TestConsentModelIsExactForEveryScopeSet(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	for requested, want := range map[string][]string{
		"openid":                        {"openid"},
		"openid profile":                {"openid", "profile"},
		"openid offline_access":         {"openid", "offline_access"},
		"offline_access profile openid": {"openid", "profile", "offline_access"},
	} {
		t.Run(requested, func(t *testing.T) {
			pending := client.Pending(ipv4Template, 49152, requested)
			page := service.PageHandle(client.Authorize(pending))

			var selection struct {
				ExpiresAt string `json:"expires_at"`
			}

			service.GET("/oauth/authorization/" + page).ExpectStatus(http.StatusOK).DecodeInto(&selection)

			person := service.Providers.Someone(oauth.Discord, "person "+requested)
			handle := service.ConsentHandle(service.FinishLogin(service.ChooseProvider(page, oauth.Discord), person))

			view := service.GET("/oauth/consent/" + handle).ExpectStatus(http.StatusOK)
			expectPageHeaders(t, view)

			var members map[string]json.RawMessage

			view.DecodeInto(&members)

			if len(members) != 3 {
				t.Errorf("the consent model has %d members: %s", len(members), view.Body)
			}

			var model consentModel

			view.DecodeInto(&model)

			if model.ApplicationName != "an installed application" || !slices.Equal(model.Scopes, want) {
				t.Errorf("the consent model is %+v", model)
			}

			if model.ExpiresAt != selection.ExpiresAt {
				t.Errorf("consent moved the deadline from %s to %s", selection.ExpiresAt, model.ExpiresAt)
			}

			body := string(view.Body)

			for _, secret := range []string{
				pending.State, pending.Nonce, pending.Challenge, "127.0.0.1", userIDOf(t, service, "person "+requested),
				"person " + requested,
			} {
				if strings.Contains(body, secret) {
					t.Error("the consent model discloses a client or person value")
				}
			}

			service.GET("/oauth/consent/" + handle).ExpectStatus(http.StatusOK)
		})
	}
}

// Allow alone creates a code. It returns the browser to the exact redirect with
// that code, the exact state and the issuer; the code redeems; and nothing about
// the consent survives to be read or answered again.
func TestAllowingReturnsExactlyOneCodeToClient(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	sessions := countRows(t, service, "browser_session")

	pending := client.Pending(ipv4Template, 49152, "openid profile")
	handle := client.ReachConsent(pending, oauth.GitHub, service.Providers.Someone(oauth.GitHub, "the person"))

	expectNoGrant(t, service, sessions)

	answer := service.AllowConsent(handle).ExpectStatus(http.StatusSeeOther)
	expectPageHeaders(t, answer)

	if len(answer.Body) != 0 || answer.Cookie(service.SessionCookieName()) != nil {
		t.Errorf("the answer carries a body or a session: %q", answer.Body)
	}

	returned, err := pending.Read(answer.Header.Get("Location"), servertest.OpenIDIssuer)
	if err != nil || len(returned.Code) != 43 {
		t.Fatalf("the client was not returned one code: %v %+v", err, returned)
	}

	if held := countRows(t, service, "oauth_native_authorization_code"); held != 1 {
		t.Errorf("%d codes are held, want the one", held)
	}

	var (
		stage     string
		leftovers int
		lifetime  time.Duration
	)

	if err := service.Pool.QueryRow(t.Context(), `SELECT r.stage,
			(r.consent_handle_hash IS NOT NULL)::int + (r.consent_user_id IS NOT NULL)::int +
				(r.consent_authenticated_at IS NOT NULL)::int,
			c.expires_at - c.created_at
		FROM oauth_native_authorization r
		JOIN oauth_native_authorization_code c ON c.authorization_id = r.id`).Scan(&stage, &leftovers, &lifetime); err != nil {
		t.Fatalf("reading the authorization: %v", err)
	}

	if stage != "code" || leftovers != 0 {
		t.Errorf("the authorization is at %q holding %d consent values", stage, leftovers)
	}

	if lifetime <= 0 || lifetime > 120*time.Second {
		t.Errorf("the code lives %v", lifetime)
	}

	expectUnavailable(t, service.GET("/oauth/consent/"+handle))
	expectUnavailable(t, service.AllowConsent(handle))
	expectUnavailable(t, service.CancelConsent(handle))

	if held := countRows(t, service, "oauth_native_authorization_code"); held != 1 {
		t.Errorf("a replay left %d codes", held)
	}

	client.Exchange(pending, returned.Code).ExpectStatus(http.StatusOK)
}

// Cancel tells the client the person declined, at its exact redirect, and leaves
// it nothing, while the account the provider sign-in created stays.
func TestCancellingConsentTellsClientPersonDeclinedAndGrantsNothing(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	sessions := countRows(t, service, "browser_session")

	pending := client.Pending(ipv4Template, 61000, "openid profile offline_access")
	handle := client.ReachConsent(pending, oauth.Discord, service.Providers.Someone(oauth.Discord, "a new person"))

	answer := service.CancelConsent(handle).ExpectStatus(http.StatusSeeOther)

	answer.ExpectRedirectTo(pending.RedirectURI + "?error=access_denied&state=" + pending.State +
		"&iss=" + url.QueryEscape(servertest.OpenIDIssuer))
	expectPageHeaders(t, answer)

	if returned, err := pending.Read(answer.Header.Get("Location"), servertest.OpenIDIssuer); err != nil ||
		returned.Error != "access_denied" {
		t.Errorf("the client could not read the cancellation: %v %+v", err, returned)
	}

	if held := countRows(t, service, "oauth_native_authorization"); held != 0 {
		t.Errorf("a cancelled authorization still holds %d slots", held)
	}

	expectNoGrant(t, service, sessions)

	if userIDOf(t, service, "a new person") == "" {
		t.Error("the account the provider sign-in created did not stay")
	}

	expectUnavailable(t, service.GET("/oauth/consent/"+handle))
	expectUnavailable(t, service.AllowConsent(handle))
	expectUnavailable(t, service.CancelConsent(handle))
}

// Consent's answers are refused unless they carry exactly the site's origin and
// the browser's binding. The origin is judged before the handle is even read,
// and no refusal consumes the consent.
func TestConsentAnswersNeedSiteOriginAndBinding(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	handle := client.ReachConsent(client.Pending(ipv4Template, 49152, "openid"), oauth.Discord,
		service.Providers.Someone(oauth.Discord, "the person"))

	answers := []string{"/oauth/consent/" + handle + "/allow", "/oauth/consent/" + handle + "/cancel"}

	for name, origins := range map[string][]string{
		"no origin":            nil,
		"null":                 {"null"},
		"a trailing slash":     {servertest.SiteOrigin + "/"},
		"a path":               {servertest.SiteOrigin + "/consent"},
		"another port":         {servertest.SiteOrigin + ":444"},
		"plain HTTP":           {"http://auth.example.test"},
		"the API's origin":     {servertest.APIOrigin},
		"a foreign origin":     {"https://elsewhere.example.test"},
		"two origins":          {servertest.SiteOrigin, servertest.SiteOrigin},
		"comma-joined origins": {servertest.SiteOrigin + ", " + servertest.SiteOrigin},
		"credentials":          {"https://user@auth.example.test"},
	} {
		t.Run(name, func(t *testing.T) {
			withOrigins := func(request *http.Request) {
				for _, origin := range origins {
					request.Header.Add("Origin", origin)
				}
			}

			for _, path := range answers {
				expectForbidden(t, service.POSTForm(path, "", withOrigins))
			}

			// A handle that could never be looked up is refused for its origin
			// first, so the two refusals cannot be told apart by what they read.
			for _, path := range []string{"/oauth/consent/short/allow", "/oauth/consent/short/cancel"} {
				expectForbidden(t, service.POSTForm(path, "", withOrigins))
			}
		})
	}

	binding := service.CookieValue(service.NativeLoginCookieName())
	service.Forget(service.NativeLoginCookieName())

	for name, cookies := range map[string]string{
		"no binding":           "",
		"another binding":      service.NativeLoginCookieName() + "=" + strings.Repeat("B", 42) + "A",
		"conflicting bindings": service.NativeLoginCookieName() + "=" + binding + "; " + service.NativeLoginCookieName() + "=" + strings.Repeat("B", 42) + "A",
		"a quoted binding":     service.NativeLoginCookieName() + `="` + binding + `"`,
		"the login cookie":     service.LoginCookieName() + "=" + binding,
	} {
		t.Run(name, func(t *testing.T) {
			carrying := func(request *http.Request) {
				service.FromSite(request)

				if cookies != "" {
					request.Header.Set("Cookie", cookies)
				}
			}

			expectUnavailable(t, service.GET("/oauth/consent/"+handle, carrying))

			for _, path := range answers {
				expectUnavailable(t, service.POSTForm(path, "", carrying))
			}
		})
	}

	genuine := func(request *http.Request) {
		service.FromSite(request)
		request.Header.Set("Cookie", service.NativeLoginCookieName()+"="+binding)
	}

	for _, malformed := range []string{"short", strings.Repeat("A", 44), strings.Repeat("A", 42) + "B", strings.Repeat("A", 42) + "="} {
		expectUnavailable(t, service.GET("/oauth/consent/"+malformed, genuine))
		expectUnavailable(t, service.POSTForm("/oauth/consent/"+malformed+"/allow", "", genuine))
		expectUnavailable(t, service.POSTForm("/oauth/consent/"+malformed+"/cancel", "", genuine))
	}

	if held := countRows(t, service, "oauth_native_authorization_code"); held != 0 {
		t.Errorf("a refused answer created %d codes", held)
	}

	// The genuine browser is the positive control, and nothing above consumed the
	// consent. Nothing in the form is read, whatever it says.
	service.GET("/oauth/consent/"+handle, genuine).ExpectStatus(http.StatusOK)
	service.POSTForm("/oauth/consent/"+handle+"/allow?answer=cancel", "answer=cancel&state=forged", genuine).
		ExpectStatus(http.StatusSeeOther)

	if held := countRows(t, service, "oauth_native_authorization_code"); held != 1 {
		t.Errorf("the genuine approval created %d codes", held)
	}
}

// A page handle is no consent and a consent handle is no page, in either
// direction and at every stage, and another authorization's handle answers for
// nothing. Presenting one consumes nothing.
func TestPageAndConsentHandlesAreNotInterchangeable(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	waitingPage := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49152, "openid")))

	expectUnavailable(t, service.GET("/oauth/consent/"+waitingPage))
	expectUnavailable(t, service.AllowConsent(waitingPage))
	expectUnavailable(t, service.CancelConsent(waitingPage))

	spentPage := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49153, "openid")))
	consent := service.ConsentHandle(service.FinishLogin(service.ChooseProvider(spentPage, oauth.Discord),
		service.Providers.Someone(oauth.Discord, "the person")))

	expectUnavailable(t, service.GET("/oauth/authorization/"+consent))
	expectUnavailable(t, service.POSTForm("/oauth/authorization/"+consent+"/discord", "", service.FromSite))
	expectUnavailable(t, service.GET("/oauth/consent/"+spentPage))
	expectUnavailable(t, service.AllowConsent(spentPage))

	service.GET("/oauth/authorization/" + waitingPage).ExpectStatus(http.StatusOK)
	service.GET("/oauth/consent/" + consent).ExpectStatus(http.StatusOK)

	if held := countRows(t, service, "oauth_native_authorization_code"); held != 0 {
		t.Errorf("a misplaced handle created %d codes", held)
	}
}

// Of an approval and a cancellation, and of several approvals, racing for one
// consent exactly one wins. Every loser is the one fixed refusal, which cannot
// say which action won, and at most one code ever exists.
func TestExactlyOneConsentAnswerWins(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	for attempt := range 5 {
		pending := client.Pending(ipv4Template, 49152+attempt, "openid")
		handle := client.ReachConsent(pending, oauth.Discord, service.Providers.Someone(oauth.Discord, "the person"))

		submissions := []func(string, ...func(*http.Request)) *servertest.Response{
			service.AllowConsent, service.CancelConsent, service.AllowConsent,
		}

		answers := make([]*servertest.Response, len(submissions))

		var racing sync.WaitGroup

		for index, submit := range submissions {
			racing.Add(1)

			go func() {
				defer racing.Done()

				answers[index] = submit(handle)
			}()
		}

		racing.Wait()

		won := 0
		code := ""

		for _, answer := range answers {
			switch answer.Status {
			case http.StatusSeeOther:
				won++

				returned, err := pending.Read(answer.Header.Get("Location"), servertest.OpenIDIssuer)
				if err != nil {
					t.Errorf("the winner's answer cannot be read: %v", err)
				}

				code = returned.Code
			default:
				expectUnavailable(t, answer)
			}
		}

		if won != 1 {
			t.Errorf("%d of the racing answers won, want exactly one", won)
		}

		if code != "" {
			client.Exchange(pending, code).ExpectStatus(http.StatusOK)
		}

		testdatabase.Execute(t, service.Pool, `DELETE FROM oauth_native_authorization`)
	}
}

// Consent never extends the deadline it was reached under: once it passes,
// reading and answering are the same refusal and no code is created.
func TestExpiredConsentGrantsNothing(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	handle := client.ReachConsent(client.Pending(ipv4Template, 49152, "openid"), oauth.Discord,
		service.Providers.Someone(oauth.Discord, "the person"))

	testdatabase.Execute(t, service.Pool, `UPDATE oauth_native_authorization
		SET created_at = created_at - interval '5 minutes', expires_at = expires_at - interval '5 minutes'`)

	expectUnavailable(t, service.GET("/oauth/consent/"+handle))
	expectUnavailable(t, service.AllowConsent(handle))
	expectUnavailable(t, service.CancelConsent(handle))

	if held := countRows(t, service, "oauth_native_authorization_code"); held != 0 {
		t.Errorf("an expired consent created %d codes", held)
	}
}

// A code issued close to the deadline is cut short by it: it is always positive,
// at most 120 seconds, and never outlives its authorization.
func TestCodeIssuedNearDeadlineNeverOutlivesIt(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	pending := client.Pending(ipv4Template, 49152, "openid")
	handle := client.ReachConsent(pending, oauth.Discord, service.Providers.Someone(oauth.Discord, "the person"))

	testdatabase.Execute(t, service.Pool, `UPDATE oauth_native_authorization
		SET created_at = created_at - interval '4 minutes 30 seconds',
			expires_at = expires_at - interval '4 minutes 30 seconds'`)

	service.AllowConsent(handle).ExpectStatus(http.StatusSeeOther)

	var (
		matches  bool
		lifetime time.Duration
	)

	if err := service.Pool.QueryRow(t.Context(), `SELECT c.expires_at = r.expires_at, c.expires_at - c.created_at
		FROM oauth_native_authorization_code c
		JOIN oauth_native_authorization r ON r.id = c.authorization_id`).Scan(&matches, &lifetime); err != nil {
		t.Fatalf("reading the code: %v", err)
	}

	if !matches || lifetime <= 0 || lifetime > 30*time.Second {
		t.Errorf("the code ends at the authorization's deadline = %v, and lives %v", matches, lifetime)
	}
}

// A person or an application deleted while the consent waits leaves nothing to
// read or answer, and nothing for a client.
func TestConsentEndsWithItsPersonOrApplication(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)

	person := service.Providers.Someone(oauth.Discord, "the person")
	ofPerson := client.ReachConsent(client.Pending(ipv4Template, 49152, "openid"), oauth.Discord, person)

	testdatabase.Execute(t, service.Pool, `DELETE FROM "User" WHERE "username" = 'the person'`)

	expectUnavailable(t, service.GET("/oauth/consent/"+ofPerson))
	expectUnavailable(t, service.AllowConsent(ofPerson))
	expectUnavailable(t, service.CancelConsent(ofPerson))

	ofApplication := client.ReachConsent(client.Pending(ipv4Template, 49153, "openid"), oauth.Discord,
		service.Providers.Someone(oauth.Discord, "another person"))

	service.DELETE("/developer_application/"+application.ID.String(), service.Protected).ExpectStatus(http.StatusOK)

	expectUnavailable(t, service.GET("/oauth/consent/"+ofApplication))
	expectUnavailable(t, service.AllowConsent(ofApplication))
	expectUnavailable(t, service.CancelConsent(ofApplication))

	if held := countRows(t, service, "oauth_native_authorization_code"); held != 0 {
		t.Errorf("a consent without its person or application created %d codes", held)
	}
}

// A failure answering a consent says nothing about why and logs only the fixed
// event, the request and the matched route: never the handle, the binding, the
// application, the person, what the request carried or what the database said.
// Once the database recovers, the consent is still there to answer.
func TestConsentFailureLogsNothingItHandled(t *testing.T) {
	t.Parallel()

	const applicationSentinel = "application-name-sentinel"

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	client := service.InstalledClient(service.RegisterPublicClient(applicationSentinel, ipv4Template))

	pending := client.Pending(ipv4Template, 49152, "openid")
	handle := client.ReachConsent(pending, oauth.Discord, service.Providers.Someone(oauth.Discord, "person-name-sentinel"))
	binding := service.CookieValue(service.NativeLoginCookieName())
	person := userIDOf(t, service, "person-name-sentinel")

	testdatabase.Execute(t, service.Pool,
		`ALTER TABLE oauth_native_authorization RENAME TO database_error_sentinel`)

	for what, answer := range map[string]*servertest.Response{
		"viewing":    service.GET("/oauth/consent/" + handle + "?query=query-value-sentinel"),
		"allowing":   service.POSTForm("/oauth/consent/"+handle+"/allow?query=query-value-sentinel", "form=form-value-sentinel", service.FromSite),
		"cancelling": service.POSTForm("/oauth/consent/"+handle+"/cancel?query=query-value-sentinel", "form=form-value-sentinel", service.FromSite),
	} {
		t.Run(what, func(t *testing.T) {
			answer.ExpectStatus(http.StatusInternalServerError).ExpectDetail("Internal Server Error")
			expectPageHeaders(t, answer)

			if strings.Contains(string(answer.Body), "sentinel") {
				t.Errorf("the answer repeats what it handled: %s", answer.Body)
			}
		})
	}

	written := service.Logs.String()

	for _, secret := range []string{
		handle, binding, person, applicationSentinel, "person-name-sentinel", "query-value-sentinel",
		"form-value-sentinel", "database_error_sentinel", pending.State, pending.RedirectURI,
	} {
		if strings.Contains(written, secret) {
			t.Errorf("the log carries a value the request handled: %q", secret)
		}
	}

	for _, expected := range []string{
		"a public-client request could not be answered", "request_id", "/api/oauth/consent/{consent}/allow",
	} {
		if !strings.Contains(written, expected) {
			t.Errorf("the log does not carry %q", expected)
		}
	}

	testdatabase.Execute(t, service.Pool,
		`ALTER TABLE database_error_sentinel RENAME TO oauth_native_authorization`)

	service.GET("/oauth/consent/" + handle).ExpectStatus(http.StatusOK)
	service.AllowConsent(handle).ExpectStatus(http.StatusSeeOther)
}

// An application name is returned at consent as the text it was registered with.
func TestHostileApplicationNameIsReturnedAtConsentAsText(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	hostile := `<script>alert("x")</script><img src=x onerror=alert(1)>`
	client := service.InstalledClient(service.RegisterPublicClient(hostile, ipv4Template))

	handle := client.ReachConsent(client.Pending(ipv4Template, 49152, "openid"), oauth.Discord,
		service.Providers.Someone(oauth.Discord, "the person"))

	view := service.GET("/oauth/consent/" + handle).ExpectStatus(http.StatusOK)

	if strings.Contains(string(view.Body), "<script>") {
		t.Error("the consent model carries markup unescaped")
	}

	var model consentModel

	if view.DecodeInto(&model); model.ApplicationName != hostile {
		t.Errorf("application name = %q, want the registered text", model.ApplicationName)
	}

	if view.Header.Get("Content-Type") != "application/json" {
		t.Errorf("the consent model is served as %q", view.Header.Get("Content-Type"))
	}
}

// A public authorization and a confidential sign-in in other tabs of one
// browser use separate cookies and never disturb each other, and a second
// public authorization reuses the browser's binding.
func TestPublicAuthorizationAndConfidentialSignInShareBrowserSafely(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	_, client := installedClient(t, service)

	confidential := service.RegisterApplication("a server-side application", externalCallbackURI)

	first := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49152, "openid")))
	binding := service.CookieValue(service.NativeLoginCookieName())

	login := service.StartLogin(oauth.Discord, confidential.ID, externalCallbackURI)
	loginBinding := service.CookieValue(service.LoginCookieName())

	again := client.Authorize(client.Pending(ipv6Template, 49153, "openid"))
	second := service.PageHandle(again)

	if reused := again.Cookie(service.NativeLoginCookieName()); reused == nil || reused.Value != binding || reused.MaxAge != 300 {
		t.Errorf("the second authorization did not renew the browser's binding: %+v", reused)
	}

	if service.CookieValue(service.LoginCookieName()) != loginBinding {
		t.Error("a public authorization replaced the confidential login's binding")
	}

	if loginBinding == binding {
		t.Error("the two flows share a binding value")
	}

	service.FinishLogin(login, service.Providers.Someone(oauth.Discord, "someone")).
		ExpectStatus(http.StatusTemporaryRedirect)

	service.GET("/oauth/authorization/" + first).ExpectStatus(http.StatusOK)
	service.GET("/oauth/authorization/" + second).ExpectStatus(http.StatusOK)
}

// The service holds at most ten thousand authorizations at once. The last slot
// is taken exactly once, the next request is told only to come back later,
// nothing names the client, and ending one frees its slot.
func TestAuthorizationCapacityIsExactAndRecovers(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	application, client := installedClient(t, service)

	// Ten thousand authorizations are written directly: making them one request
	// at a time would spend the suite's whole budget proving a count.
	testdatabase.Execute(t, service.Pool, `INSERT INTO oauth_native_authorization (
			application_id, browser_binding_hash, redirect_uri, scopes, client_state, client_nonce,
			code_challenge, stage, page_handle_hash, auth_epoch, expires_at)
		SELECT $1, sha256(('b' || g)::bytea), 'http://127.0.0.1:1/oauth/callback', 'openid',
			repeat('s', 43), repeat('n', 43), repeat('c', 43), 'page', sha256(('h' || g)::bytea),
			(SELECT epoch FROM auth_epoch), CURRENT_TIMESTAMP + interval '5 minutes'
		FROM generate_series(1, $2::int) g`, application.ID, oauth.NativeAuthorizationCapacity-1)

	last := client.Pending(ipv4Template, 49152, "openid")
	handle := service.PageHandle(client.Authorize(last))

	full := client.Pending(ipv4Template, 49153, "openid")
	refused := client.Authorize(full).ExpectStatus(http.StatusSeeOther)
	refused.ExpectRedirectTo(full.RedirectURI + "?error=temporarily_unavailable&state=" + full.State +
		"&iss=" + url.QueryEscape(servertest.OpenIDIssuer))

	if strings.Contains(refused.Header.Get("Location"), application.ID.String()) {
		t.Error("the capacity refusal names the client")
	}

	if held := countRows(t, service, "oauth_native_authorization"); held != oauth.NativeAuthorizationCapacity {
		t.Errorf("%d authorizations are held, want exactly the capacity", held)
	}

	consent := service.ConsentHandle(service.FinishLogin(service.ChooseProvider(handle, oauth.Discord),
		service.Providers.Someone(oauth.Discord, "the person")))
	service.CancelConsent(consent).ExpectStatus(http.StatusSeeOther)
	service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49154, "openid")))

	if _, err := database.RotateAuthority(t.Context(), service.Pool); err != nil {
		t.Fatalf("rotating the authority: %v", err)
	}

	if held := countRows(t, service, "oauth_native_authorization"); held != 0 {
		t.Errorf("rotation left %d authorizations holding slots", held)
	}
}

// An application name is returned as the text it was registered with, so the
// page can only render it as text.
func TestHostileApplicationNameIsReturnedAsText(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	hostile := `<script>alert("x")</script><img src=x onerror=alert(1)>`
	application := service.RegisterPublicClient(hostile, ipv4Template)
	client := service.InstalledClient(application)

	handle := service.PageHandle(client.Authorize(client.Pending(ipv4Template, 49152, "openid")))

	view := service.GET("/oauth/authorization/" + handle).ExpectStatus(http.StatusOK)

	if strings.Contains(string(view.Body), "<script>") {
		t.Error("the page model carries markup unescaped")
	}

	var page struct {
		ApplicationName string `json:"application_name"`
	}

	if view.DecodeInto(&page); page.ApplicationName != hostile {
		t.Errorf("application name = %q, want the registered text", page.ApplicationName)
	}

	if view.Header.Get("Content-Type") != "application/json" {
		t.Errorf("the page model is served as %q", view.Header.Get("Content-Type"))
	}
}
