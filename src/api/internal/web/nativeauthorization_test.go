package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// pageHandle is a well-formed opaque handle. It is a placeholder and names
// nothing.
var pageHandle = strings.Repeat("A", 43)

const (
	publicClientID     = "00000000-0000-0000-0000-000000000002"
	loopbackRedirect   = "http://127.0.0.1:49152/oauth/callback"
	clientVerifierText = "client-verifier-placeholder-client-verifier-placeholder"
)

var (
	clientState = strings.Repeat("s", 43)
	clientNonce = strings.Repeat("n", 43)
)

func clientChallenge(t *testing.T) string {
	t.Helper()

	challenge, valid := oauth.ChallengeForVerifier(clientVerifierText)
	if !valid {
		t.Fatal("the placeholder verifier is not an RFC 7636 verifier")
	}

	return challenge
}

func authorizationParametersFor(t *testing.T) url.Values {
	t.Helper()

	return url.Values{
		"response_type":         {"code"},
		"client_id":             {publicClientID},
		"redirect_uri":          {loopbackRedirect},
		"scope":                 {"openid profile offline_access"},
		"state":                 {clientState},
		"nonce":                 {clientNonce},
		"code_challenge":        {clientChallenge(t)},
		"code_challenge_method": {"S256"},
	}
}

func authorizationRequestWithQuery(rawQuery string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, APIRoot+"/oauth/authorize", nil)
	request.URL.RawQuery = rawQuery

	return request
}

// A complete request is read whole: the client, the exact redirect, the
// client's own random values and the canonical scopes.
func TestAuthorizationRequestReadsEveryParameter(t *testing.T) {
	t.Parallel()

	parameters := authorizationParametersFor(t)
	parameters.Set("scope", "offline_access openid profile")
	parameters.Set("response_mode", "query")
	parameters.Set("an_unknown_parameter", "ignored")

	read, readable := readNativeAuthorizationRequest(authorizationRequestWithQuery(parameters.Encode()))
	if !readable || read.refusal != "" {
		t.Fatalf("a valid request was refused: readable %v, refusal %q", readable, read.refusal)
	}

	if read.clientID.String() != publicClientID || read.redirectURI != loopbackRedirect {
		t.Errorf("client and redirect = %s %q", read.clientID, read.redirectURI)
	}

	if read.clientState != clientState || read.nonce != clientNonce || read.codeChallenge != clientChallenge(t) {
		t.Error("the client's state, nonce or challenge was not read exactly")
	}

	if read.scopes.String() != "openid profile offline_access" {
		t.Errorf("scopes = %q, want the canonical order", read.scopes)
	}
}

// Nothing is redirected until the client and the redirect are proven, so a
// request whose client or redirect cannot even be read is refused directly.
func TestAuthorizationRequestRefusesUnreadableClientOrRedirectDirectly(t *testing.T) {
	t.Parallel()

	valid := authorizationParametersFor(t).Encode()

	tests := map[string]string{
		"no client":                     strings.Replace(valid, "client_id=", "unrelated=", 1),
		"a repeated client":             valid + "&client_id=" + publicClientID,
		"an upper-case client":          strings.Replace(valid, publicClientID, "00000000-0000-0000-0000-00000000000A", 1),
		"a client without hyphens":      strings.Replace(valid, publicClientID, strings.ReplaceAll(publicClientID, "-", ""), 1),
		"a braced client":               strings.Replace(valid, publicClientID, "%7B"+publicClientID+"%7D", 1),
		"no redirect":                   strings.Replace(valid, "redirect_uri=", "unrelated_uri=", 1),
		"a repeated redirect":           valid + "&redirect_uri=" + url.QueryEscape(loopbackRedirect),
		"an empty redirect":             valid + "&redirect_uri=",
		"a redirect over 2,048 bytes":   replaceParameter(valid, "redirect_uri", loopbackRedirect+"?q="+strings.Repeat("a", 2048)),
		"a bare percent sign":           valid + "&x=%",
		"a truncated escape":            valid + "&x=%4",
		"a non-hexadecimal escape":      valid + "&x=%zz",
		"a semicolon separator":         valid + ";x=1",
		"an encoded parameter name":     valid + "&client%5Fid=" + publicClientID,
		"a differently cased name":      valid + "&Client_ID=" + publicClientID,
		"invalid UTF-8":                 valid + "&x=%ff",
		"a NUL":                         valid + "&x=%00",
		"a control character":           valid + "&x=%0a",
		"a raw space":                   valid + "&x=a b",
		"an empty field":                valid + "&&x=1",
		"a name over 64 bytes":          valid + "&" + strings.Repeat("n", 65) + "=1",
		"more than 32 fields":           valid + strings.Repeat("&x=1", 32),
		"a query over 8,192 bytes":      valid + "&x=" + strings.Repeat("a", 8192),
		"a duplicate only once decoded": valid + "&client%5fid=" + publicClientID,
	}

	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, readable := readNativeAuthorizationRequest(authorizationRequestWithQuery(query)); readable {
				t.Error("an unreadable client or redirect was read")
			}
		})
	}
}

// Limits are exact: the largest permitted request is read.
func TestAuthorizationRequestAcceptsItsExactBounds(t *testing.T) {
	t.Parallel()

	parameters := authorizationParametersFor(t)
	longest := "http://127.0.0.1:1/" + strings.Repeat("p", urlpolicy.MaxNativeRedirectBytes-len("http://127.0.0.1:1/"))
	parameters.Set("redirect_uri", longest)

	query := parameters.Encode()

	for fields := len(parameters); fields < 31; fields++ {
		query += "&u=1"
	}

	query += "&" + strings.Repeat("n", 64) + "="
	query += strings.Repeat("v", 8192-len(query))

	if len(query) != 8192 || strings.Count(query, "&")+1 != 32 {
		t.Fatalf("the boundary query has %d bytes and %d fields", len(query), strings.Count(query, "&")+1)
	}

	read, readable := readNativeAuthorizationRequest(authorizationRequestWithQuery(query))
	if !readable || read.refusal != "" || read.redirectURI != longest {
		t.Errorf("a request at every bound was refused: readable %v, refusal %q", readable, read.refusal)
	}
}

func replaceParameter(query, name, value string) string {
	parsed, _ := url.ParseQuery(query)
	parsed.Set(name, value)

	return parsed.Encode()
}

// Once the client and the redirect can be read, every other fault becomes the
// OAuth error the client is redirected with, and the client's state is echoed
// only when exactly one valid state was given.
func TestAuthorizationRequestRedirectsEveryOtherFault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		change    func(url.Values)
		want      string
		echoState bool
	}{
		{"no response type", func(v url.Values) { v.Del("response_type") }, response.OAuthInvalidRequest, true},
		{"an empty response type", func(v url.Values) { v.Set("response_type", "") }, response.OAuthInvalidRequest, true},
		{"a token response type", func(v url.Values) { v.Set("response_type", "token") }, response.OAuthUnsupportedResponseType, true},
		{"a hybrid response type", func(v url.Values) { v.Set("response_type", "code id_token") }, response.OAuthUnsupportedResponseType, true},
		{"a repeated response type", func(v url.Values) { v.Add("response_type", "code") }, response.OAuthInvalidRequest, true},
		{"no scope", func(v url.Values) { v.Del("scope") }, response.OAuthInvalidRequest, true},
		{"a repeated scope", func(v url.Values) { v.Set("scope", "openid openid") }, response.OAuthInvalidScope, true},
		{"no openid", func(v url.Values) { v.Set("scope", "profile") }, response.OAuthInvalidScope, true},
		{"an unknown scope", func(v url.Values) { v.Set("scope", "openid email") }, response.OAuthInvalidScope, true},
		{"a doubled space", func(v url.Values) { v.Set("scope", "openid  profile") }, response.OAuthInvalidRequest, true},
		{"a leading space", func(v url.Values) { v.Set("scope", " openid") }, response.OAuthInvalidRequest, true},
		{"a scope over 64 bytes", func(v url.Values) { v.Set("scope", "openid "+strings.Repeat("x", 58)) }, response.OAuthInvalidRequest, true},
		{"a scope parameter given twice", func(v url.Values) { v.Add("scope", "openid") }, response.OAuthInvalidRequest, true},
		{"no state", func(v url.Values) { v.Del("state") }, response.OAuthInvalidRequest, false},
		{"a 42-character state", func(v url.Values) { v.Set("state", strings.Repeat("s", 42)) }, response.OAuthInvalidRequest, false},
		{"a 129-character state", func(v url.Values) { v.Set("state", strings.Repeat("s", 129)) }, response.OAuthInvalidRequest, false},
		{"a padded state", func(v url.Values) { v.Set("state", strings.Repeat("s", 43)+"=") }, response.OAuthInvalidRequest, false},
		{"a state with standard base64", func(v url.Values) { v.Set("state", strings.Repeat("s", 42)+"+") }, response.OAuthInvalidRequest, false},
		{"a state with a space", func(v url.Values) { v.Set("state", strings.Repeat("s", 42)+" ") }, response.OAuthInvalidRequest, false},
		{"a Unicode state", func(v url.Values) { v.Set("state", strings.Repeat("s", 42)+"é") }, response.OAuthInvalidRequest, false},
		{"a repeated state", func(v url.Values) { v.Add("state", clientState) }, response.OAuthInvalidRequest, false},
		{"no nonce", func(v url.Values) { v.Del("nonce") }, response.OAuthInvalidRequest, true},
		{"a 42-character nonce", func(v url.Values) { v.Set("nonce", strings.Repeat("n", 42)) }, response.OAuthInvalidRequest, true},
		{"a 129-character nonce", func(v url.Values) { v.Set("nonce", strings.Repeat("n", 129)) }, response.OAuthInvalidRequest, true},
		{"a repeated nonce", func(v url.Values) { v.Add("nonce", clientNonce) }, response.OAuthInvalidRequest, true},
		{"no challenge", func(v url.Values) { v.Del("code_challenge") }, response.OAuthInvalidRequest, true},
		{"a 42-character challenge", func(v url.Values) { v.Set("code_challenge", strings.Repeat("c", 42)) }, response.OAuthInvalidRequest, true},
		{"a 44-character challenge", func(v url.Values) { v.Set("code_challenge", strings.Repeat("c", 44)) }, response.OAuthInvalidRequest, true},
		{"a padded challenge", func(v url.Values) { v.Set("code_challenge", strings.Repeat("A", 42)+"=") }, response.OAuthInvalidRequest, true},
		{"no challenge method", func(v url.Values) { v.Del("code_challenge_method") }, response.OAuthInvalidRequest, true},
		{"the plain method", func(v url.Values) { v.Set("code_challenge_method", "plain") }, response.OAuthInvalidRequest, true},
		{"a lower-case method", func(v url.Values) { v.Set("code_challenge_method", "s256") }, response.OAuthInvalidRequest, true},
		{"a repeated method", func(v url.Values) { v.Add("code_challenge_method", "S256") }, response.OAuthInvalidRequest, true},
		{"a fragment response mode", func(v url.Values) { v.Set("response_mode", "fragment") }, response.OAuthInvalidRequest, true},
		{"a repeated response mode", func(v url.Values) { v["response_mode"] = []string{"query", "query"} }, response.OAuthInvalidRequest, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			parameters := authorizationParametersFor(t)
			test.change(parameters)

			read, readable := readNativeAuthorizationRequest(authorizationRequestWithQuery(parameters.Encode()))
			if !readable {
				t.Fatal("a readable client and redirect were refused directly")
			}

			if read.refusal != test.want {
				t.Errorf("refusal = %q, want %q", read.refusal, test.want)
			}

			if echoed := read.clientState != ""; echoed != test.echoState {
				t.Errorf("state echoed = %v, want %v", echoed, test.echoState)
			}
		})
	}
}

// State and nonce accept exactly 43 to 128 unpadded base64url characters.
func TestClientRandomValuesHaveExactBounds(t *testing.T) {
	t.Parallel()

	for _, length := range []int{43, 128} {
		parameters := authorizationParametersFor(t)
		parameters.Set("state", strings.Repeat("-", length))
		parameters.Set("nonce", strings.Repeat("_", length))

		read, readable := readNativeAuthorizationRequest(authorizationRequestWithQuery(parameters.Encode()))
		if !readable || read.refusal != "" {
			t.Errorf("a %d-character state and nonce were refused: %q", length, read.refusal)
		}
	}
}

// A page handle reaches a lookup only in its exact form.
func TestPageHandleIsReadOnlyInItsExactForm(t *testing.T) {
	t.Parallel()

	refused := map[string]string{
		"empty":             "",
		"one character":     "A",
		"42 characters":     strings.Repeat("A", 42),
		"44 characters":     strings.Repeat("A", 44),
		"padded":            strings.Repeat("A", 42) + "=",
		"standard base64":   strings.Repeat("A", 42) + "+",
		"a space":           strings.Repeat("A", 42) + " ",
		"a NUL":             strings.Repeat("A", 42) + "\x00",
		"Unicode":           strings.Repeat("A", 41) + "é",
		"a URL delimiter":   strings.Repeat("A", 42) + "/",
		"SQL-like text":     "' OR 1=1 --" + strings.Repeat("A", 32),
		"JWT-looking text":  "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
		"a large body":      strings.Repeat("A", 8193),
		"non-zero tail bit": strings.Repeat("A", 42) + "B",
	}

	for name, handle := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, APIRoot+"/oauth/authorization/x", nil)
			request.SetPathValue("request", handle)

			if _, readable := readAuthorizationPageHandle(request); readable {
				t.Error("a malformed handle would be looked up")
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, APIRoot+"/oauth/authorization/"+pageHandle, nil)
	request.SetPathValue("request", pageHandle)

	if handle, readable := readAuthorizationPageHandle(request); !readable || handle != pageHandle {
		t.Error("a well-formed handle was refused")
	}
}

// Only the four providers can be chosen, each by its exact name.
func TestProviderSelectionNamesOnlyOfferedProviders(t *testing.T) {
	t.Parallel()

	selection := func(provider string) *http.Request {
		request := httptest.NewRequest(http.MethodPost, APIRoot+"/oauth/authorization/x/y", nil)
		request.SetPathValue("request", pageHandle)
		request.SetPathValue("provider", provider)

		return request
	}

	for _, provider := range oauth.Providers {
		if _, chosen, readable := readProviderSelection(selection(string(provider))); !readable || chosen != provider {
			t.Errorf("%s could not be chosen", provider)
		}
	}

	for _, provider := range []string{"", "Discord", "twitter", "cancel", "steam "} {
		if _, _, readable := readProviderSelection(selection(provider)); readable {
			t.Errorf("%q was accepted as a provider", provider)
		}
	}
}

// The binding is read from the raw header, so a quoted, malformed or
// conflicting value binds nothing, while one repeated identically still binds.
func TestNativeBindingIsReadOnlyWhenUnambiguous(t *testing.T) {
	t.Parallel()

	server := &Server{}
	name := server.NativeLoginCookieName()

	if name != "__Host-abandonauth_native_oauth" {
		t.Fatalf("a deployment's binding cookie is %q", name)
	}

	other := strings.Repeat("B", 42) + "A"

	tests := []struct {
		label   string
		headers []string
		want    string
	}{
		{"one binding", []string{name + "=" + pageHandle}, pageHandle},
		{"among other cookies", []string{"a=b; " + name + "=" + pageHandle + "; c=d"}, pageHandle},
		{"the same value twice", []string{name + "=" + pageHandle, name + "=" + pageHandle}, pageHandle},
		{"none", []string{"a=b"}, ""},
		{"two values", []string{name + "=" + pageHandle + "; " + name + "=" + other}, ""},
		{"two values in two headers", []string{name + "=" + pageHandle, name + "=" + other}, ""},
		{"a quoted value", []string{name + `="` + pageHandle + `"`}, ""},
		{"a short value", []string{name + "=" + pageHandle[1:]}, ""},
		{"an oversized value", []string{name + "=" + strings.Repeat("A", 4096)}, ""},
		{"the unprefixed name", []string{"abandonauth_native_oauth=" + pageHandle}, ""},
		{"the confidential login's cookie", []string{"__Host-abandonauth_oauth=" + pageHandle}, ""},
	}

	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, APIRoot+"/oauth/authorize", nil)
			for _, header := range test.headers {
				request.Header.Add("Cookie", header)
			}

			if got := server.nativeBinding(request); got != test.want {
				t.Errorf("binding = %q, want %q", got, test.want)
			}
		})
	}
}

// The canonical scope order is what every response reports, whatever order
// was asked for.
func TestRequestedScopesAreReportedCanonically(t *testing.T) {
	t.Parallel()

	scopes, err := oidc.ParseScopes("offline_access profile openid")
	if err != nil || scopes.String() != "openid profile offline_access" {
		t.Errorf("scopes = %q, %v", scopes, err)
	}
}
