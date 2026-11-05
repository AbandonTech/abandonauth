package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

var (
	authorizationCode = strings.Repeat("C", 42) + "A"
	refreshTokenValue = strings.Repeat("R", 42) + "A"
)

func formRequest(path, body string, contentTypes ...string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, APIRoot+path, strings.NewReader(body))

	if contentTypes == nil {
		contentTypes = []string{"application/x-www-form-urlencoded"}
	}

	for _, contentType := range contentTypes {
		request.Header.Add("Content-Type", contentType)
	}

	return request
}

func codeGrantForm() url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {publicClientID},
		"code":          {authorizationCode},
		"redirect_uri":  {loopbackRedirect},
		"code_verifier": {clientVerifierText},
	}
}

func refreshGrantForm() url.Values {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {publicClientID},
		"refresh_token": {refreshTokenValue},
	}
}

// An authorization code grant is read with exactly its five members.
func TestTokenRequestReadsCodeGrant(t *testing.T) {
	t.Parallel()

	form := codeGrantForm()
	form.Set("unknown", "ignored")

	read, refusal := readNativeTokenRequest(formRequest("/oauth/token", form.Encode()))
	if refusal != "" {
		t.Fatalf("a valid code grant was refused: %q", refusal)
	}

	if read.grant != grantAuthorizationCode || read.clientID.String() != publicClientID ||
		read.code != authorizationCode || read.redirectURI != loopbackRedirect || read.codeVerifier != clientVerifierText {
		t.Errorf("the code grant was not read exactly: %+v", read)
	}
}

// A refresh grant keeps its scope when none is named and narrows it otherwise.
func TestTokenRequestReadsRefreshGrant(t *testing.T) {
	t.Parallel()

	read, refusal := readNativeTokenRequest(formRequest("/oauth/token", refreshGrantForm().Encode()))
	if refusal != "" || read.grant != grantRefreshToken || read.refreshToken != refreshTokenValue || read.scopes != nil {
		t.Fatalf("a refresh grant without scope was not read exactly: %q %+v", refusal, read)
	}

	form := refreshGrantForm()
	form.Set("scope", "profile openid")

	read, refusal = readNativeTokenRequest(formRequest("/oauth/token", form.Encode()))
	if refusal != "" || read.scopes == nil || *read.scopes != oidc.ScopeOpenID|oidc.ScopeProfile {
		t.Errorf("a narrowing refresh grant was not read exactly: %q", refusal)
	}
}

// Each malformed request earns its one fixed OAuth error, and nothing of the
// request is used.
func TestTokenRequestRefusals(t *testing.T) {
	t.Parallel()

	code := func(change func(url.Values)) string {
		form := codeGrantForm()
		change(form)

		return form.Encode()
	}

	refresh := func(change func(url.Values)) string {
		form := refreshGrantForm()
		change(form)

		return form.Encode()
	}

	tests := []struct {
		name         string
		body         string
		contentTypes []string
		header       string
		query        string
		want         string
	}{
		{name: "no content type", body: code(func(url.Values) {}), contentTypes: []string{}, want: response.OAuthInvalidRequest},
		{name: "a JSON body", body: `{"grant_type":"authorization_code"}`, contentTypes: []string{"application/json"}, want: response.OAuthInvalidRequest},
		{name: "a charset parameter", body: code(func(url.Values) {}), contentTypes: []string{"application/x-www-form-urlencoded; charset=UTF-8"}, want: response.OAuthInvalidRequest},
		{name: "two content types", body: code(func(url.Values) {}), contentTypes: []string{"application/x-www-form-urlencoded", "application/x-www-form-urlencoded"}, want: response.OAuthInvalidRequest},
		{name: "a comma-joined content type", body: code(func(url.Values) {}), contentTypes: []string{"application/x-www-form-urlencoded, text/plain"}, want: response.OAuthInvalidRequest},
		{name: "an Authorization header", body: code(func(url.Values) {}), header: "Basic Y2xpZW50OnNlY3JldA==", want: response.OAuthInvalidRequest},
		{name: "a client secret", body: code(func(v url.Values) { v.Set("client_secret", "x") }), want: response.OAuthInvalidRequest},
		{name: "an empty client secret", body: code(func(v url.Values) { v.Set("client_secret", "") }), want: response.OAuthInvalidRequest},
		{name: "a client assertion", body: code(func(v url.Values) { v.Set("client_assertion", "x") }), want: response.OAuthInvalidRequest},
		{name: "no grant type", body: code(func(v url.Values) { v.Del("grant_type") }), want: response.OAuthInvalidRequest},
		{name: "an empty grant type", body: code(func(v url.Values) { v.Set("grant_type", "") }), want: response.OAuthInvalidRequest},
		{name: "a repeated grant type", body: code(func(v url.Values) { v.Add("grant_type", "authorization_code") }), want: response.OAuthInvalidRequest},
		{name: "conflicting grant types", body: code(func(v url.Values) { v.Add("grant_type", "refresh_token") }), want: response.OAuthInvalidRequest},
		{name: "a password grant", body: code(func(v url.Values) { v.Set("grant_type", "password") }), want: response.OAuthUnsupportedGrantType},
		{name: "a client credentials grant", body: code(func(v url.Values) { v.Set("grant_type", "client_credentials") }), want: response.OAuthUnsupportedGrantType},
		{name: "a differently cased grant", body: code(func(v url.Values) { v.Set("grant_type", "Authorization_Code") }), want: response.OAuthUnsupportedGrantType},
		{name: "no client", body: code(func(v url.Values) { v.Del("client_id") }), want: response.OAuthInvalidRequest},
		{name: "a non-canonical client", body: code(func(v url.Values) { v.Set("client_id", "00000000-0000-0000-0000-00000000000A") }), want: response.OAuthInvalidRequest},
		{name: "a repeated client", body: code(func(v url.Values) { v.Add("client_id", publicClientID) }), want: response.OAuthInvalidRequest},
		{name: "no code", body: code(func(v url.Values) { v.Del("code") }), want: response.OAuthInvalidRequest},
		{name: "a 42-character code", body: code(func(v url.Values) { v.Set("code", authorizationCode[1:]) }), want: response.OAuthInvalidRequest},
		{name: "a 44-character code", body: code(func(v url.Values) { v.Set("code", authorizationCode+"A") }), want: response.OAuthInvalidRequest},
		{name: "a repeated code", body: code(func(v url.Values) { v.Add("code", authorizationCode) }), want: response.OAuthInvalidRequest},
		{name: "no redirect", body: code(func(v url.Values) { v.Del("redirect_uri") }), want: response.OAuthInvalidRequest},
		{name: "an empty redirect", body: code(func(v url.Values) { v.Set("redirect_uri", "") }), want: response.OAuthInvalidRequest},
		{name: "a redirect over 2,048 bytes", body: code(func(v url.Values) { v.Set("redirect_uri", loopbackRedirect+strings.Repeat("a", 2048)) }), want: response.OAuthInvalidRequest},
		{name: "no verifier", body: code(func(v url.Values) { v.Del("code_verifier") }), want: response.OAuthInvalidRequest},
		{name: "a 42-character verifier", body: code(func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 42)) }), want: response.OAuthInvalidRequest},
		{name: "a 129-character verifier", body: code(func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 129)) }), want: response.OAuthInvalidRequest},
		{name: "a verifier with a slash", body: code(func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 42)+"/") }), want: response.OAuthInvalidRequest},
		{name: "a verifier with padding", body: code(func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 42)+"=") }), want: response.OAuthInvalidRequest},
		{name: "a verifier with a plus decoded to a space", body: strings.Replace(code(func(url.Values) {}), "code_verifier=client", "code_verifier=client+", 1), want: response.OAuthInvalidRequest},
		{name: "a Unicode verifier", body: code(func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 42)+"é") }), want: response.OAuthInvalidRequest},
		{name: "a refresh token in a code grant", body: code(func(v url.Values) { v.Set("refresh_token", refreshTokenValue) }), want: response.OAuthInvalidRequest},
		{name: "a scope in a code grant", body: code(func(v url.Values) { v.Set("scope", "openid") }), want: response.OAuthInvalidRequest},
		{name: "no refresh token", body: refresh(func(v url.Values) { v.Del("refresh_token") }), want: response.OAuthInvalidRequest},
		{name: "a 44-character refresh token", body: refresh(func(v url.Values) { v.Set("refresh_token", refreshTokenValue+"A") }), want: response.OAuthInvalidRequest},
		{name: "a repeated refresh token", body: refresh(func(v url.Values) { v.Add("refresh_token", refreshTokenValue) }), want: response.OAuthInvalidRequest},
		{name: "a code in a refresh grant", body: refresh(func(v url.Values) { v.Set("code", authorizationCode) }), want: response.OAuthInvalidRequest},
		{name: "a verifier in a refresh grant", body: refresh(func(v url.Values) { v.Set("code_verifier", clientVerifierText) }), want: response.OAuthInvalidRequest},
		{name: "a refresh without a client", body: refresh(func(v url.Values) { v.Del("client_id") }), want: response.OAuthInvalidRequest},
		{name: "a malformed narrowing", body: refresh(func(v url.Values) { v.Set("scope", "openid  profile") }), want: response.OAuthInvalidRequest},
		{name: "a narrowing without openid", body: refresh(func(v url.Values) { v.Set("scope", "profile") }), want: response.OAuthInvalidScope},
		{name: "a repeated narrowing", body: refresh(func(v url.Values) { v["scope"] = []string{"openid", "openid"} }), want: response.OAuthInvalidRequest},
		{name: "a body over 16,384 bytes", body: code(func(v url.Values) { v.Set("padding", strings.Repeat("p", 16384)) }), want: response.OAuthInvalidRequest},
		{name: "more than 16 fields", body: code(func(url.Values) {}) + strings.Repeat("&x=1", 12), want: response.OAuthInvalidRequest},
		{name: "a semicolon separator", body: code(func(url.Values) {}) + ";x=1", want: response.OAuthInvalidRequest},
		{name: "an encoded field name", body: code(func(url.Values) {}) + "&client%5Fsecret=x", want: response.OAuthInvalidRequest},
		{name: "a differently cased field name", body: code(func(url.Values) {}) + "&Grant_Type=refresh_token", want: response.OAuthInvalidRequest},
		{name: "a malformed escape", body: code(func(url.Values) {}) + "&x=%G0", want: response.OAuthInvalidRequest},
		{name: "a control character", body: code(func(url.Values) {}) + "&x=%0d", want: response.OAuthInvalidRequest},
		{name: "parameters only in the query", body: "", query: code(func(url.Values) {}), want: response.OAuthInvalidRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := formRequest("/oauth/token", test.body, test.contentTypes...)
			if test.contentTypes != nil && len(test.contentTypes) == 0 {
				request.Header.Del("Content-Type")
			}

			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}

			request.URL.RawQuery = test.query

			if _, refusal := readNativeTokenRequest(request); refusal != test.want {
				t.Errorf("refusal = %q, want %q", refusal, test.want)
			}
		})
	}
}

// A form at every bound is still read: 16 fields, 16,384 bytes and a 64-byte
// name.
func TestTokenRequestAcceptsItsExactBounds(t *testing.T) {
	t.Parallel()

	body := codeGrantForm().Encode()
	for fields := 5; fields < 15; fields++ {
		body += "&u=1"
	}

	body += "&" + strings.Repeat("n", 64) + "="
	body += strings.Repeat("v", 16384-len(body))

	if len(body) != 16384 || strings.Count(body, "&")+1 != 16 {
		t.Fatalf("the boundary form has %d bytes and %d fields", len(body), strings.Count(body, "&")+1)
	}

	if _, refusal := readNativeTokenRequest(formRequest("/oauth/token", body)); refusal != "" {
		t.Errorf("a form at every bound was refused: %q", refusal)
	}
}

// A revocation names its client and token once each, and every
// token_type_hint is ignored entirely, whatever it says and however often.
func TestRevocationRequestIgnoresEveryHint(t *testing.T) {
	t.Parallel()

	base := url.Values{"client_id": {publicClientID}, "token": {refreshTokenValue}}.Encode()

	for name, hints := range map[string]string{
		"no hint":                    "",
		"a matching hint":            "&token_type_hint=refresh_token",
		"the other class":            "&token_type_hint=access_token",
		"an unknown hint":            "&token_type_hint=id_token",
		"an empty hint":              "&token_type_hint=",
		"a repeated hint":            "&token_type_hint=refresh_token&token_type_hint=access_token",
		"an encoded hint value":      "&token_type_hint=refresh%5Ftoken",
		"a differently cased name":   "&TOKEN_TYPE_HINT=refresh_token",
		"a differently cased value":  "&token_type_hint=REFRESH_TOKEN",
		"a hint without a value":     "&token_type_hint",
		"several hints and unknowns": "&token_type_hint=a&x=1&token_type_hint=b",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			read, readable := readNativeRevocationRequest(formRequest("/oauth/revoke", base+hints))
			if !readable || read.token != refreshTokenValue || read.clientID.String() != publicClientID {
				t.Errorf("a revocation with %s was not read exactly", name)
			}
		})
	}
}

// A malformed revocation is refused whole, before any lookup.
func TestRevocationRequestRefusals(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"no client":                  "token=" + refreshTokenValue,
		"a non-canonical client":     "client_id=00000000-0000-0000-0000-00000000000A&token=" + refreshTokenValue,
		"a repeated client":          "client_id=" + publicClientID + "&client_id=" + publicClientID + "&token=x",
		"no token":                   "client_id=" + publicClientID,
		"an empty token":             "client_id=" + publicClientID + "&token=",
		"a repeated token":           "client_id=" + publicClientID + "&token=a&token=b",
		"a token over 8,192 bytes":   "client_id=" + publicClientID + "&token=" + strings.Repeat("t", 8193),
		"an encoded hint name":       "client_id=" + publicClientID + "&token=x&token%5Ftype%5Fhint=a",
		"a malformed escape in hint": "client_id=" + publicClientID + "&token=x&token_type_hint=%",
		"more than 16 fields":        "client_id=" + publicClientID + "&token=x" + strings.Repeat("&token_type_hint=a", 15),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, readable := readNativeRevocationRequest(formRequest("/oauth/revoke", body)); readable {
				t.Error("a malformed revocation was read")
			}
		})
	}

	request := formRequest("/oauth/revoke", "client_id="+publicClientID+"&token=x", "text/plain")
	if _, readable := readNativeRevocationRequest(request); readable {
		t.Error("a revocation that is not a form was read")
	}

	request = formRequest("/oauth/revoke", "")
	request.URL.RawQuery = "client_id=" + publicClientID + "&token=x"

	if _, readable := readNativeRevocationRequest(request); readable {
		t.Error("a revocation was read from the query")
	}

	if _, readable := readNativeRevocationRequest(formRequest("/oauth/revoke",
		"client_id="+publicClientID+"&token="+strings.Repeat("t", 8192))); !readable {
		t.Error("a token of exactly 8,192 bytes was refused")
	}
}

// UserInfo reads one Bearer credential from one header, and nothing longer
// than any token this service signs.
func TestUserInfoReadsOneBearerCredential(t *testing.T) {
	t.Parallel()

	request := func(headers ...string) *http.Request {
		built := httptest.NewRequest(http.MethodGet, APIRoot+"/oauth/userinfo", nil)
		for _, header := range headers {
			built.Header.Add("Authorization", header)
		}

		return built
	}

	if token, readable := readOIDCAccessToken(request("Bearer a.b.c")); !readable || token != "a.b.c" {
		t.Error("a Bearer credential was not read")
	}

	if _, readable := readOIDCAccessToken(request("bearer a.b.c")); !readable {
		t.Error("the scheme was compared with its letter case")
	}

	if _, readable := readOIDCAccessToken(request("Bearer " + strings.Repeat("t", oidc.MaxTokenBytes))); !readable {
		t.Error("a credential of exactly the longest length was refused")
	}

	for name, headers := range map[string][]string{
		"no header":                  nil,
		"two headers":                {"Bearer a.b.c", "Bearer a.b.c"},
		"another scheme":             {"Basic a.b.c"},
		"no credential":              {"Bearer "},
		"no separator":               {"Bearer"},
		"a doubled space":            {"Bearer  a.b.c"},
		"a trailing word":            {"Bearer a.b.c extra"},
		"a credential over the size": {"Bearer " + strings.Repeat("t", oidc.MaxTokenBytes+1)},
	} {
		if _, readable := readOIDCAccessToken(request(headers...)); readable {
			t.Errorf("%s was read as a credential", name)
		}
	}
}
