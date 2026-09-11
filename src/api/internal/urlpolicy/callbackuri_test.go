package urlpolicy_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

func TestParseCallbackURIAccepts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"https host", "https://example.test/callback"},
		{"https with port", "https://example.test:8443/callback"},
		{"https root path", "https://example.test/"},
		{"https bare host", "https://example.test"},
		{"https with unrelated query", "https://example.test/callback?tenant=acme&next=%2Fhome"},
		{"loopback name with port", "http://localhost:8001/login/callback"},
		{"loopback address with port", "http://127.0.0.1:3000/callback"},
		{"loopback range with port", "http://127.5.5.5:3000/callback"},
		{"ipv6 loopback with port", "http://[::1]:3000/callback"},
		{"uppercase scheme and host", "HTTPS://Example.test/callback"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := urlpolicy.ParseCallbackURI(testCase.uri)
			if err != nil {
				t.Fatalf("ParseCallbackURI(%q) = %v, want no error", testCase.uri, err)
			}

			if parsed.IsZero() {
				t.Fatal("ParseCallbackURI returned no URL")
			}
		})
	}
}

func TestParseCallbackURIRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"relative", "/callback"},
		{"scheme relative", "//example.test/callback"},
		{"no scheme", "example.test/callback"},
		{"javascript scheme", "javascript:alert(1)"},
		{"data scheme", "data:text/html,hello"},
		{"file scheme", "file:///etc/passwd"},
		{"ftp scheme", "ftp://example.test/callback"},
		{"http on public host", "http://example.test/callback"},
		{"http loopback without port", "http://localhost/callback"},
		{"http loopback address without port", "http://127.0.0.1/callback"},
		{"https with userinfo", "https://user:pass@example.test/callback"},
		{"https with username only", "https://user@example.test/callback"},
		{"https with fragment", "https://example.test/callback#token"},
		{"https with empty fragment", "https://example.test/callback#"},
		{"no host", "https:///callback"},
		{"newline", "https://example.test/call\nback"},
		{"carriage return", "https://example.test/call\rback"},
		{"tab", "https://example.test/call\tback"},
		{"null byte", "https://example.test/call\x00back"},
		{"leading space", " https://example.test/callback"},
		{"trailing space", "https://example.test/callback "},
		{"port zero", "https://example.test:0/callback"},
		{"port out of range", "https://example.test:70000/callback"},
		{"malformed port", "https://example.test:notaport/callback"},
		{"malformed escape", "https://example.test/%zz"},
		{"private address is not loopback", "http://10.0.0.5:3000/callback"},
		{"ipv6 non loopback", "http://[2001:db8::1]:3000/callback"},
		{"loopback https without port is allowed elsewhere but http needs one", "http://[::1]/callback"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := urlpolicy.ParseCallbackURI(testCase.uri); err == nil {
				t.Fatalf("ParseCallbackURI(%q) = nil error, want rejection", testCase.uri)
			}
		})
	}
}

// A registered callback must not already carry the query key the service adds
// when it redirects, or the receiving application would see two values for it.
func TestParseRegisteredCallbackURIRejectsReservedQueryKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"code", "https://example.test/callback?code=x"},
		{"authentication", "https://example.test/callback?authentication=x"},
		{"code with no value", "https://example.test/callback?code"},
		{"code among others", "https://example.test/callback?tenant=acme&code=x"},
		{"percent encoded code key", "https://example.test/callback?%63ode=x"},
		{"percent encoded authentication key", "https://example.test/callback?%61uthentication=x"},
		{"uppercase is a different key but still reserved", "https://example.test/callback?CODE=x"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := urlpolicy.ParseRegisteredCallbackURI(testCase.uri)
			if !errors.Is(err, urlpolicy.ErrReservedQueryKey) {
				t.Fatalf("ParseRegisteredCallbackURI(%q) = %v, want ErrReservedQueryKey", testCase.uri, err)
			}
		})
	}
}

func TestParseRegisteredCallbackURIAcceptsUnrelatedQuery(t *testing.T) {
	t.Parallel()

	uri := "https://example.test/callback?tenant=acme&redirect=%2Fhome"

	if _, err := urlpolicy.ParseRegisteredCallbackURI(uri); err != nil {
		t.Fatalf("ParseRegisteredCallbackURI(%q) = %v, want no error", uri, err)
	}
}

// The service must add its response parameter without disturbing anything the
// application already put in the URL.
func TestWithResponseParameter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		uri   string
		key   string
		value string
		want  string
	}{
		{
			name:  "no existing query",
			uri:   "https://example.test/callback",
			key:   "code",
			value: "abc",
			want:  "https://example.test/callback?code=abc",
		},
		{
			name:  "existing query is preserved",
			uri:   "https://example.test/callback?tenant=acme",
			key:   "code",
			value: "abc",
			want:  "https://example.test/callback?tenant=acme&code=abc",
		},
		{
			name:  "value is encoded rather than concatenated",
			uri:   "https://example.test/callback",
			key:   "authentication",
			value: "a b&c=d/e?f#g",
			want:  "https://example.test/callback?authentication=a+b%26c%3Dd%2Fe%3Ff%23g",
		},
		{
			name:  "encoded values in the existing query are not rewritten",
			uri:   "https://example.test/callback?next=%2Fhome%3Fa%3Db",
			key:   "code",
			value: "abc",
			want:  "https://example.test/callback?next=%2Fhome%3Fa%3Db&code=abc",
		},
		{
			name:  "path is untouched",
			uri:   "https://example.test/a%20b/callback",
			key:   "code",
			value: "abc",
			want:  "https://example.test/a%20b/callback?code=abc",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := urlpolicy.ParseRegisteredCallbackURI(testCase.uri)
			if err != nil {
				t.Fatalf("ParseRegisteredCallbackURI(%q) = %v", testCase.uri, err)
			}

			got := parsed.WithResponseParameter(testCase.key, testCase.value)
			if got != testCase.want {
				t.Errorf("WithResponseParameter() = %q, want %q", got, testCase.want)
			}
		})
	}
}

// A rejected URI must not be echoed back, because callback URIs and their query
// values can carry information about the application that registered them.
func TestCallbackErrorsDoNotEchoTheURI(t *testing.T) {
	t.Parallel()

	uri := "https://user:hunter2@example.test/callback?tenant=secretcustomer#frag"

	_, err := urlpolicy.ParseCallbackURI(uri)
	if err == nil {
		t.Fatal("expected rejection")
	}

	for _, leak := range []string{"hunter2", "secretcustomer", "example.test", uri} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q contains %q", err.Error(), leak)
		}
	}
}

// The rules are applied case-insensitively to the scheme and host, but the
// browser is sent to the spelling that was registered: an application compares
// the redirect it receives against the string it gave, and a provider compares
// it against the string registered with it.
func TestACallbackKeepsTheSpellingItWasGiven(t *testing.T) {
	t.Parallel()

	const registered = "HTTPS://Example.TEST/Callback"

	callback, err := urlpolicy.ParseCallbackURI(registered)
	if err != nil {
		t.Fatalf("ParseCallbackURI = %v", err)
	}

	if callback.String() != registered {
		t.Errorf("String() = %q, want %q", callback.String(), registered)
	}

	if got := callback.WithResponseParameter("code", "abc"); got != registered+"?code=abc" {
		t.Errorf("WithResponseParameter() = %q, want %q", got, registered+"?code=abc")
	}

	compared := callback.URL()

	if compared.Scheme != "https" {
		t.Errorf("the compared scheme = %q, want https", compared.Scheme)
	}

	if compared.Host != "example.test" {
		t.Errorf("the compared host = %q, want example.test", compared.Host)
	}

	if compared.Path != "/Callback" {
		t.Errorf("the compared path = %q, want /Callback, paths are case sensitive", compared.Path)
	}

	if _, err := url.Parse(callback.String()); err != nil {
		t.Fatalf("the registered spelling does not re-parse: %v", err)
	}
}

// The parsed form is handed out as a copy, so a caller that rewrites it cannot
// change where a later redirect sends a browser.
func TestTheComparedURLCannotBeRewritten(t *testing.T) {
	t.Parallel()

	callback, err := urlpolicy.ParseCallbackURI("https://example.test/callback")
	if err != nil {
		t.Fatalf("ParseCallbackURI = %v", err)
	}

	taken := callback.URL()
	taken.Host = "attacker.test"

	if got := callback.URL().Host; got != "example.test" {
		t.Errorf("host = %q after a caller rewrote its copy, want example.test", got)
	}

	if got := callback.WithResponseParameter("code", "abc"); strings.Contains(got, "attacker.test") {
		t.Errorf("the redirect followed a rewritten copy: %q", got)
	}
}
