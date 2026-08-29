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
		{"uppercase scheme is normalised", "HTTPS://Example.test/callback"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := urlpolicy.ParseCallbackURI(testCase.uri)
			if err != nil {
				t.Fatalf("ParseCallbackURI(%q) = %v, want no error", testCase.uri, err)
			}

			if parsed == nil {
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

			got := urlpolicy.WithResponseParameter(parsed, testCase.key, testCase.value)
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

func TestParseCallbackURIIsExactAndStable(t *testing.T) {
	t.Parallel()

	// Two spellings that differ only in case of the scheme and host resolve to
	// the same URL, but the stored form is what the application registered.
	parsed, err := urlpolicy.ParseCallbackURI("HTTPS://Example.TEST/Callback")
	if err != nil {
		t.Fatalf("ParseCallbackURI = %v", err)
	}

	if parsed.Scheme != "https" {
		t.Errorf("scheme = %q, want https", parsed.Scheme)
	}

	if parsed.Host != "example.test" {
		t.Errorf("host = %q, want example.test", parsed.Host)
	}

	if parsed.Path != "/Callback" {
		t.Errorf("path = %q, want /Callback, paths are case sensitive", parsed.Path)
	}

	if _, err := url.Parse(parsed.String()); err != nil {
		t.Fatalf("normalised URL does not re-parse: %v", err)
	}
}
