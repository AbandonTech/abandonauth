package urlpolicy_test

import (
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

func TestParseOriginSecure(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"host only", "https://auth.example.test", "https://auth.example.test"},
		{"trailing slash", "https://auth.example.test/", "https://auth.example.test"},
		{"host is lower cased", "https://Auth.Example.TEST", "https://auth.example.test"},
		{"default port is dropped", "https://auth.example.test:443", "https://auth.example.test"},
		{"explicit port is kept", "https://auth.example.test:8443", "https://auth.example.test:8443"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			origin, err := urlpolicy.ParseOrigin(testCase.value, urlpolicy.RequireSecureTransport)
			if err != nil {
				t.Fatalf("ParseOrigin(%q) = %v", testCase.value, err)
			}

			if origin.String() != testCase.want {
				t.Errorf("ParseOrigin(%q) = %q, want %q", testCase.value, origin, testCase.want)
			}
		})
	}
}

func TestParseOriginSecureRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"plain http", "http://auth.example.test"},
		{"loopback http", "http://localhost:3000"},
		{"path", "https://auth.example.test/app"},
		{"query", "https://auth.example.test/?a=b"},
		{"fragment", "https://auth.example.test/#a"},
		{"userinfo", "https://user@auth.example.test"},
		{"credentials", "https://user:pass@auth.example.test"},
		{"no host", "https://"},
		{"not a url", "auth.example.test"},
		{"scheme relative", "//auth.example.test"},
		{"control character", "https://auth.example.test\n"},
		{"trailing space", "https://auth.example.test "},
		{"port zero", "https://auth.example.test:0"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := urlpolicy.ParseOrigin(testCase.value, urlpolicy.RequireSecureTransport); err == nil {
				t.Fatalf("ParseOrigin(%q) = nil error, want rejection", testCase.value)
			}
		})
	}
}

// Local development runs the site and the API over plain HTTP on the loopback
// interface. Nothing else may be reached without TLS.
func TestParseOriginAllowsLoopbackWithoutTransportSecurity(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"http://localhost:3000",
		"http://127.0.0.1:8000",
		"http://[::1]:8000",
	}

	for _, value := range allowed {
		if _, err := urlpolicy.ParseOrigin(value, urlpolicy.AllowLoopbackWithoutTransportSecurity); err != nil {
			t.Errorf("ParseOrigin(%q) = %v, want no error", value, err)
		}
	}

	rejected := []string{
		"http://auth.example.test",
		"http://10.0.0.5:8000",
		"http://localhost.example.test:3000",
	}

	for _, value := range rejected {
		if _, err := urlpolicy.ParseOrigin(value, urlpolicy.AllowLoopbackWithoutTransportSecurity); err == nil {
			t.Errorf("ParseOrigin(%q) = nil error, want rejection", value)
		}
	}
}

// Origin comparison decides whether a cookie-authenticated request is allowed to
// change state, so it must be exact rather than a prefix or suffix test.
func TestOriginEquality(t *testing.T) {
	t.Parallel()

	site, err := urlpolicy.ParseOrigin("https://auth.example.test", urlpolicy.RequireSecureTransport)
	if err != nil {
		t.Fatalf("ParseOrigin = %v", err)
	}

	equal := []string{
		"https://auth.example.test",
		"https://AUTH.example.test",
		"https://auth.example.test:443",
	}

	for _, value := range equal {
		if !site.MatchesHeader(value) {
			t.Errorf("MatchesHeader(%q) = false, want true", value)
		}
	}

	different := []string{
		"",
		"null",
		"NULL",
		"http://auth.example.test",
		"https://auth.example.test:8443",
		"https://auth.example.test.evil.test",
		"https://evil.test/auth.example.test",
		"https://evilauth.example.test",
		"https://auth.example.test/",
		"https://auth.example.test/path",
		"https://user@auth.example.test",
		"https://auth.example.test ",
		"https://auth.example.test\n",
	}

	for _, value := range different {
		if site.MatchesHeader(value) {
			t.Errorf("MatchesHeader(%q) = true, want false", value)
		}
	}
}

func TestOriginReportsLoopback(t *testing.T) {
	t.Parallel()

	loopback, err := urlpolicy.ParseOrigin("http://127.0.0.1:8000", urlpolicy.AllowLoopbackWithoutTransportSecurity)
	if err != nil {
		t.Fatalf("ParseOrigin = %v", err)
	}

	if !loopback.IsLoopback() {
		t.Error("IsLoopback() = false for http://127.0.0.1:8000")
	}

	remote, err := urlpolicy.ParseOrigin("https://auth.example.test", urlpolicy.RequireSecureTransport)
	if err != nil {
		t.Fatalf("ParseOrigin = %v", err)
	}

	if remote.IsLoopback() {
		t.Error("IsLoopback() = true for https://auth.example.test")
	}
}

func TestOriginErrorsDoNotEchoTheValue(t *testing.T) {
	t.Parallel()

	_, err := urlpolicy.ParseOrigin("https://user:hunter2@internal.example.test/secretpath", urlpolicy.RequireSecureTransport)
	if err == nil {
		t.Fatal("expected rejection")
	}

	for _, leak := range []string{"hunter2", "secretpath", "internal.example.test"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q contains %q", err.Error(), leak)
		}
	}
}

func TestZeroOriginIsUnusable(t *testing.T) {
	t.Parallel()

	var zero urlpolicy.Origin

	if zero.String() != "" {
		t.Errorf("zero Origin String() = %q, want empty", zero)
	}

	if zero.MatchesHeader("") || zero.MatchesHeader("https://auth.example.test") {
		t.Error("zero Origin matched a header value")
	}
}
