package urlpolicy_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

func TestNativeCallbackTemplatesAcceptPortlessLoopbackLiterals(t *testing.T) {
	t.Parallel()

	for _, template := range []string{
		"http://127.0.0.1/oauth/callback",
		"http://[::1]/oauth/callback",
		"http://127.255.0.9/",
		"http://127.0.0.1/callback?client=desktop&mode=a%20b",
		"http://127.0.0.1/a:b@c/~d!$'()*+,;=",
	} {
		parsed, err := urlpolicy.ParseNativeCallbackTemplate(template)
		if err != nil {
			t.Errorf("%q was refused: %v", template, err)

			continue
		}

		if parsed.String() != template {
			t.Errorf("%q was kept as %q", template, parsed.String())
		}
	}
}

func TestNativeCallbackTemplatesRefuseEverythingElse(t *testing.T) {
	t.Parallel()

	refused := map[string]string{
		"empty":                      "",
		"localhost":                  "http://localhost/cb",
		"a non-loopback address":     "http://10.0.0.1/cb",
		"a public address":           "http://203.0.113.9/cb",
		"https":                      "https://127.0.0.1/cb",
		"an upper-case scheme":       "HTTP://127.0.0.1/cb",
		"a private-use scheme":       "com.example.app:/cb",
		"a registered port":          "http://127.0.0.1:8080/cb",
		"an IPv6 registered port":    "http://[::1]:8080/cb",
		"no path":                    "http://127.0.0.1",
		"a query without a path":     "http://127.0.0.1?x=1",
		"user information":           "http://user@127.0.0.1/cb",
		"a fragment":                 "http://127.0.0.1/cb#frag",
		"an empty fragment":          "http://127.0.0.1/cb#",
		"a control character":        "http://127.0.0.1/c\x01b",
		"a space":                    "http://127.0.0.1/c b",
		"a tab":                      "http://127.0.0.1/c\tb",
		"a line break":               "http://127.0.0.1/c\r\nb",
		"a backslash":                `http://127.0.0.1/c\b`,
		"a backslash host":           `http://127.0.0.1\@evil.example/cb`,
		"unicode":                    "http://127.0.0.1/cällback",
		"a fullwidth dot host":       "http://127．0．0．1/cb",
		"an abbreviated IPv4":        "http://127.1/cb",
		"an integer IPv4":            "http://2130706433/cb",
		"an octal IPv4":              "http://0177.0.0.1/cb",
		"a leading-zero octet":       "http://127.0.0.01/cb",
		"a hexadecimal IPv4":         "http://0x7f.0.0.1/cb",
		"an overflowing octet":       "http://127.0.0.256/cb",
		"a trailing dot":             "http://127.0.0.1./cb",
		"an IPv4-mapped IPv6":        "http://[::ffff:127.0.0.1]/cb",
		"an expanded IPv6 loopback":  "http://[0:0:0:0:0:0:0:1]/cb",
		"a zoned IPv6 loopback":      "http://[::1%25eth0]/cb",
		"an encoded host delimiter":  "http://127.0.0.1%2Fevil/cb",
		"a dot segment":              "http://127.0.0.1/a/../cb",
		"a single dot segment":       "http://127.0.0.1/./cb",
		"a trailing dot segment":     "http://127.0.0.1/cb/..",
		"an encoded slash":           "http://127.0.0.1/a%2Fb",
		"an encoded backslash":       "http://127.0.0.1/a%5cb",
		"an encoded dot":             "http://127.0.0.1/%2e%2e/cb",
		"a bare percent":             "http://127.0.0.1/a%",
		"a truncated escape":         "http://127.0.0.1/a%4",
		"a non-hex escape":           "http://127.0.0.1/a%zz",
		"a repeated slash":           "http://127.0.0.1//cb",
		"an empty query":             "http://127.0.0.1/cb?",
		"an empty query key":         "http://127.0.0.1/cb?=1",
		"a semicolon separator":      "http://127.0.0.1/cb?a=1;b=2",
		"the code key":               "http://127.0.0.1/cb?code=1",
		"the state key":              "http://127.0.0.1/cb?state=1",
		"the error key":              "http://127.0.0.1/cb?error=1",
		"the error_description key":  "http://127.0.0.1/cb?error_description=1",
		"the iss key":                "http://127.0.0.1/cb?x=1&iss=1",
		"a case-varied reserved key": "http://127.0.0.1/cb?ISS=1",
		"an encoded reserved key":    "http://127.0.0.1/cb?%69ss=1",
		"an encoded case-varied key": "http://127.0.0.1/cb?St%41te=1",
		"an overlong template":       "http://127.0.0.1/" + strings.Repeat("a", urlpolicy.MaxNativeRedirectBytes),
	}

	for name, template := range refused {
		if _, err := urlpolicy.ParseNativeCallbackTemplate(template); err == nil {
			t.Errorf("%s was accepted", name)
		} else if template != "" && strings.Contains(err.Error(), template) {
			t.Errorf("%s: the refusal repeats the template", name)
		}
	}

	if _, err := urlpolicy.ParseNativeCallbackTemplate("http://127.0.0.1/cb?Code=1"); !errors.Is(
		err, urlpolicy.ErrReservedQueryKey,
	) {
		t.Errorf("a reserved key was refused as %v", err)
	}
}

func mustTemplate(t *testing.T, raw string) urlpolicy.NativeCallbackTemplate {
	t.Helper()

	template, err := urlpolicy.ParseNativeCallbackTemplate(raw)
	if err != nil {
		t.Fatalf("%q was refused: %v", raw, err)
	}

	return template
}

func TestNativeRedirectDiffersFromTemplateOnlyByPort(t *testing.T) {
	t.Parallel()

	ipv4 := mustTemplate(t, "http://127.0.0.1/oauth/callback?client=desktop")
	ipv6 := mustTemplate(t, "http://[::1]/oauth/callback")

	for _, accepted := range []struct {
		template  urlpolicy.NativeCallbackTemplate
		requested string
	}{
		{ipv4, "http://127.0.0.1:1/oauth/callback?client=desktop"},
		{ipv4, "http://127.0.0.1:65535/oauth/callback?client=desktop"},
		{ipv4, "http://127.0.0.1:49152/oauth/callback?client=desktop"},
		{ipv6, "http://[::1]:80/oauth/callback"},
	} {
		redirect, matched := urlpolicy.MatchNativeCallback(accepted.template, accepted.requested)
		if !matched || redirect != accepted.requested {
			t.Errorf("%q did not match its template", accepted.requested)
		}
	}

	for name, requested := range map[string]string{
		"no port":               "http://127.0.0.1/oauth/callback?client=desktop",
		"an empty port":         "http://127.0.0.1:/oauth/callback?client=desktop",
		"port zero":             "http://127.0.0.1:0/oauth/callback?client=desktop",
		"an overflowing port":   "http://127.0.0.1:65536/oauth/callback?client=desktop",
		"a leading-zero port":   "http://127.0.0.1:08080/oauth/callback?client=desktop",
		"a signed port":         "http://127.0.0.1:+8080/oauth/callback?client=desktop",
		"a malformed port":      "http://127.0.0.1:80a/oauth/callback?client=desktop",
		"two ports":             "http://127.0.0.1:80:81/oauth/callback?client=desktop",
		"another address":       "http://127.0.0.2:8080/oauth/callback?client=desktop",
		"another IP form":       "http://[::1]:8080/oauth/callback?client=desktop",
		"https":                 "https://127.0.0.1:8080/oauth/callback?client=desktop",
		"localhost":             "http://localhost:8080/oauth/callback?client=desktop",
		"another path":          "http://127.0.0.1:8080/oauth/callback2?client=desktop",
		"a case-varied path":    "http://127.0.0.1:8080/OAuth/callback?client=desktop",
		"an escaped path":       "http://127.0.0.1:8080/oauth/%63allback?client=desktop",
		"another query value":   "http://127.0.0.1:8080/oauth/callback?client=other",
		"a reordered query":     "http://127.0.0.1:8080/oauth/callback?client=desktop&x=1",
		"no query":              "http://127.0.0.1:8080/oauth/callback",
		"a fragment":            "http://127.0.0.1:8080/oauth/callback?client=desktop#x",
		"credentials":           "http://user@127.0.0.1:8080/oauth/callback?client=desktop",
		"an appended parameter": "http://127.0.0.1:8080/oauth/callback?client=desktop&code=x",
	} {
		if _, matched := urlpolicy.MatchNativeCallback(ipv4, requested); matched {
			t.Errorf("%s matched", name)
		}
	}

	if _, matched := urlpolicy.MatchNativeCallback(urlpolicy.NativeCallbackTemplate{}, "http://127.0.0.1:1/"); matched {
		t.Error("a template that was never parsed matched")
	}

	overlong := "http://127.0.0.1:1/" + strings.Repeat("a", urlpolicy.MaxNativeRedirectBytes)
	if _, matched := urlpolicy.MatchNativeCallback(mustTemplate(t, "http://127.0.0.1/"+strings.Repeat("a", 2000)), overlong); matched {
		t.Error("a redirect longer than the bound matched")
	}
}

// Whatever a client put in its state, the redirect carries it as one encoded
// parameter value: never a second parameter, a fragment or a line of a header.
func TestNativeAuthorizationResponseEncodesEachValueOnce(t *testing.T) {
	t.Parallel()

	hostile := "a&code=forged=%25#frag\r\nLocation: http://evil.example\tä"

	for _, redirect := range []string{"http://127.0.0.1:5000/cb", "http://127.0.0.1:5000/cb?client=desktop"} {
		built := urlpolicy.NativeAuthorizationResponse(redirect,
			[2]string{"code", "c0de"}, [2]string{"state", hostile}, [2]string{"iss", "https://auth.example.test/api"})

		if !strings.HasPrefix(built, redirect) {
			t.Errorf("the redirect %q was rewritten to %q", redirect, built)
		}

		if strings.ContainsAny(built, "#\r\n\t ") {
			t.Errorf("%q carries a fragment, a line break or whitespace", built)
		}

		parsed, err := url.Parse(built)
		if err != nil {
			t.Fatalf("%q is not a URL: %v", built, err)
		}

		query := parsed.Query()
		if got := query["state"]; len(got) != 1 || got[0] != hostile {
			t.Errorf("state = %q, want the hostile value once", got)
		}

		if got := query["code"]; len(got) != 1 || got[0] != "c0de" {
			t.Errorf("code = %q, want one value", got)
		}

		if got := query.Get("iss"); got != "https://auth.example.test/api" {
			t.Errorf("iss = %q", got)
		}
	}

	ordered := urlpolicy.NativeAuthorizationResponse("http://[::1]:7/cb",
		[2]string{"error", "access_denied"}, [2]string{"state", "s"}, [2]string{"iss", "i"})
	if ordered != "http://[::1]:7/cb?error=access_denied&state=s&iss=i" {
		t.Errorf("the response is %q", ordered)
	}
}
