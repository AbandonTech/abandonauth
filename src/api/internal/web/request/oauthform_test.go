package request

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

var recognizedForTest = []string{"client_id", "token"}

func queryRequest(rawQuery string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/api/oauth/authorize", nil)
	request.URL.RawQuery = rawQuery

	return request
}

func bodyRequest(body string, contentTypes ...string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/oauth/token", strings.NewReader(body))
	for _, contentType := range contentTypes {
		request.Header.Add("Content-Type", contentType)
	}

	return request
}

// Recognized parameters are decoded and kept with every occurrence; anything
// else is dropped.
func TestOAuthParametersKeepOnlyRecognizedNames(t *testing.T) {
	t.Parallel()

	parsed, err := OAuthQuery(queryRequest("client_id=a%2Bb+c&other=x&token=1&token=2&flag"), recognizedForTest)
	if err != nil {
		t.Fatalf("a well-formed query was refused: %v", err)
	}

	if value, count := parsed.Lookup("client_id"); count != 1 || value != "a+b c" {
		t.Errorf("client_id = %q (%d)", value, count)
	}

	if _, count := parsed.Lookup("token"); count != 2 || !slices.Equal(parsed["token"], []string{"1", "2"}) {
		t.Errorf("token occurrences = %v", parsed["token"])
	}

	if parsed.Has("other") || parsed.Has("flag") {
		t.Error("an unrecognized name was kept")
	}

	if _, count := parsed.Lookup("absent"); count != 0 {
		t.Error("an absent name was found")
	}

	empty, err := OAuthQuery(queryRequest(""), recognizedForTest)
	if err != nil || len(empty) != 0 {
		t.Error("an empty query was not an empty set")
	}
}

// Any field two readers could read differently refuses the whole source.
func TestOAuthParametersRefuseAmbiguousSources(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{
		"a bare percent sign":        "client_id=%",
		"a truncated escape":         "client_id=%4",
		"a non-hexadecimal escape":   "client_id=%4G",
		"a semicolon":                "client_id=a;token=b",
		"an encoded name":            "client%5Fid=a",
		"a differently cased name":   "Client_Id=a",
		"an empty name":              "=a",
		"an empty field":             "client_id=a&&token=b",
		"a trailing separator":       "client_id=a&",
		"a name over 64 bytes":       strings.Repeat("n", 65) + "=a",
		"a name with a space":        "client id=a",
		"a raw space":                "client_id=a b",
		"a raw non-ASCII byte":       "client_id=\xc3\xa9",
		"invalid UTF-8":              "client_id=%C3",
		"a NUL":                      "client_id=%00",
		"a line feed":                "client_id=%0A",
		"a tab":                      "client_id=%09",
		"a delete character":         "client_id=%7F",
		"a C1 control":               "client_id=%C2%85",
		"more than 32 fields":        strings.Repeat("x=1&", 32) + "x=1",
		"more than 8,192 bytes":      "x=" + strings.Repeat("a", 8191),
		"an unrecognized bad escape": "client_id=a&other=%zz",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsed, err := OAuthQuery(queryRequest(query), recognizedForTest)
			if !errors.Is(err, ErrOAuthParameters) || parsed != nil {
				t.Errorf("an ambiguous query was read: %v %v", parsed, err)
			}
		})
	}

	exact := "x=" + strings.Repeat("a", 8190)
	if _, err := OAuthQuery(queryRequest(exact), recognizedForTest); err != nil {
		t.Errorf("a query of exactly 8,192 bytes was refused: %v", err)
	}

	if _, err := OAuthQuery(queryRequest(strings.Repeat("x=1&", 31)+"x=1"), recognizedForTest); err != nil {
		t.Errorf("a query of exactly 32 fields was refused: %v", err)
	}

	if _, err := OAuthQuery(queryRequest(strings.Repeat("n", 64)+"=a"), recognizedForTest); err != nil {
		t.Errorf("a 64-byte name was refused: %v", err)
	}
}

// A form is read only from a body declared exactly once as an unparameterized
// form, and never from the query.
func TestOAuthFormReadsOnlyTheDeclaredBody(t *testing.T) {
	t.Parallel()

	parsed, err := OAuthForm(bodyRequest("token=a", "Application/X-WWW-Form-Urlencoded"), recognizedForTest)
	if err != nil || !parsed.Has("token") {
		t.Fatalf("a form was not read: %v", err)
	}

	withQuery := bodyRequest("", OAuthFormContentType)
	withQuery.URL.RawQuery = "token=a"

	parsed, err = OAuthForm(withQuery, recognizedForTest)
	if err != nil || parsed.Has("token") {
		t.Error("the query was read as part of a form")
	}

	noBody := bodyRequest("", OAuthFormContentType)
	noBody.Body = nil

	if parsed, err := OAuthForm(noBody, recognizedForTest); err != nil || len(parsed) != 0 {
		t.Error("a request without a body was not an empty form")
	}

	for name, contentTypes := range map[string][]string{
		"none":             nil,
		"JSON":             {"application/json"},
		"a charset":        {"application/x-www-form-urlencoded; charset=utf-8"},
		"two declarations": {OAuthFormContentType, OAuthFormContentType},
		"a list":           {OAuthFormContentType + ", text/plain"},
		"surrounding text": {" " + OAuthFormContentType},
	} {
		if _, err := OAuthForm(bodyRequest("token=a", contentTypes...), recognizedForTest); !errors.Is(err, ErrOAuthContentType) {
			t.Errorf("a body declared with %s was read: %v", name, err)
		}
	}

	if _, err := OAuthForm(bodyRequest(strings.Repeat("a", MaxOAuthFormBytes+1), OAuthFormContentType),
		recognizedForTest); !errors.Is(err, ErrOAuthParameters) {
		t.Errorf("an oversized body was read: %v", err)
	}

	if _, err := OAuthForm(bodyRequest(strings.Repeat("x=1&", 16)+"x=1", OAuthFormContentType),
		recognizedForTest); !errors.Is(err, ErrOAuthParameters) {
		t.Errorf("a body of 17 fields was read: %v", err)
	}

	failing := bodyRequest("", OAuthFormContentType)
	failing.Body = failingBody{}

	if _, err := OAuthForm(failing, recognizedForTest); !errors.Is(err, ErrOAuthParameters) {
		t.Errorf("a body that could not be read was accepted: %v", err)
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("the connection failed") }

func (failingBody) Close() error { return nil }
