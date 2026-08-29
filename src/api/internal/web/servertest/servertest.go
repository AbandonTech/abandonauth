// Package servertest starts the service and drives it over HTTP.
//
// Tests call endpoints, never services or queries directly, because a client
// cannot. The client keeps cookies between requests and returns redirects
// rather than following them, so a multi-request flow is written as a sequence
// of calls and a test can assert the Location header.
//
// Provider HTTP is answered by local test servers passed in at construction. No
// test reaches a real provider.
package servertest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/web"
)

// Service is a running AbandonAuth with its own database.
type Service struct {
	t *testing.T

	// Pool reads the database a request left behind. Tests assert resulting
	// state with it; they do not use it to set up state a request should create.
	Pool *pgxpool.Pool

	// Config is the configuration the service was built with, so a test can
	// name the site origin or the internal application without repeating them.
	Config config.Config

	// Logs holds everything the service wrote while the test ran, so a test can
	// assert that a credential never reached them.
	Logs *strings.Builder

	server *httptest.Server
	client *http.Client
}

// New starts the service against a database of its own.
func New(t *testing.T, options ...Option) *Service {
	t.Helper()

	pool := testdatabase.NewMigrated(t)

	settings := placeholderSettings()
	for _, option := range options {
		option(&settings)
	}

	configuration, err := config.Load(settings)
	if err != nil {
		t.Fatalf("the test configuration is not valid: %v", err)
	}

	logs := &strings.Builder{}
	logger := zerolog.New(logs).With().Timestamp().Logger()

	server := httptest.NewServer(web.NewServer(configuration, logger, pool).Handler())
	t.Cleanup(server.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("preparing the cookie jar: %v", err)
	}

	return &Service{
		t:      t,
		Pool:   pool,
		Config: configuration,
		Logs:   logs,
		server: server,
		client: &http.Client{
			Jar: jar,
			// Redirects are part of what these endpoints promise, so they are
			// returned to the test rather than followed silently.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Option adjusts the configuration the service runs with.
type Option func(*config.Settings)

// WithSetting overrides one setting for a test that needs the service
// configured differently.
func WithSetting(apply func(*config.Settings)) Option {
	return Option(apply)
}

// URL is the address of the running service.
func (s *Service) URL() string {
	return s.server.URL
}

// Response is what an endpoint answered.
type Response struct {
	t *testing.T

	Status  int
	Header  http.Header
	Cookies []*http.Cookie
	Body    []byte
}

// GET makes a request to a path on the service.
func (s *Service) GET(path string, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	return s.do(http.MethodGet, path, nil, prepare...)
}

// POSTJSON sends a JSON body to a path on the service.
func (s *Service) POSTJSON(path string, body any, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	return s.doJSON(http.MethodPost, path, body, prepare...)
}

// PATCHJSON sends a JSON body to a path on the service.
func (s *Service) PATCHJSON(path string, body any, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	return s.doJSON(http.MethodPatch, path, body, prepare...)
}

// DELETE removes the thing a path names.
func (s *Service) DELETE(path string, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	return s.do(http.MethodDelete, path, nil, prepare...)
}

// POSTRaw sends a body exactly as given, for the tests that send something no
// encoder would produce.
func (s *Service) POSTRaw(path, body string, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	return s.do(http.MethodPost, path, strings.NewReader(body), prepare...)
}

func (s *Service) doJSON(method, path string, body any, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		s.t.Fatalf("encoding the request body: %v", err)
	}

	withContentType := append([]func(*http.Request){func(request *http.Request) {
		request.Header.Set("Content-Type", "application/json")
	}}, prepare...)

	return s.do(method, path, bytes.NewReader(encoded), withContentType...)
}

func (s *Service) do(method, path string, body io.Reader, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	request, err := http.NewRequestWithContext(s.t.Context(), method, s.server.URL+path, body)
	if err != nil {
		s.t.Fatalf("building the request: %v", err)
	}

	for _, adjust := range prepare {
		adjust(request)
	}

	response, err := s.client.Do(request)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()

	received, err := io.ReadAll(response.Body)
	if err != nil {
		s.t.Fatalf("reading the response to %s %s: %v", method, path, err)
	}

	return &Response{
		t:       s.t,
		Status:  response.StatusCode,
		Header:  response.Header,
		Cookies: response.Cookies(),
		Body:    received,
	}
}

// Bearer sends a request with an access token.
func Bearer(token string) func(*http.Request) {
	return func(request *http.Request) {
		request.Header.Set("Authorization", "Bearer "+token)
	}
}

// Header sends a request with one header set.
func Header(name, value string) func(*http.Request) {
	return func(request *http.Request) {
		request.Header.Set(name, value)
	}
}

// ExpectStatus fails the test unless the response had the given status.
func (r *Response) ExpectStatus(want int) *Response {
	r.t.Helper()

	if r.Status != want {
		r.t.Fatalf("status = %d, want %d (body: %s)", r.Status, want, r.Body)
	}

	return r
}

// ExpectDetail fails the test unless the response is a failure carrying the
// given explanation.
func (r *Response) ExpectDetail(want string) *Response {
	r.t.Helper()

	var body struct {
		Detail string `json:"detail"`
	}

	r.DecodeInto(&body)

	if body.Detail != want {
		r.t.Errorf("detail = %q, want %q", body.Detail, want)
	}

	return r
}

// ExpectRedirectTo fails the test unless the response sends a browser to the
// given location.
func (r *Response) ExpectRedirectTo(want string) *Response {
	r.t.Helper()

	if got := r.Header.Get("Location"); got != want {
		r.t.Errorf("Location = %q, want %q", got, want)
	}

	return r
}

// Cookie returns the cookie the response set, or nil.
func (r *Response) Cookie(name string) *http.Cookie {
	r.t.Helper()

	for _, cookie := range r.Cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}

// DecodeInto reads the response body as JSON.
func (r *Response) DecodeInto(target any) *Response {
	r.t.Helper()

	if err := json.Unmarshal(r.Body, target); err != nil {
		r.t.Fatalf("the response body is not the expected shape: %v (body: %s)", err, r.Body)
	}

	return r
}
