// Package servertest starts the service and drives it over HTTP.
//
// Tests call endpoints, never services or queries directly, because a client
// cannot. A request helper is given the path below the API's route root, which
// is composed in one place so that no journey can be written against a spelling
// this service does not serve.
//
// The client keeps cookies between requests and returns redirects rather than
// following them, so a multi-request flow is written as a sequence of calls and
// a test can assert the Location header.
//
// Provider HTTP is answered by local test servers passed in at construction. No
// test reaches a real provider.
package servertest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/housekeeping"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
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

	// Site is the developer application the service was configured to treat as
	// its own.
	Site Site

	// Providers answers the identity providers, so a sign-in completes without
	// leaving the machine.
	Providers *providertest.Providers

	// Logs holds everything the service wrote while the test ran, so a test can
	// assert that a credential never reached them.
	Logs *RecordedLogs

	service *web.Server
	server  *httptest.Server
	client  *http.Client
}

// New starts the service against a database of its own.
func New(t *testing.T, choices ...Option) *Service {
	t.Helper()

	pool := testdatabase.NewMigrated(t)
	site := registerSite(t, pool)

	chosen := options{settings: placeholderSettings()}
	chosen.settings.InternalApplicationID = site.ApplicationID.String()

	for _, choose := range choices {
		choose(&chosen)
	}

	configuration, err := config.Load(chosen.settings)
	if err != nil {
		t.Fatalf("the test configuration is not valid: %v", err)
	}

	chosen.providers.GoogleClientID = chosen.settings.GoogleClientID

	identityProviders := providertest.New(t, chosen.providers)

	dependencies := chosen.dependencies

	logs := &RecordedLogs{}
	logger := zerolog.New(logs).With().Timestamp().Logger()

	dependencies.Pool = pool
	dependencies.Logger = logger

	if dependencies.ProviderTransport == nil {
		dependencies.ProviderTransport = identityProviders.Transport()
	}

	service, err := web.NewServer(configuration, dependencies)
	if err != nil {
		t.Fatalf("building the service: %v", err)
	}

	server := httptest.NewServer(service.Handler())
	t.Cleanup(server.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("preparing the cookie jar: %v", err)
	}

	return &Service{
		t:         t,
		Pool:      pool,
		Config:    configuration,
		Site:      site,
		Providers: identityProviders,
		Logs:      logs,
		service:   service,
		server:    server,
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

// ExpiredRecordSweeps is how the running service removes each kind of
// short-lived record once it has expired. Nothing serves these over HTTP, so a
// test that drives them asks the service for them here.
func (s *Service) ExpiredRecordSweeps() []housekeeping.Sweep {
	return s.service.ExpiredRecordSweeps()
}

// SessionCookieName is the name of the cookie a signed-in browser carries.
func (s *Service) SessionCookieName() string { return s.service.SessionCookieName() }

// CSRFCookieName is the name of the cookie the site reads and echoes back.
func (s *Service) CSRFCookieName() string { return s.service.CSRFCookieName() }

// LoginCookieName is the name of the cookie that ties a login in progress to
// the browser that started it.
func (s *Service) LoginCookieName() string { return s.service.LoginCookieName() }

// options are what a test service is built from.
type options struct {
	settings     config.Settings
	dependencies web.Dependencies
	providers    providertest.Options
}

// WithProviderAnswering changes what the identity providers answer, so a test
// can describe an answer this service is required to refuse.
func WithProviderAnswering(apply func(*providertest.Options)) Option {
	return func(chosen *options) { apply(&chosen.providers) }
}

// Option adjusts how the service under test is built.
type Option func(*options)

// WithSetting overrides one setting for a test that needs the service
// configured differently.
func WithSetting(apply func(*config.Settings)) Option {
	return func(chosen *options) { apply(&chosen.settings) }
}

// WithDependencies points the service at test doubles: local servers standing
// in for the providers, and a clock the test controls.
func WithDependencies(apply func(*web.Dependencies)) Option {
	return func(chosen *options) { apply(&chosen.dependencies) }
}

// WithSteadyClock holds the service's clock still for the whole test.
//
// A request budget is counted in a window fixed to the clock, so a test that
// spends one takes as long as the work it drives: on a slow machine it can
// straddle a window boundary, and the count it was building is then measured
// against a fresh window. Holding the clock makes such a test describe the
// budget rather than how long the machine took.
//
// Only the service's own clock stops. Expiry recorded by the database is
// measured by the database and continues.
func WithSteadyClock() Option {
	held := time.Now().UTC()

	return WithDependencies(func(dependencies *web.Dependencies) {
		dependencies.Now = func() time.Time { return held }
	})
}

// URL is the address of the running service.
func (s *Service) URL() string {
	return s.server.URL
}

// EndpointURL is the whole address of an endpoint, given the path below the
// API's route root. Every request helper composes the root here and nowhere
// else, so a test cannot reach an endpoint by a spelling the service does not
// serve, and a test that has to build a request itself gets the same address.
func (s *Service) EndpointURL(endpointPath string) string {
	return s.server.URL + web.APIRoot + endpointPath
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

// OPTIONS asks what a browser may do with a path.
func (s *Service) OPTIONS(path string, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	return s.do(http.MethodOptions, path, nil, prepare...)
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

// AtExactTarget sends a request to a target written out in full, without the
// API's route root the endpoint helpers add.
//
// It is for the tests that describe what this service does with a target it
// does not serve. An endpoint journey uses the helpers above, so that no test
// can exercise an address by writing it a second way.
func (s *Service) AtExactTarget(method, target string, prepare ...func(*http.Request)) *Response {
	s.t.Helper()

	return s.send(method, s.server.URL+target, target, nil, prepare...)
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

	return s.send(method, s.EndpointURL(path), path, body, prepare...)
}

func (s *Service) send(
	method, address, describedAs string, body io.Reader, prepare ...func(*http.Request),
) *Response {
	s.t.Helper()

	request, err := http.NewRequestWithContext(s.t.Context(), method, address, body)
	if err != nil {
		s.t.Fatalf("building the request: %v", err)
	}

	for _, adjust := range prepare {
		adjust(request)
	}

	response, err := s.client.Do(request)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, describedAs, err)
	}
	defer response.Body.Close()

	received, err := io.ReadAll(response.Body)
	if err != nil {
		s.t.Fatalf("reading the response to %s %s: %v", method, describedAs, err)
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

// ExpectRejectedInput fails the test unless the request was refused for the
// input at the given location, such as ("query", "callback_uri").
func (r *Response) ExpectRejectedInput(location ...any) *Response {
	r.t.Helper()

	r.ExpectStatus(http.StatusUnprocessableEntity)

	var body struct {
		Detail []struct {
			Location []any  `json:"loc"`
			Message  string `json:"msg"`
			Type     string `json:"type"`
		} `json:"detail"`
	}

	r.DecodeInto(&body)

	wanted := describeLocation(location)

	for _, failure := range body.Detail {
		if describeLocation(failure.Location) == wanted {
			return r
		}
	}

	r.t.Errorf("no input at %s was refused (body: %s)", wanted, r.Body)

	return r
}

// describeLocation names where in a request an input was found, in the order
// the service reports it.
func describeLocation(parts []any) string {
	named := make([]string, 0, len(parts))
	for _, part := range parts {
		named = append(named, fmt.Sprintf("%v", part))
	}

	return strings.Join(named, "/")
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
