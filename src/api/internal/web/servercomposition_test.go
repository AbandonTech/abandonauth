package web

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// composed is a server with nothing behind it. The concerns every request
// passes through do not read the database, so they can be driven without one.
func composed() *Server {
	return &Server{now: time.Now}
}

// A route this build declares but cannot answer would reply with a surprise
// rather than with its contract, so start-up refuses to serve with any gap.
func TestEveryDeclaredRouteHasAHandler(t *testing.T) {
	t.Parallel()

	if missing := composed().MissingHandlers(); len(missing) > 0 {
		t.Errorf("declared routes with no handler: %v", missing)
	}
}

// The route table is the only place a URL is written. A handler bound to a name
// the table does not carry would never be reached, and would hide the fact that
// the endpoint it was written for is not served.
func TestNoHandlerIsBoundToARouteThatIsNotDeclared(t *testing.T) {
	t.Parallel()

	declared := make([]RouteName, 0, len(Routes()))
	for _, route := range Routes() {
		declared = append(declared, route.Name)
	}

	for name := range composed().handlers() {
		if !slices.Contains(declared, name) {
			t.Errorf("handler %q is bound to no declared route", name)
		}
	}
}

// A defect in one handler ends that request, not the process, and the client
// gets something it can parse rather than a dropped connection.
func TestAPanicIsAnsweredAndDoesNotEscape(t *testing.T) {
	t.Parallel()

	const secret = "placeholder-credential-in-scope"

	service := composed()
	handler := service.surround(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("a handler failed holding " + secret)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/me", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}

	if body := recorder.Body.String(); !strings.Contains(body, `"detail"`) {
		t.Errorf("body = %q, want the service's own failure shape", body)
	}

	// Whatever was in scope when a handler failed can include a credential, so
	// the recovered value is written to the log and never to the response.
	if strings.Contains(recorder.Body.String(), secret) {
		t.Error("what the handler was holding was returned to the client")
	}
}

// Recovery is outermost and identification is inside it, so the request that
// provoked a defect is the one a report can be traced by.
func TestAnAnswerCarriesAnIdentifierEvenWhenTheHandlerFails(t *testing.T) {
	t.Parallel()

	service := composed()
	handler := service.surround(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("a handler failed")
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/me", nil))

	if recorder.Header().Get(RequestIDHeader) == "" {
		t.Error("a failed request cannot be found in the log")
	}
}

// A client that opens a connection and then stalls must not hold a worker
// indefinitely, so each phase of a request is bounded rather than relying on one
// overall limit a slow body could evade.
func TestEveryPhaseOfAConnectionIsBounded(t *testing.T) {
	t.Parallel()

	listener := NewHTTPServer("127.0.0.1:8000", http.NotFoundHandler())

	bounded := map[string]time.Duration{
		"ReadHeaderTimeout": listener.ReadHeaderTimeout,
		"ReadTimeout":       listener.ReadTimeout,
		"WriteTimeout":      listener.WriteTimeout,
		"IdleTimeout":       listener.IdleTimeout,
	}

	for phase, limit := range bounded {
		if limit <= 0 {
			t.Errorf("%s is unbounded", phase)
		}
	}

	if ShutdownGracePeriod <= 0 {
		t.Error("a stop would wait for requests in flight forever")
	}
}
