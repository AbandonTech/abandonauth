package web

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// Deadlines the listener imposes on every connection. A client that opens a
// connection and then stalls must not be able to hold a worker indefinitely, so
// each phase of a request has its own limit rather than relying on one overall
// timeout that a slow body can evade.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 90 * time.Second

	// ShutdownGracePeriod bounds how long a stop waits for requests that are
	// already in flight. Beyond it the process exits and the reverse proxy
	// retries elsewhere.
	ShutdownGracePeriod = 20 * time.Second
)

// Server holds what the request handlers need. It is built once at start-up and
// is read-only afterwards, so handlers can run concurrently without locking.
type Server struct {
	config config.Config
	logger zerolog.Logger
	pool   *pgxpool.Pool
}

// NewServer builds the service from its validated configuration.
func NewServer(configuration config.Config, logger zerolog.Logger, pool *pgxpool.Pool) *Server {
	return &Server{config: configuration, logger: logger, pool: pool}
}

// Handler returns the routed HTTP handler.
//
// It registers the routes this build declares and has a handler for, so no URL
// is served that the route table does not name.
//
// A declared route with no handler is reported by MissingHandlers instead of
// failing here, so a test can drive the endpoints that exist while the rest are
// written. Start-up refuses to serve with any gap.
func (s *Server) Handler() http.Handler {
	handlers := s.handlers()
	mux := http.NewServeMux()

	for _, route := range Routes() {
		if handler, defined := handlers[route.Name]; defined {
			mux.Handle(route.Method+" "+route.Pattern, handler)
		}
	}

	mux.Handle("/", unmatchedRequests())

	return mux
}

// unmatchedRequests answers a request no route claimed.
//
// A URL this service does not serve gets 404. A URL it serves under a different
// method gets 405. Both use the service's own failure shape, not the router's
// plain text, so a client can parse every response it can provoke.
func unmatchedRequests() http.Handler {
	knownPaths := http.NewServeMux()
	registered := make(map[string]bool)

	for _, route := range Routes() {
		if registered[route.Pattern] {
			continue
		}

		registered[route.Pattern] = true

		knownPaths.Handle(route.Pattern, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			response.MethodNotAllowed(writer)
		}))
	}

	knownPaths.Handle("/", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		response.NotFound(writer)
	}))

	return knownPaths
}

// MissingHandlers names the routes this build declares but cannot answer.
//
// A deployment refuses to start while it is non-empty: a declared route with no
// handler would answer with a surprise rather than with its contract.
func (s *Server) MissingHandlers() []RouteName {
	handlers := s.handlers()

	var missing []RouteName

	for _, route := range Routes() {
		if _, defined := handlers[route.Name]; !defined {
			missing = append(missing, route.Name)
		}
	}

	return missing
}

// NewHTTPServer wraps a handler in a listener configured with the service's
// connection deadlines.
func NewHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}
