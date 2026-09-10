package web

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/authority"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/housekeeping"
	"github.com/abandontech/abandonauth/src/api/internal/services/keyring"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers"
	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
	"github.com/abandontech/abandonauth/src/api/internal/services/sessions"
	"github.com/abandontech/abandonauth/src/api/internal/services/tokens"
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

// Dependencies are what a server is built around.
//
// The provider addresses and transport exist so a test can answer provider
// requests locally. A deployment leaves them empty and gets the real providers,
// which are constants in the provider clients and cannot be moved by a setting.
type Dependencies struct {
	Pool   *pgxpool.Pool
	Logger zerolog.Logger

	// Now is the clock. Only tests set it.
	Now func() time.Time

	// CredentialHasher stores and checks the secrets this service holds. Its
	// zero value is the work factor a deployment stores them at, so leaving it
	// out cannot make a stored secret cheaper to attack.
	CredentialHasher credentials.Hasher

	DiscordEndpoints providers.Endpoints
	GitHubEndpoints  providers.Endpoints
	GoogleEndpoints  providers.GoogleEndpoints

	ProviderTransport http.RoundTripper
}

// Server holds what the request handlers need. It is built once at start-up and
// is read-only afterwards, so handlers can run concurrently without locking.
type Server struct {
	config config.Config
	logger zerolog.Logger
	pool   *pgxpool.Pool
	now    func() time.Time

	// credentialHasher is the one the services were built with, so a handler
	// that stores a secret itself stores it at the same work factor.
	credentialHasher credentials.Hasher

	accounts     *accounts.Accounts
	applications *applications.Applications
	authority    *authority.Authority
	sessions     *sessions.Store
	logins       *oauth.Store
	codes        *oauth.ExchangeCodes
	limiter      *ratelimit.Limiter
	signer       *tokens.Signer

	discord *providers.Discord
	github  *providers.GitHub
	google  *providers.Google
}

// NewServer builds the service from its validated configuration.
//
// Everything that can fail does so here rather than on a request: a key that
// cannot be derived or a cipher that cannot be prepared means the service
// cannot answer safely, so it does not start.
func NewServer(configuration config.Config, dependencies Dependencies) (*Server, error) {
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}

	keys, err := keyring.New(configuration.SigningSecret.Reveal())
	if err != nil {
		return nil, err
	}

	signer, err := tokens.NewSigner(tokens.Options{
		Issuer:                configuration.API.String(),
		InternalApplicationID: configuration.InternalApplicationID,
		Keys:                  keys,
		Now:                   now,
	})
	if err != nil {
		return nil, err
	}

	logins, err := oauth.NewStore(dependencies.Pool, keys.VerifierEncryption())
	if err != nil {
		return nil, err
	}

	codes, err := oauth.NewExchangeCodes(dependencies.Pool, configuration.ExchangeCodeLifetime)
	if err != nil {
		return nil, err
	}

	browserSessions, err := sessions.NewStore(dependencies.Pool, sessions.Options{
		Lifetime: configuration.BrowserSessionLifetime,
		Now:      now,
	})
	if err != nil {
		return nil, err
	}

	limiter, err := ratelimit.New(dependencies.Pool, ratelimit.Options{
		Key: keys.RateLimitPseudonym(),
		Now: now,
	})
	if err != nil {
		return nil, err
	}

	return &Server{
		config:           configuration,
		logger:           dependencies.Logger,
		pool:             dependencies.Pool,
		now:              now,
		credentialHasher: dependencies.CredentialHasher,
		accounts:         accounts.New(dependencies.Pool),
		applications:     applications.New(dependencies.Pool, dependencies.CredentialHasher),
		authority:        authority.New(dependencies.Pool),
		sessions:         browserSessions,
		logins:           logins,
		codes:            codes,
		limiter:          limiter,
		signer:           signer,
		discord: providers.NewDiscord(
			configuration.Discord, dependencies.DiscordEndpoints, dependencies.ProviderTransport,
		),
		github: providers.NewGitHub(
			configuration.GitHub, dependencies.GitHubEndpoints, dependencies.ProviderTransport,
		),
		google: providers.NewGoogle(
			configuration.Google, dependencies.GoogleEndpoints, dependencies.ProviderTransport, now,
		),
	}, nil
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
			mux.Handle(route.Method+" "+route.Pattern, recordRoute(handler))
		}
	}

	mux.Handle("/", unmatchedRequests())

	return s.surround(mux)
}

// surround wraps the router in the concerns every request shares, outermost
// first: a panic must not escape, every answer carries its request identifier
// and is logged, a target this service does not spell is refused before
// anything can turn it into one that is, and only then is a browser told what
// it may do.
func (s *Server) surround(handler http.Handler) http.Handler {
	return s.recoverPanics(s.identifyRequest(s.logRequest(onlyCanonicalTargets(s.answerCORS(handler)))))
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

// ExpiredRecordSweeps names every kind of short-lived record this service
// stores, and how each is removed once it has expired.
//
// The services are built here, so this is where the whole set is known.
func (s *Server) ExpiredRecordSweeps() []housekeeping.Sweep {
	return []housekeeping.Sweep{
		{Records: "abandoned logins", Forget: s.logins.Forget},
		{Records: "one-time codes", Forget: s.codes.Forget},
		{Records: "browser sessions", Forget: s.sessions.Forget},
		{Records: "withdrawn tokens", Forget: s.authority.Forget},
		{Records: "rate limit windows", Forget: s.limiter.Forget},
	}
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
