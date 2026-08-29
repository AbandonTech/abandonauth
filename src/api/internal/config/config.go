// Package config turns the settings supplied on the command line or in the
// environment into a validated, immutable description of how the service runs.
//
// Validation happens once at start-up and fails the process, so no request path
// has to cope with a setting that is missing, malformed, or unsafe. Errors name
// the setting that is wrong and never repeat its value.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

// Names of the settings, used in error messages so an operator can find the
// environment variable to correct.
const (
	settingDatabaseURL           = "DATABASE_URL"
	settingSigningSecret         = "JWT_SECRET"
	settingSigningAlgorithm      = "JWT_HASHING_ALGO"
	settingExchangeCodeSeconds   = "JWT_EXPIRES_IN_SECONDS_SHORT_LIVED"
	settingBrowserSessionSeconds = "JWT_EXPIRES_IN_SECONDS_LONG_LIVED"
	settingInternalApplicationID = "ABANDON_AUTH_DEVELOPER_APP_ID"
	settingSiteURL               = "ABANDON_AUTH_SITE_URL"
	settingAPIURL                = "ABANDON_AUTH_URL"
	settingDiscordClientID       = "DISCORD_CLIENT_ID"
	settingDiscordClientSecret   = "DISCORD_CLIENT_SECRET"
	settingDiscordCallback       = "ABANDON_AUTH_DISCORD_CALLBACK"
	settingGitHubClientID        = "GITHUB_CLIENT_ID"
	settingGitHubClientSecret    = "GITHUB_CLIENT_SECRET"
	settingGitHubCallback        = "ABANDON_AUTH_GITHUB_CALLBACK"
	settingGoogleClientID        = "GOOGLE_CLIENT_ID"
	settingGoogleClientSecret    = "GOOGLE_CLIENT_SECRET"
	settingGoogleCallback        = "GOOGLE_CALLBACK"
	settingDebug                 = "DEBUG"
	settingTrustedProxyCIDRs     = "TRUSTED_PROXY_CIDRS"
	settingBindAddress           = "BIND_ADDRESS"
)

// Limits the service places on configured lifetimes.
const (
	// MaxExchangeCodeLifetime bounds how long a one-time code handed to an
	// application stays usable. It is short because the code travels through the
	// user's browser.
	MaxExchangeCodeLifetime = 120 * time.Second
	// MaxBrowserSessionLifetime bounds how long a browser stays signed in
	// without proving itself to a provider again.
	MaxBrowserSessionLifetime = 30 * 24 * time.Hour
	// MinSigningSecretBytes is the shortest root signing secret accepted. The
	// per-purpose HS512 keys are derived from it, so it must carry at least as
	// much entropy as the keys it produces.
	MinSigningSecretBytes = 64
	// SigningAlgorithm is the only accepted value for the signing algorithm
	// setting. It is checked rather than obeyed so that a token can never select
	// its own verification algorithm.
	SigningAlgorithm = "HS512"
	// DefaultBindAddress serves every interface on the port the deployment's
	// reverse proxy forwards to.
	DefaultBindAddress = "0.0.0.0:8000"
	// DefaultTrustedProxyCIDRs trusts forwarding headers only from the local
	// machine, which is where a sidecar or host-network proxy runs.
	DefaultTrustedProxyCIDRs = "127.0.0.1/32,::1/128"
)

// Settings are the raw values collected from the command line and environment.
// Every field is a string, number or bool so that parsing and validation live in
// one place and can be tested without a command line.
type Settings struct {
	BindAddress string
	Debug       bool
	Verbose     bool
	Pretty      bool

	// DevelopmentBuild reports whether the binary was compiled with the
	// development tooling. Together with Debug it decides whether plain HTTP on
	// the loopback interface is acceptable.
	DevelopmentBuild bool

	DatabaseURL string

	SigningSecret         string
	SigningAlgorithm      string
	ExchangeCodeSeconds   int
	BrowserSessionSeconds int

	InternalApplicationID string

	SiteURL string
	APIURL  string

	DiscordClientID     string
	DiscordClientSecret string
	DiscordCallback     string

	GitHubClientID     string
	GitHubClientSecret string
	GitHubCallback     string

	GoogleClientID     string
	GoogleClientSecret string
	GoogleCallback     string

	TrustedProxyCIDRs string
}

// Provider is the registration AbandonAuth holds with one OAuth provider.
type Provider struct {
	ClientID     string
	ClientSecret Secret

	// Callback is the redirect URI registered with the provider. It is sent in
	// the authorization request and again in the token request, and the provider
	// rejects the exchange if the two differ.
	Callback *url.URL
}

// Config is the validated configuration of a running service. It is created
// once at start-up and never modified.
type Config struct {
	BindAddress string
	Debug       bool
	Verbose     bool
	Pretty      bool

	developmentBuild bool

	DatabaseURL Secret

	SigningSecret          Secret
	ExchangeCodeLifetime   time.Duration
	BrowserSessionLifetime time.Duration

	// InternalApplicationID is the developer application that represents the
	// AbandonAuth site itself. A browser session is only created for a login
	// that was started by this application.
	InternalApplicationID uuid.UUID

	Site urlpolicy.Origin
	API  urlpolicy.Origin

	Discord Provider
	GitHub  Provider
	Google  Provider

	TrustedProxies []netip.Prefix
}

// Load validates settings and returns the configuration to run with.
func Load(settings Settings) (Config, error) {
	loaded := Config{
		BindAddress:      strings.TrimSpace(settings.BindAddress),
		Debug:            settings.Debug,
		Verbose:          settings.Verbose,
		Pretty:           settings.Pretty,
		developmentBuild: settings.DevelopmentBuild,
	}

	if loaded.BindAddress == "" {
		loaded.BindAddress = DefaultBindAddress
	}

	if err := validateBindAddress(loaded.BindAddress); err != nil {
		return Config{}, err
	}

	// Debug mode relaxes transport rules, so a binary that cannot serve the
	// development routes must not accept it either: it would only mislead.
	if settings.Debug && !settings.DevelopmentBuild {
		return Config{}, settingError(settingDebug, "this build does not support debug mode")
	}

	transport := urlpolicy.RequireSecureTransport
	if settings.DevelopmentBuild && settings.Debug {
		transport = urlpolicy.AllowLoopbackWithoutTransportSecurity
	}

	var err error

	if loaded.DatabaseURL, err = databaseURL(settings.DatabaseURL); err != nil {
		return Config{}, err
	}

	if loaded.SigningSecret, err = signingSecret(settings.SigningSecret); err != nil {
		return Config{}, err
	}

	if settings.SigningAlgorithm != SigningAlgorithm {
		return Config{}, settingError(settingSigningAlgorithm, "must be exactly "+SigningAlgorithm)
	}

	if loaded.ExchangeCodeLifetime, err = lifetime(
		settingExchangeCodeSeconds, settings.ExchangeCodeSeconds, MaxExchangeCodeLifetime,
	); err != nil {
		return Config{}, err
	}

	if loaded.BrowserSessionLifetime, err = lifetime(
		settingBrowserSessionSeconds, settings.BrowserSessionSeconds, MaxBrowserSessionLifetime,
	); err != nil {
		return Config{}, err
	}

	if loaded.InternalApplicationID, err = uuid.Parse(settings.InternalApplicationID); err != nil {
		return Config{}, settingError(settingInternalApplicationID, "must be a UUID")
	}

	if loaded.Site, err = origin(settingSiteURL, settings.SiteURL, transport); err != nil {
		return Config{}, err
	}

	if loaded.API, err = origin(settingAPIURL, settings.APIURL, transport); err != nil {
		return Config{}, err
	}

	if loaded.Discord, err = provider(
		settingDiscordClientID, settings.DiscordClientID,
		settingDiscordClientSecret, settings.DiscordClientSecret,
		settingDiscordCallback, settings.DiscordCallback,
	); err != nil {
		return Config{}, err
	}

	if loaded.GitHub, err = provider(
		settingGitHubClientID, settings.GitHubClientID,
		settingGitHubClientSecret, settings.GitHubClientSecret,
		settingGitHubCallback, settings.GitHubCallback,
	); err != nil {
		return Config{}, err
	}

	if loaded.Google, err = provider(
		settingGoogleClientID, settings.GoogleClientID,
		settingGoogleClientSecret, settings.GoogleClientSecret,
		settingGoogleCallback, settings.GoogleCallback,
	); err != nil {
		return Config{}, err
	}

	if loaded.TrustedProxies, err = trustedProxies(settings.TrustedProxyCIDRs); err != nil {
		return Config{}, err
	}

	return loaded, nil
}

// RequireSecureCookies reports whether cookies must carry the Secure attribute
// and the __Host- prefix. Loopback development runs without TLS, where such a
// cookie would never be sent back.
func (c Config) RequireSecureCookies() bool {
	return !c.Site.IsLoopback()
}

// PasswordSignInEnabled reports whether the password routes may serve requests.
//
// They exist to seed local accounts without contacting a provider, so they need
// a development build, debug mode, and a listener no other machine can reach.
func (c Config) PasswordSignInEnabled() bool {
	return c.developmentBuild && c.Debug && bindsToLoopbackOnly(c.BindAddress)
}

// DevelopmentBuild reports whether this binary carries the development tooling.
func (c Config) DevelopmentBuild() bool {
	return c.developmentBuild
}

func settingError(setting, reason string) error {
	return fmt.Errorf("%s: %s", setting, reason)
}

func validateBindAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return settingError(settingBindAddress, "must be host:port")
	}

	number, err := strconv.Atoi(port)
	if err != nil || number <= 0 || number > 65535 {
		return settingError(settingBindAddress, "port must be a number between 1 and 65535")
	}

	if host != "" && host != "localhost" {
		if _, err := netip.ParseAddr(host); err != nil {
			return settingError(settingBindAddress, "host must be an IP address, localhost, or empty")
		}
	}

	return nil
}

func bindsToLoopbackOnly(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}

	if host == "localhost" {
		return true
	}

	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	return parsed.IsLoopback()
}

func databaseURL(raw string) (Secret, error) {
	if strings.TrimSpace(raw) == "" {
		return Secret{}, settingError(settingDatabaseURL, "is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return Secret{}, settingError(settingDatabaseURL, "is not a valid URL")
	}

	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return Secret{}, settingError(settingDatabaseURL, "must use the postgres or postgresql scheme")
	}

	if parsed.Host == "" {
		return Secret{}, settingError(settingDatabaseURL, "must name a host")
	}

	return NewSecret(raw), nil
}

func signingSecret(raw string) (Secret, error) {
	if raw == "" {
		return Secret{}, settingError(settingSigningSecret, "is required")
	}

	if len(raw) < MinSigningSecretBytes {
		return Secret{}, settingError(
			settingSigningSecret,
			fmt.Sprintf("must be at least %d bytes", MinSigningSecretBytes),
		)
	}

	return NewSecret(raw), nil
}

func lifetime(setting string, seconds int, maximum time.Duration) (time.Duration, error) {
	if seconds <= 0 {
		return 0, settingError(setting, "must be a positive number of seconds")
	}

	value := time.Duration(seconds) * time.Second
	if value > maximum {
		return 0, settingError(setting, fmt.Sprintf("must not exceed %d seconds", int(maximum.Seconds())))
	}

	return value, nil
}

func origin(setting, raw string, transport urlpolicy.TransportPolicy) (urlpolicy.Origin, error) {
	parsed, err := urlpolicy.ParseOrigin(raw, transport)
	if err != nil {
		return urlpolicy.Origin{}, settingError(setting, err.Error())
	}

	return parsed, nil
}

func provider(
	idSetting, id string,
	secretSetting, secret string,
	callbackSetting, callback string,
) (Provider, error) {
	if strings.TrimSpace(id) == "" {
		return Provider{}, settingError(idSetting, "is required")
	}

	if secret == "" {
		return Provider{}, settingError(secretSetting, "is required")
	}

	parsed, err := urlpolicy.ParseCallbackURI(callback)
	if err != nil {
		return Provider{}, settingError(callbackSetting, err.Error())
	}

	return Provider{ClientID: id, ClientSecret: NewSecret(secret), Callback: parsed}, nil
}

func trustedProxies(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		raw = DefaultTrustedProxyCIDRs
	}

	entries := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(entries))
	seen := make(map[string]bool, len(entries))

	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			return nil, settingError(settingTrustedProxyCIDRs, "contains an empty entry")
		}

		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return nil, settingError(settingTrustedProxyCIDRs, "entries must be CIDR prefixes such as 10.0.0.0/8")
		}

		// Masked so that 10.0.0.5/8 and 10.0.0.0/8 are recognised as the same
		// range and cannot both be listed.
		prefix = prefix.Masked()
		if seen[prefix.String()] {
			return nil, settingError(settingTrustedProxyCIDRs, "lists the same range twice")
		}

		seen[prefix.String()] = true

		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}
