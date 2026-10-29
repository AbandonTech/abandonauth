package urlpolicy

import (
	"errors"
	"net/url"
	"strings"
)

// Reasons an origin is refused.
var (
	ErrOriginNotAnOrigin = errors.New("value is not an origin: it must be a scheme, host and optional port only")
	ErrOriginInsecure    = errors.New("origin must use https outside the loopback interface")
)

// TransportPolicy says whether an origin may be reached without TLS.
type TransportPolicy int

const (
	// RequireSecureTransport accepts https origins only.
	RequireSecureTransport TransportPolicy = iota
	// AllowLoopbackWithoutTransportSecurity additionally accepts http origins on
	// the loopback interface, which is how the site and the API run locally.
	AllowLoopbackWithoutTransportSecurity
)

// Origin is a web origin in the form browsers send it: scheme, host, and a port
// only when it is not the scheme's default.
//
// It is compared, never concatenated. Cookie-authenticated state changes are
// allowed on an exact origin match, so a value that merely contains or starts
// with the site origin must not be treated as equal to it.
type Origin struct {
	scheme string
	host   string
	port   string
}

// ParseOrigin validates and canonicalises an origin.
func ParseOrigin(raw string, policy TransportPolicy) (Origin, error) {
	if raw == "" {
		return Origin{}, ErrEmpty
	}

	if strings.TrimSpace(raw) != raw {
		return Origin{}, ErrOriginNotAnOrigin
	}

	if hasControlCharacter(raw) {
		return Origin{}, ErrControlCharacter
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return Origin{}, ErrMalformed
	}

	if parsed.Scheme == "" {
		return Origin{}, ErrNotAbsolute
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return Origin{}, ErrUnsupportedScheme
	}

	if parsed.Host == "" {
		return Origin{}, ErrNotAbsolute
	}

	if parsed.User != nil {
		return Origin{}, ErrUserInfo
	}

	// An origin carries no path, query or fragment. Accepting them would make
	// two spellings of the same origin compare unequal.
	if parsed.Path != "" && parsed.Path != "/" {
		return Origin{}, ErrOriginNotAnOrigin
	}

	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return Origin{}, ErrOriginNotAnOrigin
	}

	port := parsed.Port()
	if port != "" && !isValidPort(port) {
		return Origin{}, ErrInvalidPort
	}

	if scheme == "http" {
		if policy != AllowLoopbackWithoutTransportSecurity || !isLoopbackHost(parsed.Hostname()) {
			return Origin{}, ErrOriginInsecure
		}
	}

	return Origin{
		scheme: scheme,
		host:   strings.ToLower(parsed.Hostname()),
		port:   canonicalPort(scheme, port),
	}, nil
}

// String returns the origin as a browser would send it.
func (o Origin) String() string {
	if o.scheme == "" || o.host == "" {
		return ""
	}

	host := o.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	if o.port == "" {
		return o.scheme + "://" + host
	}

	return o.scheme + "://" + host + ":" + o.port
}

// Hostname returns the host without brackets or port.
func (o Origin) Hostname() string {
	return o.host
}

// Scheme returns the origin's scheme.
func (o Origin) Scheme() string {
	return o.scheme
}

// IsLoopback reports whether the origin can only be reached from the machine it
// runs on. Cookies for such an origin cannot carry the Secure attribute or the
// __Host- prefix, because local development does not use TLS.
func (o Origin) IsLoopback() bool {
	return o.host != "" && isLoopbackHost(o.host)
}

// MatchesHeader reports whether an Origin request header names this origin.
//
// Browsers send the serialised origin with no trailing slash, so a value with a
// path, query, fragment or credentials is not a browser origin and never
// matches. The literal "null", which browsers send for opaque origins such as
// sandboxed frames and local files, never matches either.
func (o Origin) MatchesHeader(value string) bool {
	if o.scheme == "" || o.host == "" || value == "" {
		return false
	}

	if strings.TrimSpace(value) != value || hasControlCharacter(value) {
		return false
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.User != nil || parsed.Host == "" {
		return false
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != o.scheme {
		return false
	}

	port := parsed.Port()
	if port != "" && !isValidPort(port) {
		return false
	}

	return strings.ToLower(parsed.Hostname()) == o.host && canonicalPort(scheme, port) == o.port
}

// canonicalPort drops a port that is the scheme's default, so that
// https://host and https://host:443 are one origin.
func canonicalPort(scheme, port string) string {
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return ""
	}

	return port
}
