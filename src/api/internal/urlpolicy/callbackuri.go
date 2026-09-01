// Package urlpolicy decides which URLs AbandonAuth is willing to send a browser
// to, and which origins may drive a cookie-authenticated request.
//
// Every rejection reason is a distinct error value so callers can react to it,
// but no error ever repeats the value it rejected: callback URIs and site
// origins can carry customer names, internal host names and, when someone
// misconfigures them, credentials.
package urlpolicy

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Reasons a URL is refused.
var (
	ErrEmpty             = errors.New("url is empty")
	ErrMalformed         = errors.New("url cannot be parsed")
	ErrNotAbsolute       = errors.New("url is not absolute")
	ErrUnsupportedScheme = errors.New("url scheme must be https, or http on the loopback interface")
	ErrInsecureTransport = errors.New("http is only allowed on the loopback interface")
	ErrMissingPort       = errors.New("loopback http url must state its port")
	ErrInvalidPort       = errors.New("url port is not a valid port number")
	ErrUserInfo          = errors.New("url must not carry credentials")
	ErrFragment          = errors.New("url must not carry a fragment")
	ErrControlCharacter  = errors.New("url contains a control character")
	ErrReservedQueryKey  = errors.New("url already uses a query key the login response needs")
)

// ResponseQueryKeys are the query keys AbandonAuth adds when it returns a
// browser to an application. A registered callback may not already use one,
// because the application would then receive two values under the same key and
// could read the attacker-supplied one.
var ResponseQueryKeys = []string{"code", "authentication"}

// Callback is a URL this service may return a browser to.
//
// It carries the exact spelling that was validated as well as the parsed form
// the transport rules were applied to. A browser is sent to the exact spelling:
// an application, and a provider, match a redirect against the string they were
// given, and a normalised rewrite of it is a different string.
type Callback struct {
	registered string
	parsed     *url.URL
}

// String returns the exact spelling that was registered and validated.
func (c Callback) String() string {
	return c.registered
}

// IsZero reports a callback that was never parsed.
func (c Callback) IsZero() bool {
	return c.parsed == nil
}

// URL returns the parsed form, whose scheme and host are lower cased so that
// host comparisons are case-insensitive. It is not what a browser is sent to.
func (c Callback) URL() *url.URL {
	target := *c.parsed

	return &target
}

// WithResponseParameter returns the callback with one query parameter added.
//
// The registered spelling is copied through byte for byte instead of being
// decoded and re-encoded: an application may depend on the order or the exact
// escaping of the parameters it registered, and re-encoding could change a
// signed value. Only the added pair is encoded, by the standard encoder.
func (c Callback) WithResponseParameter(key, value string) string {
	separator := "?"
	// A fragment is refused at parse time, so the first question mark can only
	// begin the query and anything after it is already part of one.
	if strings.Contains(c.registered, "?") {
		separator = "&"
	}

	return c.registered + separator + url.Values{key: []string{value}}.Encode()
}

// ParseCallbackURI validates a URL the service may redirect a browser to.
//
// The transport rules are applied to a copy whose scheme and host are lower
// cased, and the returned callback keeps the spelling it was given, because
// callbacks are matched by exact equality against the value that was registered.
func ParseCallbackURI(raw string) (Callback, error) {
	if raw == "" {
		return Callback{}, ErrEmpty
	}

	if strings.TrimSpace(raw) != raw {
		return Callback{}, ErrMalformed
	}

	if hasControlCharacter(raw) {
		return Callback{}, ErrControlCharacter
	}

	// url.Parse silently accepts a fragment, so check the raw text as well: a
	// fragment is never sent to the server and would make an exact match
	// meaningless.
	if strings.Contains(raw, "#") {
		return Callback{}, ErrFragment
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return Callback{}, ErrMalformed
	}

	if parsed.Scheme == "" {
		return Callback{}, ErrNotAbsolute
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return Callback{}, ErrUnsupportedScheme
	}

	if parsed.Host == "" {
		return Callback{}, ErrNotAbsolute
	}

	if parsed.User != nil {
		return Callback{}, ErrUserInfo
	}

	parsed.Host = strings.ToLower(parsed.Host)

	port := parsed.Port()
	if port != "" && !isValidPort(port) {
		return Callback{}, ErrInvalidPort
	}

	if parsed.Scheme == "http" {
		if !isLoopbackHost(parsed.Hostname()) {
			return Callback{}, ErrInsecureTransport
		}

		// Without a port the URL depends on the reader's default, and an
		// application on port 80 of a developer machine is not the one that
		// registered the callback.
		if port == "" {
			return Callback{}, ErrMissingPort
		}
	}

	if _, err := url.ParseQuery(parsed.RawQuery); err != nil {
		return Callback{}, ErrMalformed
	}

	return Callback{registered: raw, parsed: parsed}, nil
}

// ParseRegisteredCallbackURI validates a URL an application wants to register.
// It applies every rule of ParseCallbackURI and additionally refuses URLs that
// already use one of ResponseQueryKeys.
func ParseRegisteredCallbackURI(raw string) (Callback, error) {
	callback, err := ParseCallbackURI(raw)
	if err != nil {
		return Callback{}, err
	}

	query, err := url.ParseQuery(callback.parsed.RawQuery)
	if err != nil {
		return Callback{}, ErrMalformed
	}

	for key := range query {
		for _, reserved := range ResponseQueryKeys {
			if strings.EqualFold(key, reserved) {
				return Callback{}, ErrReservedQueryKey
			}
		}
	}

	return callback, nil
}

func hasControlCharacter(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}

	return false
}

func isValidPort(port string) bool {
	number, err := strconv.Atoi(port)

	return err == nil && number > 0 && number <= 65535
}

// isLoopbackHost reports whether a host name can only reach the machine running
// the browser: the name localhost, or any address in 127.0.0.0/8 or ::1.
func isLoopbackHost(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}

	address, err := netip.ParseAddr(hostname)
	if err != nil {
		return false
	}

	return address.IsLoopback()
}
