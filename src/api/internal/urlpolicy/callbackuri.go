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

// ParseCallbackURI validates a URL the service may redirect a browser to and
// returns it with the scheme and host lower cased. The path, query and their
// encoding are left exactly as given, because callbacks are matched by exact
// equality against the value the application registered.
func ParseCallbackURI(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, ErrEmpty
	}

	if strings.TrimSpace(raw) != raw {
		return nil, ErrMalformed
	}

	if hasControlCharacter(raw) {
		return nil, ErrControlCharacter
	}

	// url.Parse silently accepts a fragment, so check the raw text as well: a
	// fragment is never sent to the server and would make an exact match
	// meaningless.
	if strings.Contains(raw, "#") {
		return nil, ErrFragment
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, ErrMalformed
	}

	if parsed.Scheme == "" {
		return nil, ErrNotAbsolute
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, ErrUnsupportedScheme
	}

	if parsed.Host == "" {
		return nil, ErrNotAbsolute
	}

	if parsed.User != nil {
		return nil, ErrUserInfo
	}

	parsed.Host = strings.ToLower(parsed.Host)

	port := parsed.Port()
	if port != "" && !isValidPort(port) {
		return nil, ErrInvalidPort
	}

	if parsed.Scheme == "http" {
		if !isLoopbackHost(parsed.Hostname()) {
			return nil, ErrInsecureTransport
		}

		// Without a port the URL depends on the reader's default, and an
		// application on port 80 of a developer machine is not the one that
		// registered the callback.
		if port == "" {
			return nil, ErrMissingPort
		}
	}

	if _, err := url.ParseQuery(parsed.RawQuery); err != nil {
		return nil, ErrMalformed
	}

	return parsed, nil
}

// ParseRegisteredCallbackURI validates a URL an application wants to register.
// It applies every rule of ParseCallbackURI and additionally refuses URLs that
// already use one of ResponseQueryKeys.
func ParseRegisteredCallbackURI(raw string) (*url.URL, error) {
	parsed, err := ParseCallbackURI(raw)
	if err != nil {
		return nil, err
	}

	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, ErrMalformed
	}

	for key := range query {
		for _, reserved := range ResponseQueryKeys {
			if strings.EqualFold(key, reserved) {
				return nil, ErrReservedQueryKey
			}
		}
	}

	return parsed, nil
}

// WithResponseParameter returns the callback URL with one query parameter added.
//
// The existing query is copied through byte for byte instead of being decoded
// and re-encoded: an application may depend on the order or the exact escaping
// of the parameters it registered, and re-encoding could change a signed value.
// Only the added pair is encoded, by the standard encoder.
func WithResponseParameter(callback *url.URL, key, value string) string {
	target := *callback
	added := url.Values{key: []string{value}}.Encode()

	if target.RawQuery == "" {
		target.RawQuery = added
	} else {
		target.RawQuery = target.RawQuery + "&" + added
	}

	return target.String()
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
