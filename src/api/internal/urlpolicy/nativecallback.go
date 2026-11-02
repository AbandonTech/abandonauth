package urlpolicy

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// Reasons a public client's loopback callback template is refused. Like every
// refusal here, none repeats the value it refused.
var (
	ErrNativeScheme    = errors.New("a public client callback must begin http://")
	ErrNativeHost      = errors.New("a public client callback host must be an IPv4 loopback literal or [::1]")
	ErrNativePort      = errors.New("a public client callback is registered without a port")
	ErrNativePath      = errors.New("a public client callback needs an absolute path in one spelling")
	ErrNativeQuery     = errors.New("a public client callback query is malformed")
	ErrNativeCharacter = errors.New("a public client callback carries a character it may not")
	ErrNativeTooLong   = errors.New("a public client callback is too long")
)

// MaxNativeRedirectBytes bounds a public client's redirect, port included.
const MaxNativeRedirectBytes = 2048

// nativeResponseKeys are the query keys an authorization response to a public
// client carries. A template may not already use one in any letter case or
// encoding, or the client would read two values under the key.
var nativeResponseKeys = []string{"code", "state", "error", "error_description", "iss"}

const (
	nativeScheme       = "http://"
	nativeIPv6Loopback = "[::1]"
)

// NativeCallbackTemplate is a public client's registered loopback callback: a
// redirect with its port left for the client to choose at run time.
//
// It keeps the exact registered spelling split around the place the port goes,
// so a redirect is compared and rebuilt byte for byte and no parser ever
// normalises an address, a path or an escape.
type NativeCallbackTemplate struct {
	authority string
	rest      string
}

// String returns the exact registered spelling.
func (t NativeCallbackTemplate) String() string {
	return nativeScheme + t.authority + t.rest
}

// ParseNativeCallbackTemplate validates a loopback callback a public client
// registers: http, an IPv4 literal in 127.0.0.0/8 or [::1], no port, an absolute
// path, and nothing that a parser could read in two ways.
func ParseNativeCallbackTemplate(raw string) (NativeCallbackTemplate, error) {
	if raw == "" {
		return NativeCallbackTemplate{}, ErrEmpty
	}

	if len(raw) > MaxNativeRedirectBytes {
		return NativeCallbackTemplate{}, ErrNativeTooLong
	}

	for index := range len(raw) {
		if !isNativeCharacter(raw[index]) {
			return NativeCallbackTemplate{}, ErrNativeCharacter
		}
	}

	afterScheme, found := strings.CutPrefix(raw, nativeScheme)
	if !found {
		return NativeCallbackTemplate{}, ErrNativeScheme
	}

	slash := strings.IndexByte(afterScheme, '/')
	if slash < 0 {
		return NativeCallbackTemplate{}, ErrNativePath
	}

	authority, rest := afterScheme[:slash], afterScheme[slash:]

	if strings.ContainsAny(authority, "@?") {
		return NativeCallbackTemplate{}, ErrUserInfo
	}

	if err := checkLoopbackAuthority(authority); err != nil {
		return NativeCallbackTemplate{}, err
	}

	path, query, hasQuery := strings.Cut(rest, "?")

	if err := checkNativePath(path); err != nil {
		return NativeCallbackTemplate{}, err
	}

	if hasQuery {
		if err := checkNativeQuery(query); err != nil {
			return NativeCallbackTemplate{}, err
		}
	}

	return NativeCallbackTemplate{authority: authority, rest: rest}, nil
}

// MatchNativeCallback returns the redirect a public client asked for when it is
// exactly the template with one port from 1 through 65535 added after the
// address, and nothing else changed.
func MatchNativeCallback(template NativeCallbackTemplate, requested string) (string, bool) {
	if template.authority == "" || len(requested) > MaxNativeRedirectBytes {
		return "", false
	}

	prefix := nativeScheme + template.authority + ":"

	afterPrefix, found := strings.CutPrefix(requested, prefix)
	if !found {
		return "", false
	}

	port, found := strings.CutSuffix(afterPrefix, template.rest)
	if !found || !isCanonicalPort(port) {
		return "", false
	}

	return requested, true
}

// NativeAuthorizationResponse appends the response parameters to a redirect a
// public client was proven to have registered, in the order given.
//
// Every existing byte is kept; only the added names and values are encoded,
// so nothing a client registered is rewritten and nothing a caller supplies can
// become a second parameter, a fragment or a header.
func NativeAuthorizationResponse(redirect string, parameters ...[2]string) string {
	var built strings.Builder

	built.WriteString(redirect)

	separator := "?"
	if strings.Contains(redirect, "?") {
		separator = "&"
	}

	for _, parameter := range parameters {
		built.WriteString(separator)
		built.WriteString(url.QueryEscape(parameter[0]))
		built.WriteString("=")
		built.WriteString(url.QueryEscape(parameter[1]))

		separator = "&"
	}

	return built.String()
}

// isNativeCharacter admits the printable ASCII an address may carry, less the
// characters that begin a fragment, separate in another dialect or invite a
// reader to re-encode them.
func isNativeCharacter(character byte) bool {
	if character <= 0x20 || character >= 0x7f {
		return false
	}

	return !strings.ContainsRune(`#\"<>^`+"`{|}", rune(character))
}

func checkLoopbackAuthority(authority string) error {
	if authority == nativeIPv6Loopback {
		return nil
	}

	if strings.Contains(authority, ":") {
		if strings.HasPrefix(authority, "[") {
			return ErrNativeHost
		}

		return ErrNativePort
	}

	octets := strings.Split(authority, ".")
	if len(octets) != 4 {
		return ErrNativeHost
	}

	for index, octet := range octets {
		value, canonical := canonicalDecimal(octet)
		if !canonical || value > 255 {
			return ErrNativeHost
		}

		if index == 0 && value != 127 {
			return ErrNativeHost
		}
	}

	return nil
}

// canonicalDecimal reads a run of digits with no sign and no leading zero.
func canonicalDecimal(text string) (int, bool) {
	if text == "" || len(text) > 5 || (len(text) > 1 && text[0] == '0') {
		return 0, false
	}

	for index := range len(text) {
		if text[index] < '0' || text[index] > '9' {
			return 0, false
		}
	}

	value, err := strconv.Atoi(text)

	return value, err == nil
}

func isCanonicalPort(port string) bool {
	value, canonical := canonicalDecimal(port)

	return canonical && value >= 1 && value <= 65535
}

func checkNativePath(path string) error {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") {
		return ErrNativePath
	}

	if err := checkEscapes(path); err != nil {
		return err
	}

	lowered := strings.ToLower(path)
	for _, encoded := range []string{"%2f", "%5c", "%2e"} {
		if strings.Contains(lowered, encoded) {
			return ErrNativePath
		}
	}

	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "." || segment == ".." {
			return ErrNativePath
		}
	}

	return nil
}

func checkNativeQuery(query string) error {
	if query == "" {
		return ErrNativeQuery
	}

	if strings.ContainsAny(query, ";?") {
		return ErrNativeQuery
	}

	if err := checkEscapes(query); err != nil {
		return ErrNativeQuery
	}

	for _, pair := range strings.Split(query, "&") {
		rawKey, _, _ := strings.Cut(pair, "=")
		if rawKey == "" {
			return ErrNativeQuery
		}

		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return ErrNativeQuery
		}

		for _, reserved := range nativeResponseKeys {
			if strings.EqualFold(key, reserved) {
				return ErrReservedQueryKey
			}
		}
	}

	return nil
}

// checkEscapes refuses a percent sign that does not begin two hexadecimal
// digits, which readers disagree about.
func checkEscapes(text string) error {
	for index := 0; index < len(text); index++ {
		if text[index] != '%' {
			continue
		}

		if index+2 >= len(text) || !isHexDigit(text[index+1]) || !isHexDigit(text[index+2]) {
			return ErrNativePath
		}

		index += 2
	}

	return nil
}

func isHexDigit(character byte) bool {
	return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
		(character >= 'A' && character <= 'F')
}
