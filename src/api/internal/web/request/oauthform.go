package request

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Fixed bounds of the parameters an OAuth endpoint reads. They are protocol
// constants, not settings, and each is checked before any value is used.
const (
	MaxOAuthQueryBytes  = 8192
	MaxOAuthQueryFields = 32
	MaxOAuthFormBytes   = 16384
	MaxOAuthFormFields  = 16
	MaxOAuthNameBytes   = 64
)

// OAuthFormContentType is the one media type an OAuth form is accepted in.
const OAuthFormContentType = "application/x-www-form-urlencoded"

// Reasons an OAuth endpoint's parameters are refused whole. Neither says which
// part was refused or repeats it.
var (
	ErrOAuthParameters  = errors.New("the parameters are not one well-formed, bounded set")
	ErrOAuthContentType = errors.New("the body is not exactly an application/x-www-form-urlencoded form")
)

// OAuthParameters are the recognized parameters of one OAuth request, decoded.
// A field the endpoint does not recognize is not kept.
type OAuthParameters map[string][]string

// Lookup returns a recognized parameter's value when it appeared exactly once,
// and how many times it appeared.
func (p OAuthParameters) Lookup(name string) (string, int) {
	values := p[name]
	if len(values) != 1 {
		return "", len(values)
	}

	return values[0], 1
}

// Has reports whether a recognized parameter appeared at all.
func (p OAuthParameters) Has(name string) bool {
	return len(p[name]) > 0
}

// OAuthQuery reads an OAuth endpoint's query under the authorization request's
// bounds. A request body is never a source.
func OAuthQuery(request *http.Request, recognized []string) (OAuthParameters, error) {
	return parseOAuthParameters(request.URL.RawQuery, MaxOAuthQueryBytes, MaxOAuthQueryFields, recognized)
}

// OAuthForm reads an OAuth endpoint's form body. The query is never a source.
//
// The body must be declared exactly once as an unparameterized form, and is
// read only up to one byte past its bound, so an oversized body is refused
// without being buffered.
func OAuthForm(request *http.Request, recognized []string) (OAuthParameters, error) {
	declared := request.Header.Values("Content-Type")
	if len(declared) != 1 || !strings.EqualFold(declared[0], OAuthFormContentType) {
		return nil, ErrOAuthContentType
	}

	if request.Body == nil {
		return OAuthParameters{}, nil
	}

	raw, err := io.ReadAll(io.LimitReader(request.Body, MaxOAuthFormBytes+1))
	if err != nil {
		return nil, ErrOAuthParameters
	}

	return parseOAuthParameters(string(raw), MaxOAuthFormBytes, MaxOAuthFormFields, recognized)
}

// parseOAuthParameters reads name=value pairs separated by '&'.
//
// Readers disagree about separators, escapes, encoded names and letter case,
// and a parameter one reader sees and another does not is where a smuggled
// value hides. So any field two readers could read differently refuses the
// whole source, and nothing parsed from it is returned.
func parseOAuthParameters(raw string, maxBytes, maxFields int, recognized []string) (OAuthParameters, error) {
	if len(raw) > maxBytes {
		return nil, ErrOAuthParameters
	}

	parsed := OAuthParameters{}

	if raw == "" {
		return parsed, nil
	}

	if strings.Contains(raw, ";") {
		return nil, ErrOAuthParameters
	}

	fields := strings.Split(raw, "&")
	if len(fields) > maxFields {
		return nil, ErrOAuthParameters
	}

	for _, field := range fields {
		name, rawValue, _ := strings.Cut(field, "=")
		if !isParameterName(name) {
			return nil, ErrOAuthParameters
		}

		value, valid := decodeParameterValue(rawValue)
		if !valid {
			return nil, ErrOAuthParameters
		}

		known, varied := recognizedName(name, recognized)
		if varied {
			return nil, ErrOAuthParameters
		}

		if known {
			parsed[name] = append(parsed[name], value)
		}
	}

	return parsed, nil
}

// isParameterName admits a name of unreserved characters only, so no name can
// be written in a second, encoded spelling.
func isParameterName(name string) bool {
	if name == "" || len(name) > MaxOAuthNameBytes {
		return false
	}

	for index := range len(name) {
		character := name[index]

		unreserved := (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '.' ||
			character == '_' || character == '~'
		if !unreserved {
			return false
		}
	}

	return true
}

// recognizedName reports whether a name is one the endpoint reads, and whether
// it differs from one only in letter case, which is refused rather than read.
func recognizedName(name string, recognized []string) (bool, bool) {
	for _, candidate := range recognized {
		if name == candidate {
			return true, false
		}

		if strings.EqualFold(name, candidate) {
			return false, true
		}
	}

	return false, false
}

// decodeParameterValue decodes '+' as a space and each percent escape, and
// refuses a raw byte outside printable ASCII, an escape that is not two
// hexadecimal digits, and a result that is not UTF-8 or holds a control
// character.
func decodeParameterValue(raw string) (string, bool) {
	var decoded strings.Builder

	decoded.Grow(len(raw))

	for index := 0; index < len(raw); index++ {
		character := raw[index]

		switch {
		case character == '+':
			decoded.WriteByte(' ')
		case character == '%':
			if index+2 >= len(raw) || !isHex(raw[index+1]) || !isHex(raw[index+2]) {
				return "", false
			}

			decoded.WriteByte(unhex(raw[index+1])<<4 | unhex(raw[index+2]))

			index += 2
		case character <= 0x20 || character >= 0x7f:
			return "", false
		default:
			decoded.WriteByte(character)
		}
	}

	value := decoded.String()
	if !utf8.ValidString(value) {
		return "", false
	}

	for _, character := range value {
		if character < 0x20 || character == 0x7f || (character >= 0x80 && character <= 0x9f) {
			return "", false
		}
	}

	return value, true
}

func isHex(character byte) bool {
	return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
		(character >= 'A' && character <= 'F')
}

func unhex(character byte) byte {
	switch {
	case character >= 'a':
		return character - 'a' + 10
	case character >= 'A':
		return character - 'A' + 10
	default:
		return character - '0'
	}
}
