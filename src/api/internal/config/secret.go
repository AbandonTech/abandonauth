package config

import "errors"

// Secret holds a configured value that must never reach a log line, an error
// message, a metric label or the API documentation.
//
// The value is only obtainable through Reveal, so every other way of rendering
// it, including fmt verbs and JSON encoding, produces the redaction marker
// instead. Call Reveal at the point of use and do not store the result.
type Secret struct {
	value string
}

// Redacted is what a Secret renders as.
const Redacted = "[redacted]"

// NewSecret wraps a sensitive configured value.
func NewSecret(value string) Secret {
	return Secret{value: value}
}

// Reveal returns the underlying value.
func (s Secret) Reveal() string {
	return s.value
}

// IsEmpty reports whether no value was configured.
func (s Secret) IsEmpty() bool {
	return s.value == ""
}

// String satisfies fmt.Stringer with the redaction marker.
func (s Secret) String() string {
	return Redacted
}

// GoString satisfies the %#v verb with the redaction marker.
func (s Secret) GoString() string {
	return Redacted
}

// MarshalJSON refuses to encode the value. Configuration is not serialised in
// normal operation, so an attempt to encode it is a mistake worth surfacing.
func (s Secret) MarshalJSON() ([]byte, error) {
	return nil, errors.New("a configuration secret cannot be encoded")
}
