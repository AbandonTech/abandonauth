// Package request reads the inputs of one HTTP request and records why any of
// them was refused.
//
// A handler reads the inputs it needs, then calls OK once. A refused input
// returns its zero value, so a handler that forgets to check OK still cannot
// act on a value that failed to parse.
//
// A refusal says where the input was and what was wrong with it, never what it
// contained. Refusals are sent to the client and may be logged, and a request
// that fails validation can still have carried a credential.
package request

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// MaxBodyBytes is the largest request body this service reads. Every body it
// accepts is one small JSON object or a list of callback URIs. A larger body is
// refused without being buffered.
const MaxBodyBytes int64 = 64 << 10

// Where an input was found. These are the first element of a refusal's location.
const (
	locationBody   = "body"
	locationPath   = "path"
	locationQuery  = "query"
	locationHeader = "header"
)

// Why an input was refused.
const (
	typeMissing     = "missing"
	typeStringType  = "string_type"
	typeListType    = "list_type"
	typeObjectType  = "model_attributes_type"
	typeUUIDParsing = "uuid_parsing"
	typeJSONInvalid = "json_invalid"
	typeTooLong     = "too_long"
)

// Inputs collects the values one handler reads and the refusals it accumulated.
type Inputs struct {
	request *http.Request

	// body holds the members of a decoded object body. bodyDecoded records that
	// decoding succeeded, so reading a member of a body that never arrived
	// reports the missing body once instead of once per member.
	body        map[string]json.RawMessage
	bodyDecoded bool

	failures []response.Failure
}

// New starts reading the inputs of a request.
func New(httpRequest *http.Request) *Inputs {
	return &Inputs{request: httpRequest}
}

// OK reports whether every input read so far was acceptable.
func (i *Inputs) OK() bool {
	return len(i.failures) == 0
}

// Failures lists every refusal, in the order the inputs were read.
func (i *Inputs) Failures() []response.Failure {
	return i.failures
}

// Refuse records a refusal a handler decided on itself.
func (i *Inputs) Refuse(failure response.Failure) {
	i.failures = append(i.failures, failure)
}

func (i *Inputs) record(location []any, message, failureType string) {
	i.failures = append(i.failures, response.Failure{
		Location: location,
		Message:  message,
		Type:     failureType,
	})
}

// DecodeObjectBody reads a JSON object body. Members the service does not know
// are ignored, so an application that sends extra fields keeps working.
func (i *Inputs) DecodeObjectBody() {
	raw, ok := i.readBody()
	if !ok {
		return
	}

	if len(raw) == 0 {
		i.record([]any{locationBody}, "Field required", typeMissing)

		return
	}

	var members map[string]json.RawMessage

	if err := decodeExactlyOneValue(raw, &members); err != nil {
		i.refuseDecodeError(err, typeObjectType, "Input should be a valid dictionary or object")

		return
	}

	i.body = members
	i.bodyDecoded = true
}

// DecodeOptionalObjectBody reads a JSON object body that the request need not
// carry. It reports whether one was present.
//
// An empty body is not a refusal, and neither is an explicit null, which is how
// a client says it is sending nothing. A body that is present and malformed is.
func (i *Inputs) DecodeOptionalObjectBody() bool {
	raw, ok := i.readBody()
	if !ok {
		return false
	}

	if len(raw) == 0 {
		return false
	}

	var members map[string]json.RawMessage

	if err := decodeExactlyOneValue(raw, &members); err != nil {
		i.refuseDecodeError(err, typeObjectType, "Input should be a valid dictionary or object")

		return false
	}

	if members == nil {
		return false
	}

	i.body = members
	i.bodyDecoded = true

	return true
}

// DecodeStringArrayBody reads a JSON array of strings as the whole body.
func (i *Inputs) DecodeStringArrayBody() []string {
	raw, ok := i.readBody()
	if !ok {
		return nil
	}

	if len(raw) == 0 {
		i.record([]any{locationBody}, "Field required", typeMissing)

		return nil
	}

	var elements []json.RawMessage

	if err := decodeExactlyOneValue(raw, &elements); err != nil {
		i.refuseDecodeError(err, typeListType, "Input should be a valid list")

		return nil
	}

	values := make([]string, 0, len(elements))

	for index, element := range elements {
		var value string

		if err := json.Unmarshal(element, &value); err != nil {
			i.record([]any{locationBody, index}, "Input should be a valid string", typeStringType)

			continue
		}

		values = append(values, value)
	}

	return values
}

// BodyString reads a required string member of the object body.
func (i *Inputs) BodyString(name string) string {
	raw, present := i.bodyMember(name)
	if !present {
		return ""
	}

	var value string

	if err := json.Unmarshal(raw, &value); err != nil {
		i.record([]any{locationBody, name}, "Input should be a valid string", typeStringType)

		return ""
	}

	return value
}

// BodyUUID reads a required member of the object body that must be a UUID.
func (i *Inputs) BodyUUID(name string) uuid.UUID {
	raw, present := i.bodyMember(name)
	if !present {
		return uuid.Nil
	}

	var value string

	if err := json.Unmarshal(raw, &value); err != nil {
		i.record([]any{locationBody, name}, "Input should be a valid string", typeStringType)

		return uuid.Nil
	}

	parsed, err := uuid.Parse(value)
	if err != nil {
		i.record([]any{locationBody, name}, "Input should be a valid UUID", typeUUIDParsing)

		return uuid.Nil
	}

	return parsed
}

// PathUUID reads a path segment that must be a UUID.
func (i *Inputs) PathUUID(name string) uuid.UUID {
	value := i.request.PathValue(name)

	parsed, err := uuid.Parse(value)
	if err != nil {
		i.record([]any{locationPath, name}, "Input should be a valid UUID", typeUUIDParsing)

		return uuid.Nil
	}

	return parsed
}

// PathString reads a path segment as text.
func (i *Inputs) PathString(name string) string {
	return i.request.PathValue(name)
}

// Header reads a required request header.
func (i *Inputs) Header(name string) string {
	value := i.request.Header.Get(name)
	if value == "" {
		i.record([]any{locationHeader, strings.ToLower(name)}, "Field required", typeMissing)

		return ""
	}

	return value
}

// OptionalHeader reads a request header that need not be present.
func (i *Inputs) OptionalHeader(name string) string {
	return i.request.Header.Get(name)
}

// Query reads a required query parameter.
func (i *Inputs) Query(name string) string {
	values, present := i.request.URL.Query()[name]
	if !present || len(values) == 0 {
		i.record([]any{locationQuery, name}, "Field required", typeMissing)

		return ""
	}

	return values[0]
}

// QueryUUID reads a required query parameter that must be a UUID.
func (i *Inputs) QueryUUID(name string) uuid.UUID {
	value := i.Query(name)
	if value == "" {
		return uuid.Nil
	}

	parsed, err := uuid.Parse(value)
	if err != nil {
		i.record([]any{locationQuery, name}, "Input should be a valid UUID", typeUUIDParsing)

		return uuid.Nil
	}

	return parsed
}

// OptionalQuery reads a query parameter that need not be present.
func (i *Inputs) OptionalQuery(name string) string {
	return i.request.URL.Query().Get(name)
}

// bodyMember returns a member of the decoded object body, recording that it is
// required and absent when it is.
func (i *Inputs) bodyMember(name string) (json.RawMessage, bool) {
	if !i.bodyDecoded {
		return nil, false
	}

	raw, present := i.body[name]
	if !present || string(raw) == "null" {
		i.record([]any{locationBody, name}, "Field required", typeMissing)

		return nil, false
	}

	return raw, true
}

func (i *Inputs) readBody() ([]byte, bool) {
	if i.request.Body == nil {
		return nil, true
	}

	limited := http.MaxBytesReader(nil, i.request.Body, MaxBodyBytes)

	raw, err := io.ReadAll(limited)
	if err != nil {
		var toolarge *http.MaxBytesError
		if errors.As(err, &toolarge) {
			i.record([]any{locationBody}, "Request body is too large", typeTooLong)

			return nil, false
		}

		i.record([]any{locationBody}, "JSON decode error", typeJSONInvalid)

		return nil, false
	}

	return raw, true
}

// refuseDecodeError distinguishes text that is not JSON at all from JSON that is
// the wrong kind of value, because a client can act on the difference.
func (i *Inputs) refuseDecodeError(err error, wrongShapeType, wrongShapeMessage string) {
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) {
		i.record([]any{locationBody}, wrongShapeMessage, wrongShapeType)

		return
	}

	i.record([]any{locationBody}, "JSON decode error", typeJSONInvalid)
}

// decodeExactlyOneValue rejects trailing content after the value, which would
// otherwise let a body carry a second document that nothing inspects.
func decodeExactlyOneValue(raw []byte, into any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))

	if err := decoder.Decode(into); err != nil {
		return err
	}

	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("the body carries more than one value")
	}

	return nil
}
