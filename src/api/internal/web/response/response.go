// Package response writes what clients receive.
//
// Nothing here writes the value that was rejected. Responses are sent to clients
// and may be logged, and a request that fails validation can still have carried
// a credential.
package response

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// ContentTypeJSON is the media type of every body this service writes.
const ContentTypeJSON = "application/json"

const (
	headerContentType = "Content-Type"
	headerLocation    = "Location"
	headerRetryAfter  = "Retry-After"
)

// Failure describes one input a request was rejected for. Location names where
// the input was found, from outermost to innermost: the part of the request,
// then the field, then the index within it.
type Failure struct {
	Location []any  `json:"loc"`
	Message  string `json:"msg"`
	Type     string `json:"type"`
}

// Failed is the body of a request the service refused, with one explanation.
type Failed struct {
	Detail string `json:"detail"`
}

// Invalidated is the body of a request refused for its inputs, listing each one.
type Invalidated struct {
	Detail []Failure `json:"detail"`
}

// JSON writes a value as the body of a response.
//
// A value that cannot be encoded is a defect in the handler, not something the
// client can act on, so the status is already written and the body is truncated
// rather than followed by a second, contradictory response.
func JSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set(headerContentType, ContentTypeJSON)
	writer.WriteHeader(status)

	_ = json.NewEncoder(writer).Encode(payload)
}

// Empty writes a response with no body.
func Empty(writer http.ResponseWriter, status int) {
	writer.WriteHeader(status)
}

// Error writes a failure with a human-readable explanation.
//
// The detail is written by the service, never assembled from request input, so
// it cannot be used to reflect a caller's value back to a browser.
func Error(writer http.ResponseWriter, status int, detail string) {
	JSON(writer, status, Failed{Detail: detail})
}

// NotFound reports that no route matched, or that the caller may not know
// whether the thing it named exists.
func NotFound(writer http.ResponseWriter) {
	Error(writer, http.StatusNotFound, "Not Found")
}

// MethodNotAllowed reports that the route exists but not for this method.
func MethodNotAllowed(writer http.ResponseWriter) {
	Error(writer, http.StatusMethodNotAllowed, "Method Not Allowed")
}

// Invalid rejects a request and lists the inputs it was rejected for.
func Invalid(writer http.ResponseWriter, failures []Failure) {
	if failures == nil {
		failures = []Failure{}
	}

	JSON(writer, http.StatusUnprocessableEntity, Invalidated{Detail: failures})
}

// TooManyRequests refuses a request that exceeded a limit and says how long to
// wait.
//
// The detail is the same whoever the caller is, so that being refused reveals
// nothing about whether an account or an application exists.
func TooManyRequests(writer http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if retryAfter > time.Duration(seconds)*time.Second {
		seconds++
	}

	if seconds < 1 {
		seconds = 1
	}

	writer.Header().Set(headerRetryAfter, strconv.Itoa(seconds))
	Error(writer, http.StatusTooManyRequests, "Too many requests. Try again later.")
}

// Redirect sends a browser elsewhere.
//
// The location is written exactly as given. Callers build it from a registered
// URL, so nothing here re-encodes or re-normalises a value that was already
// checked.
func Redirect(writer http.ResponseWriter, status int, location string) {
	writer.Header().Set(headerLocation, location)
	writer.WriteHeader(status)
}
