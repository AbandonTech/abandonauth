package web

import (
	"bufio"
	"context"
	"net"
	"net/http"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// RequestIDHeader carries an identifier a client can quote when reporting a
// problem, and which every log line about the request is written under.
const RequestIDHeader = "X-Request-ID"

// maxAcceptedRequestID bounds an identifier a client supplied, so a header
// cannot be used to write an unbounded value into every log line.
const maxAcceptedRequestID = 64

// recordingWriter remembers what was answered, because the response is written
// by a handler and both the logging and the recovery from a failure happen
// outside it. It also remembers whether anything has been committed yet, which
// is what decides whether a failure can still be answered.
type recordingWriter struct {
	http.ResponseWriter

	status   int
	written  int64
	hijacked bool
}

// recording returns the recorder a writer already is, or wraps it in one.
func recording(writer http.ResponseWriter) *recordingWriter {
	if recorder, already := writer.(*recordingWriter); already {
		return recorder
	}

	return &recordingWriter{ResponseWriter: writer}
}

// Unwrap exposes the underlying writer to http.ResponseController, so the
// optional operations this recorder does not observe still reach the listener.
func (w *recordingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// committed reports whether anything has reached the client: a status, a body,
// or the connection itself.
func (w *recordingWriter) committed() bool {
	return w.status != 0 || w.hijacked
}

func (w *recordingWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *recordingWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	written, err := w.ResponseWriter.Write(body)
	w.written += int64(written)

	return written, err
}

// Flush sends what has been written so far. Flushing commits an implicit 200
// if nothing was written, so it is recorded as such before it happens.
func (w *recordingWriter) Flush() {
	_ = w.FlushError()
}

// FlushError is what http.ResponseController prefers over Flush.
func (w *recordingWriter) FlushError() error {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Hijack hands the connection to the handler. Once that has succeeded nothing
// more can be written through this writer, so the recorder stops answering.
func (w *recordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	connection, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.hijacked = true
	}

	return connection, buffered, err
}

// recoverPanics keeps a defect in one handler from ending the process, and
// answers the request that provoked it with a failure it can parse, unless an
// answer has already begun: a second one would only contradict the first.
//
// The value recovered is written nowhere. It can hold anything that was in
// scope, including a credential, so the log records only that a handler failed
// and which request it was answering.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder := recording(writer)
		answering, request := routeRecording(request)

		defer func() {
			if recover() == nil {
				return
			}

			s.logger.Error().
				Str("request_id", requestIDOf(request)).
				Str("route", answering.name()).
				Msg("a request handler failed")

			if recorder.committed() {
				return
			}

			response.Error(recorder, http.StatusInternalServerError, "Internal Server Error")
		}()

		next.ServeHTTP(recorder, request)
	})
}

// identifyRequest gives every request an identifier and returns it, so a report
// of a failure can be found in the log without the reporter quoting anything
// they sent.
func (s *Server) identifyRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identifier := request.Header.Get(RequestIDHeader)
		if identifier == "" || len(identifier) > maxAcceptedRequestID || hasUnprintable(identifier) {
			identifier = uuid.NewString()
		}

		request.Header.Set(RequestIDHeader, identifier)
		writer.Header().Set(RequestIDHeader, identifier)

		next.ServeHTTP(writer, request)
	})
}

// answeringRoute is where the router leaves the pattern it matched, so a log
// line can name it. The match happens inside the router, on a request derived
// from this one, so it cannot be read from the request the outer layers hold.
type answeringRoute struct {
	pattern string
}

// name is what a log line calls the route: its pattern, or the fact that no
// route claimed the request.
func (a *answeringRoute) name() string {
	if a.pattern == "" {
		return "unmatched"
	}

	return a.pattern
}

// routeKey is the context key the matched route is left under.
type routeKey struct{}

// routeRecording returns the route holder a request already carries, or gives
// it one, so every layer that logs names the same route.
func routeRecording(request *http.Request) (*answeringRoute, *http.Request) {
	if answering, carried := request.Context().Value(routeKey{}).(*answeringRoute); carried {
		return answering, request
	}

	answering := &answeringRoute{}

	return answering, request.WithContext(context.WithValue(request.Context(), routeKey{}, answering))
}

// recordRoute hands the pattern the router matched back to the request log.
func recordRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if answering, carried := request.Context().Value(routeKey{}).(*answeringRoute); carried {
			answering.pattern = request.Pattern
		}

		next.ServeHTTP(writer, request)
	})
}

// logRequest records that a request happened and how it ended.
//
// It records the route pattern rather than the URL, and never the query, the
// headers, the cookies or the body: a URL this service serves can carry an
// authorization code, and a header can carry a token.
func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := s.now()
		recorder := recording(writer)
		answering, request := routeRecording(request)

		next.ServeHTTP(recorder, request)

		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}

		event := s.logger.Info()
		if status >= http.StatusInternalServerError {
			event = s.logger.Error()
		}

		event.
			Str("request_id", requestIDOf(request)).
			Str("method", request.Method).
			Str("route", answering.name()).
			Int("status", status).
			Int64("bytes", recorder.written).
			Dur("duration", s.now().Sub(started)).
			Msg("request")
	})
}

func requestIDOf(request *http.Request) string {
	return request.Header.Get(RequestIDHeader)
}

func hasUnprintable(value string) bool {
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return true
		}
	}

	return false
}
