package web

import (
	"context"
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
// by a handler and the logging happens outside it.
type recordingWriter struct {
	http.ResponseWriter

	status  int
	written int64
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

// recoverPanics keeps a defect in one handler from ending the process, and
// answers the request that provoked it with a failure it can parse.
//
// The value recovered is written to the log and never to the response: it can
// hold anything that was in scope, including a credential.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}

			s.logger.Error().
				Str("request_id", requestIDOf(request)).
				Str("route", request.Pattern).
				Interface("panic", recovered).
				Msg("a request handler failed")

			response.Error(writer, http.StatusInternalServerError, "Internal Server Error")
		}()

		next.ServeHTTP(writer, request)
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

// answeringRoute is where the router leaves the pattern it matched, so the log
// can name it. The match happens inside the router, on a request derived from
// this one, so it cannot be read from the request the log middleware holds.
type answeringRoute struct {
	pattern string
}

// routeKey is the context key the matched route is left under.
type routeKey struct{}

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
		recorder := &recordingWriter{ResponseWriter: writer}
		answering := &answeringRoute{}

		request = request.WithContext(context.WithValue(request.Context(), routeKey{}, answering))

		next.ServeHTTP(recorder, request)

		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}

		event := s.logger.Info()
		if status >= http.StatusInternalServerError {
			event = s.logger.Error()
		}

		route := answering.pattern
		if route == "" {
			route = "unmatched"
		}

		event.
			Str("request_id", requestIDOf(request)).
			Str("method", request.Method).
			Str("route", route).
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
