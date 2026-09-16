package web

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// composed is a server with nothing behind it. The concerns every request
// passes through do not read the database, so they can be driven without one.
func composed() *Server {
	return &Server{now: time.Now}
}

// composedWithLog is a server whose log the test can read.
func composedWithLog(log *bytes.Buffer) *Server {
	return &Server{now: time.Now, logger: zerolog.New(log)}
}

// hijackableWriter is a listener's writer that can hand its connection over,
// and remembers whether anything was written through it afterwards.
type hijackableWriter struct {
	*httptest.ResponseRecorder

	hijacked    bool
	wroteHeader bool
	written     int
}

func (w *hijackableWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true

	ours, theirs := net.Pipe()

	_ = theirs.Close()

	return ours, bufio.NewReadWriter(bufio.NewReader(ours), bufio.NewWriter(ours)), nil
}

func (w *hijackableWriter) WriteHeader(status int) {
	w.wroteHeader = true
	w.ResponseRecorder.WriteHeader(status)
}

func (w *hijackableWriter) Write(body []byte) (int, error) {
	w.written += len(body)

	return w.ResponseRecorder.Write(body)
}

// deadlineWriter is a listener's writer that accepts a write deadline, which
// the recorder in front of it does not itself implement.
type deadlineWriter struct {
	*httptest.ResponseRecorder

	deadline time.Time
}

func (w *deadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline

	return nil
}

// A route this build declares but cannot answer would reply with a surprise
// rather than with its contract, so start-up refuses to serve with any gap.
func TestEveryDeclaredRouteHasHandler(t *testing.T) {
	t.Parallel()

	if missing := composed().MissingHandlers(); len(missing) > 0 {
		t.Errorf("declared routes with no handler: %v", missing)
	}
}

// The route table is the only place a URL is written. A handler bound to a name
// the table does not carry would never be reached, and would hide the fact that
// the endpoint it was written for is not served.
func TestNoHandlerIsBoundToRouteThatIsNotDeclared(t *testing.T) {
	t.Parallel()

	declared := make([]RouteName, 0, len(Routes()))
	for _, route := range Routes() {
		declared = append(declared, route.Name)
	}

	for name := range composed().handlers() {
		if !slices.Contains(declared, name) {
			t.Errorf("handler %q is bound to no declared route", name)
		}
	}
}

// A defect in one handler ends that request, not the process, and the client
// gets something it can parse rather than a dropped connection.
func TestPanicIsAnsweredAndDoesNotEscape(t *testing.T) {
	t.Parallel()

	const secret = "placeholder-credential-in-scope"

	var log bytes.Buffer

	service := composedWithLog(&log)
	handler := service.surround(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("a handler failed holding " + secret)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, APIRoot+"/me", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}

	if body := recorder.Body.String(); body != "{\"detail\":\"Internal Server Error\"}\n" {
		t.Errorf("body = %q, want the service's own failure shape", body)
	}

	// Whatever was in scope when a handler failed can include a credential, so
	// the recovered value is written neither to the response nor to the log.
	if strings.Contains(recorder.Body.String(), secret) {
		t.Error("what the handler was holding was returned to the client")
	}

	if strings.Contains(log.String(), secret) {
		t.Error("what the handler was holding was written to the log")
	}

	if !strings.Contains(log.String(), "a request handler failed") {
		t.Error("the failure was not logged at all")
	}
}

// An answer that has already begun is not followed by a second one. Whatever a
// handler had written when it failed is what the client gets, not that and
// then a failure body glued to it.
func TestPanicAfterAnswerHasBegunAddsNothingToIt(t *testing.T) {
	t.Parallel()

	begun := map[string]func(http.ResponseWriter){
		"a status and part of a body": func(writer http.ResponseWriter) {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("partial"))
		},
		"part of a body alone": func(writer http.ResponseWriter) {
			_, _ = writer.Write([]byte("partial"))
		},
	}

	for name, begin := range begun {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := composed()
			handler := service.surround(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				begin(writer)
				panic("a handler failed after answering")
			}))

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, APIRoot+"/me", nil))

			if recorder.Code != http.StatusOK {
				t.Errorf("status = %d, want the %d that had already been sent", recorder.Code, http.StatusOK)
			}

			if body := recorder.Body.String(); body != "partial" {
				t.Errorf("body = %q, want only what the handler had written", body)
			}
		})
	}
}

// Flushing commits the response as much as writing does, whichever way the
// handler asks for it, so a failure after a flush is not answered either.
func TestPanicAfterFlushAddsNothing(t *testing.T) {
	t.Parallel()

	flushes := map[string]func(http.ResponseWriter){
		"through the response controller": func(writer http.ResponseWriter) {
			if err := http.NewResponseController(writer).Flush(); err != nil {
				panic("flushing was refused: " + err.Error())
			}
		},
		"through the flusher interface": func(writer http.ResponseWriter) {
			flusher, ok := writer.(http.Flusher)
			if !ok {
				panic("the writer cannot flush")
			}

			flusher.Flush()
		},
	}

	for name, flush := range flushes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := composed()
			handler := service.surround(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				flush(writer)
				panic("a handler failed after flushing")
			}))

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, APIRoot+"/me", nil))

			if !recorder.Flushed {
				t.Error("the flush did not reach the listener")
			}

			if recorder.Code != http.StatusOK {
				t.Errorf("status = %d, want the %d the flush committed", recorder.Code, http.StatusOK)
			}

			if recorder.Body.Len() != 0 {
				t.Errorf("body = %q, want nothing after a flushed empty response", recorder.Body.String())
			}
		})
	}
}

// Once a handler has taken the connection, nothing more can be written through
// the response, and a failure afterwards writes nothing.
func TestPanicAfterHijackWritesNothing(t *testing.T) {
	t.Parallel()

	service := composed()
	handler := service.surround(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		connection, _, err := http.NewResponseController(writer).Hijack()
		if err != nil {
			panic("hijacking was refused: " + err.Error())
		}

		_ = connection.Close()

		panic("a handler failed after taking the connection")
	}))

	writer := &hijackableWriter{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, APIRoot+"/me", nil))

	if !writer.hijacked {
		t.Fatal("the hijack did not reach the listener")
	}

	if writer.wroteHeader || writer.written != 0 {
		t.Error("something was written through a response whose connection had been taken")
	}
}

// The recorder in front of the listener's writer does not hide what that
// writer can do: an operation it does not observe reaches the listener when
// the listener supports it, and is reported unsupported when it does not.
func TestOptionalWriterOperationsReachListener(t *testing.T) {
	t.Parallel()

	deadline := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)

	var (
		reported  error
		requested bool
	)

	service := composed()
	handler := service.surround(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requested = true
		reported = http.NewResponseController(writer).SetWriteDeadline(deadline)
	}))

	supporting := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(supporting, httptest.NewRequest(http.MethodGet, APIRoot+"/me", nil))

	if !requested {
		t.Fatal("the handler was not reached")
	}

	if reported != nil {
		t.Errorf("a deadline the listener supports was refused: %v", reported)
	}

	if !supporting.deadline.Equal(deadline) {
		t.Errorf("deadline = %v, want %v to have reached the listener", supporting.deadline, deadline)
	}

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, APIRoot+"/me", nil))

	if !errors.Is(reported, http.ErrNotSupported) {
		t.Errorf("a deadline the listener cannot support reported %v, want %v", reported, http.ErrNotSupported)
	}
}

// Recovery is outermost and identification is inside it, so the request that
// provoked a defect is the one a report can be traced by.
func TestAnswerCarriesIdentifierEvenWhenHandlerFails(t *testing.T) {
	t.Parallel()

	service := composed()
	handler := service.surround(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("a handler failed")
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, APIRoot+"/me", nil))

	if recorder.Header().Get(RequestIDHeader) == "" {
		t.Error("a failed request cannot be found in the log")
	}
}

// A client that opens a connection and then stalls must not hold a worker
// indefinitely, so each phase of a request is bounded rather than relying on one
// overall limit a slow body could evade.
func TestEveryPhaseOfConnectionIsBounded(t *testing.T) {
	t.Parallel()

	listener := NewHTTPServer("127.0.0.1:8000", http.NotFoundHandler())

	bounded := map[string]time.Duration{
		"ReadHeaderTimeout": listener.ReadHeaderTimeout,
		"ReadTimeout":       listener.ReadTimeout,
		"WriteTimeout":      listener.WriteTimeout,
		"IdleTimeout":       listener.IdleTimeout,
	}

	for phase, limit := range bounded {
		if limit <= 0 {
			t.Errorf("%s is unbounded", phase)
		}
	}

	if ShutdownGracePeriod <= 0 {
		t.Error("a stop would wait for requests in flight forever")
	}
}
