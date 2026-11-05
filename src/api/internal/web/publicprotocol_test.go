package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The worker serves exactly 64 public-protocol requests at once. The next is
// refused at once, before its handler runs, and is served again as soon as a
// permit is returned.
func TestPublicProtocolAdmitsExactlySixtyFourAtOnce(t *testing.T) {
	t.Parallel()

	admission := newPublicProtocolAdmission()
	release := make(chan struct{})

	var entered sync.WaitGroup

	entered.Add(publicProtocolPermits)

	held := withPublicProtocolAdmission(admission, refuseOAuthOverload, http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			entered.Done()
			<-release
		}))

	var finished sync.WaitGroup

	for range publicProtocolPermits {
		finished.Add(1)

		go func() {
			defer finished.Done()

			held.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}

	entered.Wait()

	reached := false
	next := withPublicProtocolAdmission(admission, refuseOAuthOverload, http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { reached = true }))

	refused := httptest.NewRecorder()
	next.ServeHTTP(refused, httptest.NewRequest(http.MethodGet, "/", nil))

	if reached || refused.Code != http.StatusServiceUnavailable {
		t.Fatalf("the 65th request was served (status %d)", refused.Code)
	}

	if body := refused.Body.String(); body != `{"error":"temporarily_unavailable"}`+"\n" {
		t.Errorf("body = %q", body)
	}

	if refused.Header().Get("Cache-Control") != "no-store" || refused.Header().Get("Pragma") != "no-cache" {
		t.Error("the refusal may be cached")
	}

	close(release)
	finished.Wait()

	next.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if !reached {
		t.Error("a request was refused after every permit was returned")
	}
}

// A handler that panics or whose request is abandoned still returns its permit.
func TestPublicProtocolPermitReturnsHoweverRequestEnds(t *testing.T) {
	t.Parallel()

	admission := newPublicProtocolAdmission()

	panicking := withPublicProtocolAdmission(admission, refuseOAuthOverload, http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { panic("a handler failure") }))

	for range publicProtocolPermits + 1 {
		func() {
			defer func() { _ = recover() }()

			panicking.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}

	abandoned := withPublicProtocolAdmission(admission, refuseOAuthOverload, http.HandlerFunc(
		func(_ http.ResponseWriter, request *http.Request) { <-request.Context().Done() }))

	for range publicProtocolPermits + 1 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		abandoned.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
		cancel()
	}

	if held := len(admission.permits); held != 0 {
		t.Errorf("%d permits are still held", held)
	}
}

// Each kind of public-protocol request is told it was refused in its own fixed
// words, and the browser-facing ones carry the page headers.
func TestPublicProtocolRefusalsAreFixed(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		refuse      func(http.ResponseWriter)
		body        string
		pageHeaders bool
	}{
		"an OAuth endpoint": {refuseOAuthOverload, `{"error":"temporarily_unavailable"}`, false},
		"the authorization request": {
			refuseAuthorizationOverload, `{"error":"temporarily_unavailable"}`, true,
		},
		"the authorization page": {refusePageOverload, `{"detail":"Service temporarily unavailable"}`, true},
		"a provider callback":    {refuseCallbackOverload, `{"detail":"Service temporarily unavailable"}`, false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			test.refuse(recorder)

			if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != test.body+"\n" {
				t.Errorf("answer = %d %q", recorder.Code, recorder.Body.String())
			}

			framed := recorder.Header().Get("X-Frame-Options") == "DENY" &&
				recorder.Header().Get("Referrer-Policy") == "no-referrer" &&
				recorder.Header().Get("Content-Security-Policy") == "frame-ancestors 'none'"
			if framed != test.pageHeaders {
				t.Errorf("page headers present = %v, want %v", framed, test.pageHeaders)
			}
		})
	}
}
