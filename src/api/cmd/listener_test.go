package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/logging"
)

// settleTimeout bounds every wait in these tests. Generous, because a loaded
// machine can take a moment to accept its first connection, and a test that
// waits forever reports a deadlock as ten silent minutes.
const settleTimeout = 10 * time.Second

func quietLogger() zerolog.Logger {
	return logging.New(logging.Options{Output: io.Discard})
}

// openListener binds a port of the machine's choosing, so the address is one
// nothing else is using and is open before anything is served on it.
func openListener(t *testing.T) net.Listener {
	t.Helper()

	listener, err := listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("opening a listener: %v", err)
	}

	return listener
}

func waitUntilAccepting(t *testing.T, address string) {
	t.Helper()

	deadline := time.Now().Add(settleTimeout)

	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			_ = connection.Close()

			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("nothing accepted a connection on %s", address)
}

func waitUntilRefusing(t *testing.T, address string) {
	t.Helper()

	deadline := time.Now().Add(settleTimeout)

	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return
		}

		_ = connection.Close()

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s was still accepting connections", address)
}

// awaitStop reads how serving ended, or fails the test if it never did.
func awaitStop(t *testing.T, stopped <-chan error) error {
	t.Helper()

	select {
	case err := <-stopped:
		return err
	case <-time.After(settleTimeout):
		t.Fatal("serving did not stop")

		return nil
	}
}

func TestStoppingClosesTheListener(t *testing.T) {
	listener := openListener(t)
	address := listener.Addr().String()

	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	stopped := make(chan error, 1)

	go func() {
		stopped <- serveUntilStopped(ctx, quietLogger(), listener, http.NotFoundHandler())
	}()

	waitUntilAccepting(t, address)
	stop()

	if err := awaitStop(t, stopped); err != nil {
		t.Fatalf("stopping reported an error: %v", err)
	}

	if connection, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		_ = connection.Close()

		t.Error("the port still accepts connections after the stop returned")
	}
}

func TestARequestInFlightIsAllowedToFinish(t *testing.T) {
	listener := openListener(t)
	address := listener.Addr().String()

	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	arrived := make(chan struct{})
	release := make(chan struct{})

	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(arrived)
		<-release

		writer.WriteHeader(http.StatusTeapot)

		if _, err := writer.Write([]byte("finished")); err != nil {
			t.Errorf("writing the response: %v", err)
		}
	})

	stopped := make(chan error, 1)

	go func() {
		stopped <- serveUntilStopped(ctx, quietLogger(), listener, handler)
	}()

	type outcome struct {
		status int
		body   string
		err    error
	}

	answered := make(chan outcome, 1)

	go func() {
		response, err := http.Get("http://" + address + "/")
		if err != nil {
			answered <- outcome{err: err}

			return
		}
		defer func() { _ = response.Body.Close() }()

		body, err := io.ReadAll(response.Body)
		answered <- outcome{status: response.StatusCode, body: string(body), err: err}
	}()

	select {
	case <-arrived:
	case <-time.After(settleTimeout):
		t.Fatal("the request never reached the handler")
	}

	stop()

	// The handler is held until the listener has already been closed, so what
	// follows is a response written after the stop began rather than one that
	// happened to finish first.
	waitUntilRefusing(t, address)
	close(release)

	select {
	case answer := <-answered:
		if answer.err != nil {
			t.Fatalf("the request in flight failed: %v", answer.err)
		}

		if answer.status != http.StatusTeapot {
			t.Errorf("status = %d, want %d", answer.status, http.StatusTeapot)
		}

		if answer.body != "finished" {
			t.Errorf("body = %q, want the whole response", answer.body)
		}
	case <-time.After(settleTimeout):
		t.Fatal("the request in flight was never answered")
	}

	if err := awaitStop(t, stopped); err != nil {
		t.Fatalf("stopping reported an error: %v", err)
	}
}

// A stop that arrives before anything has been served still closes the
// listener and returns, rather than serving on or hanging.
func TestAStopBeforeServingBeginsStillCloses(t *testing.T) {
	listener := openListener(t)
	address := listener.Addr().String()

	ctx, stop := context.WithCancel(t.Context())
	stop()

	stopped := make(chan error, 1)

	go func() {
		stopped <- serveUntilStopped(ctx, quietLogger(), listener, http.NotFoundHandler())
	}()

	if err := awaitStop(t, stopped); err != nil {
		t.Fatalf("stopping reported an error: %v", err)
	}

	if connection, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		_ = connection.Close()

		t.Error("the port still accepts connections after the stop returned")
	}
}

// An address that cannot be bound is reported before anything is served, and
// the report names the address.
func TestAnAddressThatCannotBeListenedOnIsReported(t *testing.T) {
	occupied := openListener(t)
	defer func() { _ = occupied.Close() }()

	address := occupied.Addr().String()

	listener, err := listen(address)
	if err == nil {
		_ = listener.Close()

		t.Fatal("an address already in use was bound")
	}

	if !strings.Contains(err.Error(), address) {
		t.Errorf("the error does not name the address it could not listen on: %v", err)
	}
}

// A listener that fails while it is being served on ends serving with the
// failure, rather than leaving the caller waiting for a stop.
func TestAListenerThatFailsEndsServing(t *testing.T) {
	listener := openListener(t)

	if err := listener.Close(); err != nil {
		t.Fatalf("closing the listener: %v", err)
	}

	stopped := make(chan error, 1)

	go func() {
		stopped <- serveUntilStopped(t.Context(), quietLogger(), listener, http.NotFoundHandler())
	}()

	if err := awaitStop(t, stopped); err == nil {
		t.Fatal("serving on a listener that had failed reported success")
	}
}
