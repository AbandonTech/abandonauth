//go:build integration && !devtools

package web_test

import (
	"io"
	"net/http"
	"sync"
	"testing"
)

// answered is what one request of a set sent together received.
//
// A racing request can be the one that succeeded, so its body carries a
// credential. Decode it and compare it; never format it into a failure message.
type answered struct {
	status   int
	location string
	cookies  []*http.Cookie
	body     []byte
	err      error
}

// cookie returns the cookie the response set, or nil.
func (a answered) cookie(name string) *http.Cookie {
	for _, set := range a.cookies {
		if set.Name == name {
			return set
		}
	}

	return nil
}

// atTheSameMoment sends requests the test has already built, together, and
// returns what each one received.
//
// Building them first keeps the race to the endpoint's own work. Nothing inside
// a goroutine ends the test: a result is carried back and asserted here, where
// stopping is allowed.
func atTheSameMoment(t *testing.T, requests ...*http.Request) []answered {
	t.Helper()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	received := make([]answered, len(requests))
	release := make(chan struct{})

	var running sync.WaitGroup

	for index, request := range requests {
		running.Add(1)

		go func() {
			defer running.Done()

			<-release

			response, err := client.Do(request)
			if err != nil {
				received[index] = answered{err: err}

				return
			}

			defer response.Body.Close()

			body, err := io.ReadAll(response.Body)

			received[index] = answered{
				status:   response.StatusCode,
				location: response.Header.Get("Location"),
				cookies:  response.Cookies(),
				body:     body,
				err:      err,
			}
		}()
	}

	close(release)
	running.Wait()

	for _, answer := range received {
		if answer.err != nil {
			t.Fatalf("a request sent alongside another did not complete: %v", answer.err)
		}
	}

	return received
}
