// Package providers talks to the identity providers a person can sign in with.
//
// Every request leaves with a deadline, comes back through a client that will
// not follow a redirect, and is read only up to a fixed number of bytes, so a
// provider that is slow, that points somewhere else, or that answers with
// something enormous cannot hold or exhaust this service.
//
// The addresses of the real providers are constants. A test supplies its own
// through the constructor; nothing at runtime can move a provider somewhere
// else, so a configuration mistake cannot send an authorization code to a host
// of someone else's choosing.
package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// requestTimeout bounds one exchange with a provider, including reading its
// answer. A person is waiting on the redirect, so a provider that stalls fails
// the login rather than holding the request open.
const requestTimeout = 10 * time.Second

// maxResponseBytes bounds what is read from a provider. Every answer this
// service reads is a small JSON object.
const maxResponseBytes = 64 << 10

// ErrProviderRefused reports that a provider did not complete the exchange.
//
// It carries no detail from the provider: the body of a failed token exchange
// can quote the authorization code that was sent.
var ErrProviderRefused = errors.New("the identity provider did not complete the sign-in")

// ErrUnusableIdentity reports that a provider answered with a person this
// service cannot record.
var ErrUnusableIdentity = errors.New("the identity provider described this person in a way this service cannot use")

// newHTTPClient builds the client every provider call goes through.
//
// Redirects are returned rather than followed. A redirect from a token endpoint
// would otherwise send the client credentials, or an authorization code, to
// whatever host the answer named.
func newHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// postForm sends a form-encoded request and decodes a JSON answer.
func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values, into any) error {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()),
	)
	if err != nil {
		return fmt.Errorf("%w: the request could not be built", ErrProviderRefused)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	return send(client, request, into)
}

// get sends a request that reads something from a provider, optionally with an
// access token.
func get(ctx context.Context, client *http.Client, endpoint, accessToken string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: the request could not be built", ErrProviderRefused)
	}

	request.Header.Set("Accept", "application/json")

	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}

	return send(client, request, into)
}

func send(client *http.Client, request *http.Request, into any) error {
	response, err := client.Do(request)
	if err != nil {
		// The transport error can quote the request URL, which for a token
		// exchange carries no secret in the query but for a redirect might.
		return fmt.Errorf("%w: it could not be reached", ErrProviderRefused)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: it answered with status %d", ErrProviderRefused, response.StatusCode)
	}

	if err := requireJSON(response.Header.Get("Content-Type")); err != nil {
		return err
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: its answer could not be read", ErrProviderRefused)
	}

	if len(body) > maxResponseBytes {
		return fmt.Errorf("%w: its answer is larger than this service will read", ErrProviderRefused)
	}

	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%w: its answer is not the expected shape", ErrProviderRefused)
	}

	return nil
}

// requireJSON refuses an answer that is not JSON, so a login page or an error
// page served in place of an API answer is not parsed as one.
func requireJSON(contentType string) error {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("%w: its answer does not say what it is", ErrProviderRefused)
	}

	if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
		return fmt.Errorf("%w: its answer is not JSON", ErrProviderRefused)
	}

	return nil
}

// requireHTTPS refuses an address that is not an absolute https URL, which is
// how an injected test endpoint is kept from being mistaken for a real one and
// how a discovery document is kept from moving this service to plain HTTP.
func requireHTTPS(address string) error {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%w: it named an address this service will not use", ErrProviderRefused)
	}

	return nil
}
