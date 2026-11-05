//go:build integration && !devtools

package web_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// publicProtocolPermits is how many public-protocol requests one worker
// serves at once, as the service promises it.
const publicProtocolPermits = 64

type roundTripper func(*http.Request) (*http.Response, error)

func (r roundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return r(request) }

// providerGate holds provider requests open while it is closed, and counts
// them, so a test can keep provider callbacks in progress on purpose.
type providerGate struct {
	mutex   sync.Mutex
	holding bool
	held    int
	entered chan struct{}
	opened  chan struct{}
}

func newProviderGate() *providerGate {
	return &providerGate{entered: make(chan struct{}, 4*publicProtocolPermits), opened: make(chan struct{})}
}

func (g *providerGate) wrap(next http.RoundTripper) http.RoundTripper {
	return roundTripper(func(request *http.Request) (*http.Response, error) {
		g.mutex.Lock()
		holding := g.holding

		if holding {
			g.held++
		}
		g.mutex.Unlock()

		if holding {
			g.entered <- struct{}{}
			<-g.opened
		}

		return next.RoundTrip(request)
	})
}

func (g *providerGate) requests() int {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	return g.held
}

// heldCallbacks are provider callbacks kept in progress at the provider.
type heldCallbacks struct {
	gate     *providerGate
	finished sync.WaitGroup
}

// hold starts count of the site's own sign-ins and keeps every one of their
// callbacks waiting at the provider, each holding a permit.
func (g *providerGate) hold(t *testing.T, service *servertest.Service, count int) *heldCallbacks {
	t.Helper()

	type returning struct{ code, state string }

	callbacks := make([]returning, 0, count)

	for range count {
		started := service.StartLogin(oauth.Discord, service.Site.ApplicationID, service.Site.CallbackURI)
		callbacks = append(callbacks, returning{
			code:  service.Providers.Issue(oauth.Discord, providerGrant(service, started)),
			state: started.State,
		})
	}

	g.mutex.Lock()
	g.holding = true
	g.mutex.Unlock()

	held := &heldCallbacks{gate: g}

	for _, callback := range callbacks {
		held.finished.Add(1)

		go func() {
			defer held.finished.Done()

			service.ReturnFromProvider(oauth.Discord, callback.code, callback.state)
		}()
	}

	for range count {
		<-g.entered
	}

	return held
}

func (h *heldCallbacks) release() {
	h.gate.mutex.Lock()
	h.gate.holding = false
	h.gate.mutex.Unlock()

	close(h.gate.opened)
	h.finished.Wait()
}

func providerGrant(service *servertest.Service, started servertest.Authorization) providertest.Grant {
	return providertest.Grant{
		Identity:  service.Providers.Someone(started.Provider, "someone"),
		Challenge: started.Challenge,
		Nonce:     started.Nonce,
		ReturnTo:  started.ReturnTo,
	}
}

// When every permit is in use, a public client's provider callback is refused
// before its state is consumed or its provider is asked anything, and the very
// same callback succeeds once a permit is free. Every other public-protocol
// endpoint refuses at once in its own terms.
func TestPublicProtocolRefusesAtOnceAndRecovers(t *testing.T) {
	t.Parallel()

	gate := newProviderGate()
	service := servertest.New(t, servertest.WithProviderTransportWrapped(gate.wrap))
	_, client := installedClient(t, service)

	pending := client.Pending(ipv4Template, 49152, "openid")
	started := client.BeginPublicSignIn(pending, oauth.Discord)
	code := service.Providers.Issue(oauth.Discord, providerGrant(service, started))

	deciding := client.Pending(ipv4Template, 49153, "openid")
	consent := client.ReachConsent(deciding, oauth.Discord, service.Providers.Someone(oauth.Discord, "someone deciding"))

	cancelling := client.Pending(ipv4Template, 49154, "openid")
	declined := client.ReachConsent(cancelling, oauth.Discord, service.Providers.Someone(oauth.Discord, "someone declining"))

	held := gate.hold(t, service, publicProtocolPermits)

	refused := service.ReturnFromProvider(oauth.Discord, code, started.State).
		ExpectStatus(http.StatusServiceUnavailable).
		ExpectDetail("Service temporarily unavailable")

	if refused.Header.Get("Location") != "" || gate.requests() != publicProtocolPermits {
		t.Error("a refused callback was redirected or asked the provider something")
	}

	expectOAuthError(t, service.POSTForm("/oauth/token", "grant_type=authorization_code"),
		http.StatusServiceUnavailable, "temporarily_unavailable")
	expectOAuthError(t, service.GET("/oauth/userinfo", servertest.Bearer(strings.Repeat("a.b.", 2000))),
		http.StatusServiceUnavailable, "temporarily_unavailable")
	expectOAuthError(t, service.POSTForm("/oauth/revoke", "token=x"),
		http.StatusServiceUnavailable, "temporarily_unavailable")

	overloaded := client.Authorize(client.Pending(ipv4Template, 1, "openid"))
	expectOAuthError(t, overloaded, http.StatusServiceUnavailable, "temporarily_unavailable")
	expectPageHeaders(t, overloaded)

	service.GET("/oauth/authorization/" + strings.Repeat("A", 43)).
		ExpectStatus(http.StatusServiceUnavailable).
		ExpectDetail("Service temporarily unavailable")

	for what, refusal := range map[string]*servertest.Response{
		"reading a consent":    service.GET("/oauth/consent/" + consent),
		"allowing a consent":   service.AllowConsent(consent),
		"cancelling a consent": service.CancelConsent(consent),
	} {
		t.Run(what, func(t *testing.T) {
			refusal.ExpectStatus(http.StatusServiceUnavailable).ExpectDetail("Service temporarily unavailable")
			expectPageHeaders(t, refusal)

			if refusal.Header.Get("Location") != "" {
				t.Error("an overloaded consent answer was redirected")
			}
		})
	}

	held.release()

	returned := service.ReturnFromProvider(oauth.Discord, code, started.State).ExpectStatus(http.StatusSeeOther)
	handle := service.ConsentHandle(returned)
	allowed := service.AllowConsent(handle).ExpectStatus(http.StatusSeeOther)

	answer, err := pending.Read(allowed.Header.Get("Location"), servertest.OpenIDIssuer)
	if err != nil || answer.Code == "" {
		t.Fatalf("the retried callback did not lead to a code: %v %+v", err, answer)
	}

	client.Exchange(pending, answer.Code).ExpectStatus(http.StatusOK)

	// Overload consumed nothing, so both refused consents can still be answered.
	service.GET("/oauth/consent/" + consent).ExpectStatus(http.StatusOK)

	retried := service.AllowConsent(consent).ExpectStatus(http.StatusSeeOther)
	if retriedAnswer, err := deciding.Read(retried.Header.Get("Location"), servertest.OpenIDIssuer); err != nil ||
		retriedAnswer.Code == "" {
		t.Errorf("the retried approval did not return a code: %v %+v", err, retriedAnswer)
	}

	cancelled := service.CancelConsent(declined).ExpectStatus(http.StatusSeeOther)
	if cancelledAnswer, err := cancelling.Read(cancelled.Header.Get("Location"), servertest.OpenIDIssuer); err != nil ||
		cancelledAnswer.Error != "access_denied" {
		t.Errorf("the retried cancellation did not tell the client: %v %+v", err, cancelledAnswer)
	}
}

// Steam's callback is admitted before its assertion is even read, so a Steam
// callback refused for want of a permit has asked Steam nothing and can be
// retried.
func TestSteamCallbackIsAdmittedBeforeItsAssertionIsRead(t *testing.T) {
	t.Parallel()

	gate := newProviderGate()
	service := servertest.New(t, servertest.WithProviderTransportWrapped(gate.wrap))
	_, client := installedClient(t, service)

	pending := client.Pending(ipv4Template, 49152, "openid")
	started := client.BeginPublicSignIn(pending, oauth.Steam)
	assertion := service.Providers.Issue(oauth.Steam, providerGrant(service, started))

	held := gate.hold(t, service, publicProtocolPermits)

	service.ReturnFromProvider(oauth.Steam, assertion, started.State).
		ExpectStatus(http.StatusServiceUnavailable)

	if verified := service.Providers.SteamVerifications(); verified != 0 {
		t.Errorf("Steam was asked to verify %d assertions while no permit was free", verified)
	}

	held.release()

	service.ConsentHandle(service.ReturnFromProvider(oauth.Steam, assertion, started.State))
}
