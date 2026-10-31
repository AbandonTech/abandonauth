package providers

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

const (
	testSteamSite     = "https://Auth.Example.test:8443/"
	testSteamCallback = "https://auth.example.test:8443/api/ui/steam-callback"
	testSteamRealm    = "https://auth.example.test:8443/"
	testSteamState    = "placeholder-login-state"
	testSteamID       = "76561197960287930"
)

// testSteamNow is the clock every Steam test reads, so a nonce's age is exact.
var testSteamNow = time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC)

func newTestSteam(t *testing.T, transport http.RoundTripper) *Steam {
	t.Helper()

	site, err := urlpolicy.ParseOrigin(testSteamSite, urlpolicy.RequireSecureTransport)
	if err != nil {
		t.Fatalf("parsing the site origin: %v", err)
	}

	return NewSteam(site, "/api/ui/steam-callback", transport, func() time.Time { return testSteamNow })
}

// steamAssertion is a positive assertion as Steam returns it for testSteamState,
// with the signature fields filled with placeholders.
func steamAssertion() url.Values {
	return url.Values{
		"state":                 {testSteamState},
		"openid.ns":             {openIDNamespace},
		"openid.mode":           {"id_res"},
		"openid.op_endpoint":    {"https://steamcommunity.com/openid/login"},
		"openid.claimed_id":     {"https://steamcommunity.com/openid/id/" + testSteamID},
		"openid.identity":       {"https://steamcommunity.com/openid/id/" + testSteamID},
		"openid.return_to":      {testSteamCallback + "?state=" + testSteamState},
		"openid.response_nonce": {"2026-10-30T11:59:58Z" + marker},
		"openid.assoc_handle":   {"1234567890"},
		"openid.signed":         {"signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle"},
		"openid.sig":            {marker + "-signature="},
	}
}

func steamAssertionWith(change func(url.Values)) string {
	assertion := steamAssertion()
	change(assertion)

	return assertion.Encode()
}

// expectSteamRefused requires a refusal for exactly the given package-owned
// reason, repeating no value the callback or Steam supplied.
func expectSteamRefused(t *testing.T, err error, reason string) {
	t.Helper()

	if err == nil {
		t.Fatal("Steam's answer was accepted")
	}

	if !errors.Is(err, ErrProviderRefused) {
		t.Errorf("error = %v, want it to wrap ErrProviderRefused", err)
	}

	if want := "identity provider authentication failed: " + reason; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}

	expectNoMarker(t, err)
}

// The realm and return address are the site's origin as a browser sends it,
// whatever spelling the site was given in.
func TestSteamSignInStartsAtSteamsOwnAddress(t *testing.T) {
	t.Parallel()

	address := newTestSteam(t, nil).AuthorizationURL(testSteamState)

	endpoint, query, found := strings.Cut(address, "?")
	if !found || endpoint != "https://steamcommunity.com/openid/login" {
		t.Fatalf("the browser is sent to %q, want Steam's OpenID endpoint", endpoint)
	}

	parameters, err := url.ParseQuery(query)
	if err != nil {
		t.Fatalf("the authorization request is not a query: %v", err)
	}

	want := map[string]string{
		"openid.ns":         "http://specs.openid.net/auth/2.0",
		"openid.mode":       "checkid_setup",
		"openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
		"openid.identity":   "http://specs.openid.net/auth/2.0/identifier_select",
		"openid.realm":      testSteamRealm,
		"openid.return_to":  testSteamCallback + "?state=" + testSteamState,
	}

	if len(parameters) != len(want) {
		t.Errorf("the authorization request carries %d parameters, want %d", len(parameters), len(want))
	}

	for name, value := range want {
		if got := parameters[name]; len(got) != 1 || got[0] != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

// The control for the refusals below: an assertion as Steam returns it for
// this login is read, with the Steam ID it names.
func TestSteamCallbackAsSteamReturnsItIsRead(t *testing.T) {
	t.Parallel()

	callback, err := newTestSteam(t, nil).ReadCallback(steamAssertion().Encode())
	if err != nil {
		t.Fatalf("an assertion as Steam returns it was refused: %v", err)
	}

	if callback.State != testSteamState || callback.Cancelled() || callback.steamID != testSteamID {
		t.Errorf("callback = state %q, cancelled %v, Steam ID %q", callback.State, callback.Cancelled(), callback.steamID)
	}

	if _, carriesState := callback.assertion["state"]; carriesState {
		t.Error("the assertion to be verified carries the login state")
	}

	largest, err := newTestSteam(t, nil).ReadCallback(steamAssertionWith(func(assertion url.Values) {
		claimed := "https://steamcommunity.com/openid/id/18446744073709551615"
		assertion.Set("openid.claimed_id", claimed)
		assertion.Set("openid.identity", claimed)
	}))
	if err != nil {
		t.Fatalf("the largest Steam ID was refused: %v", err)
	}

	if largest.steamID != "18446744073709551615" {
		t.Errorf("Steam ID = %q, want the largest unsigned 64-bit value", largest.steamID)
	}
}

func TestSteamCancellationIsRead(t *testing.T) {
	t.Parallel()

	steam := newTestSteam(t, nil)

	cancellations := map[string]url.Values{
		"bare": {
			"state":       {testSteamState},
			"openid.ns":   {openIDNamespace},
			"openid.mode": {"cancel"},
		},
		"with other fields": {
			"state":              {testSteamState},
			"openid.ns":          {openIDNamespace},
			"openid.mode":        {"cancel"},
			"openid.claimed_id":  {"https://steamcommunity.com/openid/id/" + testSteamID},
			"openid.op_endpoint": {"https://steamcommunity.com/openid/login"},
		},
	}

	for name, cancellation := range cancellations {
		callback, err := steam.ReadCallback(cancellation.Encode())
		if err != nil {
			t.Fatalf("a %s cancellation was refused: %v", name, err)
		}

		if !callback.Cancelled() || callback.State != testSteamState {
			t.Errorf("%s: callback = cancelled %v, state %q", name, callback.Cancelled(), callback.State)
		}

		if _, err := steam.Identify(t.Context(), callback); err == nil {
			t.Errorf("a %s cancellation was identified as a person", name)
		}
	}
}

func TestSteamCallbackIsRefusedBeforeStateOrSteamIsConsulted(t *testing.T) {
	t.Parallel()

	sameNamedBy := func(claimed string) func(url.Values) {
		return func(assertion url.Values) {
			assertion.Set("openid.claimed_id", claimed)
			assertion.Set("openid.identity", claimed)
		}
	}

	const missing = "Steam assertion is missing a field"
	const notSteamID = "Steam assertion claims an identifier Steam does not issue"
	const unsigned = "Steam assertion leaves a field unsigned"
	const malformedNonce = "Steam assertion nonce is malformed"

	tests := map[string]struct {
		query  string
		reason string
	}{
		"malformed encoding": {steamAssertion().Encode() + "&openid.sig=%zz", "malformed Steam callback"},
		"a semicolon separator": {
			steamAssertion().Encode() + ";openid.sig=" + marker, "malformed Steam callback",
		},
		"a repeated state": {
			steamAssertion().Encode() + "&state=" + marker, "Steam callback repeats a parameter",
		},
		"a repeated mode": {
			steamAssertion().Encode() + "&openid.mode=id_res", "Steam callback repeats a parameter",
		},
		"a repeated signature": {
			steamAssertion().Encode() + "&openid.sig=" + marker, "Steam callback repeats a parameter",
		},
		"a repeated signed list": {
			steamAssertion().Encode() + "&openid.signed=signed", "Steam callback repeats a parameter",
		},
		"a repeated association handle": {
			steamAssertion().Encode() + "&openid.assoc_handle=1", "Steam callback repeats a parameter",
		},
		"a repeated claimed identifier": {
			steamAssertion().Encode() + "&openid.claimed_id=" + marker, "Steam callback repeats a parameter",
		},
		"no state": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("state") }),
			"Steam callback carries no state",
		},
		"an empty state": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("state", "") }),
			"Steam callback carries no state",
		},
		"another namespace": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("openid.ns", "http://openid.net/signon/1.1") }),
			"Steam callback is not OpenID 2.0",
		},
		"no namespace": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("openid.ns") }),
			"Steam callback is not OpenID 2.0",
		},
		"another mode": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("openid.mode", "setup_needed") }),
			"Steam callback mode is not supported",
		},
		"no mode": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("openid.mode") }),
			"Steam callback mode is not supported",
		},
		"no signed list": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("openid.signed") }), missing,
		},
		"an empty signed list": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("openid.signed", "") }), missing,
		},
		"no signature": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("openid.sig") }), missing,
		},
		"an empty signature": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("openid.sig", "") }), missing,
		},
		"no association handle": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("openid.assoc_handle") }), missing,
		},
		"an empty association handle": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("openid.assoc_handle", "") }), missing,
		},
		"no return address": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("openid.return_to") }), missing,
		},
		"no nonce": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("openid.response_nonce") }), missing,
		},
		"no identity": {
			steamAssertionWith(func(assertion url.Values) { assertion.Del("openid.identity") }), missing,
		},
		"another provider endpoint": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.op_endpoint", "https://"+marker+".example.test/openid/login")
			}),
			"Steam assertion names another provider endpoint",
		},
		"Steam's endpoint over plain HTTP": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.op_endpoint", "http://steamcommunity.com/openid/login")
			}),
			"Steam assertion names another provider endpoint",
		},
		"a return address for another login": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.return_to", testSteamCallback+"?state="+marker)
			}),
			"Steam assertion was returned for another login",
		},
		"a state other than the signed one": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("state", marker) }),
			"Steam assertion was returned for another login",
		},
		"a return address on another origin": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.return_to", "https://"+marker+".example.test/api/ui/steam-callback?state="+testSteamState)
			}),
			"Steam assertion was returned for another login",
		},
		"a return address with more appended": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.return_to", testSteamCallback+"?state="+testSteamState+"&"+marker+"=1")
			}),
			"Steam assertion was returned for another login",
		},
		"an identity other than the claimed identifier": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.identity", "https://steamcommunity.com/openid/id/76561197960287931")
			}),
			"Steam assertion identity differs from its claimed identifier",
		},
		"another host":       {steamAssertionWith(sameNamedBy("https://" + marker + ".example.test/openid/id/" + testSteamID)), notSteamID},
		"plain HTTP":         {steamAssertionWith(sameNamedBy("http://steamcommunity.com/openid/id/" + testSteamID)), notSteamID},
		"an upper-case host": {steamAssertionWith(sameNamedBy("https://SteamCommunity.com/openid/id/" + testSteamID)), notSteamID},
		"another prefix":     {steamAssertionWith(sameNamedBy("https://steamcommunity.com/id/" + testSteamID)), notSteamID},
		"a query":            {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/" + testSteamID + "?x=1")), notSteamID},
		"a fragment":         {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/" + testSteamID + "#x")), notSteamID},
		"a path suffix":      {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/" + testSteamID + "/")), notSteamID},
		"whitespace":         {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/ " + testSteamID)), notSteamID},
		"a sign":             {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/+" + testSteamID)), notSteamID},
		"a leading zero":     {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/0" + testSteamID)), notSteamID},
		"zero":               {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/0")), notSteamID},
		"no Steam ID":        {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/")), notSteamID},
		"an overflowing Steam ID": {
			steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/18446744073709551616")), notSteamID,
		},
		"a malformed Steam ID": {steamAssertionWith(sameNamedBy("https://steamcommunity.com/openid/id/7656119796028793a")), notSteamID},
		"an unsigned return address": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.signed", "op_endpoint,claimed_id,identity,response_nonce,assoc_handle")
			}),
			unsigned,
		},
		"an unsigned claimed identifier": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.signed", "op_endpoint,identity,return_to,response_nonce")
			}),
			unsigned,
		},
		"an unsigned identity": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.signed", "op_endpoint,claimed_id,return_to,response_nonce")
			}),
			unsigned,
		},
		"an unsigned endpoint": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.signed", "claimed_id,identity,return_to,response_nonce")
			}),
			unsigned,
		},
		"an unsigned nonce": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.signed", "op_endpoint,claimed_id,identity,return_to")
			}),
			unsigned,
		},
		"a nonce with no timestamp": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("openid.response_nonce", marker) }),
			malformedNonce,
		},
		"a nonce with its timestamp embedded": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.response_nonce", marker+"2026-10-30T11:59:58Z"+marker)
			}),
			malformedNonce,
		},
		"a nonce with a numeric offset": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.response_nonce", "2026-10-30T11:59:58+00:00"+marker)
			}),
			malformedNonce,
		},
		"a nonce with a lower-case zone": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.response_nonce", "2026-10-30T11:59:58z"+marker)
			}),
			malformedNonce,
		},
		"a nonce with no uniqueness value": {
			steamAssertionWith(func(assertion url.Values) { assertion.Set("openid.response_nonce", "2026-10-30T11:59:58Z") }),
			malformedNonce,
		},
		"a nonce with an empty fraction": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.response_nonce", "2026-10-30T11:59:58.Z"+marker)
			}),
			malformedNonce,
		},
		"a nonce with ten fraction digits": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.response_nonce", "2026-10-30T11:59:58.0123456789Z"+marker)
			}),
			malformedNonce,
		},
		"a nonce on a day that does not exist": {
			steamAssertionWith(func(assertion url.Values) {
				assertion.Set("openid.response_nonce", "2026-02-30T11:59:58Z"+marker)
			}),
			malformedNonce,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := newTestSteam(t, nil).ReadCallback(test.query)
			expectSteamRefused(t, err, test.reason)
		})
	}
}

func TestSteamNonceMustBeFresh(t *testing.T) {
	t.Parallel()

	withNonce := func(issued time.Time, layout string) string {
		return steamAssertionWith(func(assertion url.Values) {
			assertion.Set("openid.response_nonce", issued.Format(layout)+marker)
		})
	}

	const whole = "2006-01-02T15:04:05Z"

	oldest := testSteamNow.Add(-(oauth.StateLifetime + 30*time.Second))
	latest := testSteamNow.Add(30 * time.Second)

	accepted := map[string]string{
		"issued now":                    withNonce(testSteamNow, whole),
		"the oldest a login allows":     withNonce(oldest, whole),
		"the furthest the clock allows": withNonce(latest, whole),
		"with fractional seconds":       withNonce(testSteamNow.Add(-1500*time.Millisecond), time.RFC3339Nano),
	}

	for name, query := range accepted {
		if _, err := newTestSteam(t, nil).ReadCallback(query); err != nil {
			t.Errorf("a nonce %s was refused: %v", name, err)
		}
	}

	_, err := newTestSteam(t, nil).ReadCallback(withNonce(oldest.Add(-time.Second), whole))
	expectSteamRefused(t, err, "Steam assertion nonce has expired")

	_, err = newTestSteam(t, nil).ReadCallback(withNonce(oldest.Add(-time.Millisecond), time.RFC3339Nano))
	expectSteamRefused(t, err, "Steam assertion nonce has expired")

	_, err = newTestSteam(t, nil).ReadCallback(withNonce(latest.Add(time.Second), whole))
	expectSteamRefused(t, err, "Steam assertion nonce is from the future")
}

// readTestCallback is the callback a Steam test verifies.
func readTestCallback(t *testing.T, steam *Steam) SteamCallback {
	t.Helper()

	callback, err := steam.ReadCallback(steamAssertion().Encode())
	if err != nil {
		t.Fatalf("reading the callback: %v", err)
	}

	return callback
}

func steamAnswer(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

const positiveVerification = "ns:http://specs.openid.net/auth/2.0\nis_valid:true\n"

// Steam is asked at its own fixed HTTPS address, by a form carrying exactly the
// assertion's fields with the mode changed, and its yes names the person.
func TestSteamIsAskedToVerifyAssertionAtItsOwnAddress(t *testing.T) {
	t.Parallel()

	var asked []*http.Request

	var form url.Values

	steam := newTestSteam(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		asked = append(asked, request)

		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}

		form, err = url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}

		return steamAnswer(http.StatusOK, positiveVerification), nil
	}))

	identity, err := steam.Identify(t.Context(), readTestCallback(t, steam))
	if err != nil {
		t.Fatalf("an assertion Steam verified was refused: %v", err)
	}

	if identity.Provider != oauth.Steam || identity.ID != testSteamID || identity.Username != "steam:"+testSteamID {
		t.Errorf("identity = %+v, want the Steam ID and its steam: username", identity)
	}

	if len(asked) != 1 {
		t.Fatalf("Steam was asked %d times, want once", len(asked))
	}

	request := asked[0]

	if request.Method != http.MethodPost || request.URL.String() != "https://steamcommunity.com/openid/login" {
		t.Errorf("Steam was asked with %s %s", request.Method, request.URL)
	}

	if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", request.Header.Get("Content-Type"))
	}

	want := steamAssertion()
	want.Del("state")
	want.Set("openid.mode", "check_authentication")

	if form.Encode() != want.Encode() {
		t.Errorf("Steam was sent %v, want %v", form, want)
	}
}

// Steam may sign fields beyond the ones that bind a login, such as an OpenID
// extension. They are accepted and sent back to Steam with the rest, because
// Steam checks its signature over every field it signed. Parameters outside
// OpenID are not sent.
func TestSteamExtensionFieldsAreSentBackForVerification(t *testing.T) {
	t.Parallel()

	var form url.Values

	steam := newTestSteam(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}

		form, err = url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}

		return steamAnswer(http.StatusOK, positiveVerification), nil
	}))

	extended := steamAssertion()
	extended.Set("openid.ns.sreg", "http://openid.net/extensions/sreg/1.1")
	extended.Set("openid.sreg.nickname", "placeholder")
	extended.Set("openid.signed", extended.Get("openid.signed")+",ns.sreg,sreg.nickname")
	extended.Set("utm_source", "placeholder")

	callback, err := steam.ReadCallback(extended.Encode())
	if err != nil {
		t.Fatalf("an assertion with an extension was refused: %v", err)
	}

	if _, err := steam.Identify(t.Context(), callback); err != nil {
		t.Fatalf("an assertion with an extension Steam verified was refused: %v", err)
	}

	want := extended
	want.Del("state")
	want.Del("utm_source")
	want.Set("openid.mode", "check_authentication")

	if form.Encode() != want.Encode() {
		t.Errorf("Steam was sent %v, want %v", form, want)
	}
}

func TestSteamVerificationIsRefusedUnlessSteamSaysExactlyYes(t *testing.T) {
	t.Parallel()

	const refusedAnswer = "Steam did not verify the assertion"
	const malformedAnswer = "the Steam verification answer is malformed"
	const repeatedAnswer = "the Steam verification answer repeats a field"
	const namespace = "the Steam verification answer is not OpenID 2.0"

	tests := map[string]struct {
		response *http.Response
		reason   string
	}{
		"is_valid false": {
			steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\nis_valid:false\n"), refusedAnswer,
		},
		"is_valid in capitals": {
			steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\nis_valid:TRUE\n"), refusedAnswer,
		},
		"is_valid with a carriage return": {
			steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\r\nis_valid:true\r\n"), namespace,
		},
		"is_valid with whitespace": {
			steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\nis_valid: true\n"), refusedAnswer,
		},
		"no is_valid":  {steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\n"), refusedAnswer},
		"no namespace": {steamAnswer(http.StatusOK, "is_valid:true\n"), namespace},
		"another namespace": {
			steamAnswer(http.StatusOK, "ns:http://openid.net/signon/1.1\nis_valid:true\n"), namespace,
		},
		"is_valid repeated": {
			steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\nis_valid:false\nis_valid:true\n"),
			repeatedAnswer,
		},
		"the namespace repeated": {
			steamAnswer(http.StatusOK, positiveVerification+"ns:http://specs.openid.net/auth/2.0\n"), repeatedAnswer,
		},
		"a line without a separator": {
			steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\n"+marker+"\nis_valid:true\n"),
			malformedAnswer,
		},
		"an empty line": {
			steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\n\nis_valid:true\n"), malformedAnswer,
		},
		"a line with no key": {
			steamAnswer(http.StatusOK, "ns:http://specs.openid.net/auth/2.0\n:"+marker+"\nis_valid:true\n"),
			malformedAnswer,
		},
		"an empty answer": {steamAnswer(http.StatusOK, ""), malformedAnswer},
		"JSON":            {steamAnswer(http.StatusOK, `{"is_valid":true,"`+marker+`":1}`), namespace},
		"an oversized answer": {
			steamAnswer(http.StatusOK, positiveVerification+strings.Repeat("a", maxResponseBytes)),
			"the Steam verification answer is larger than this service will read",
		},
		"a refusal status": {
			steamAnswer(http.StatusBadRequest, positiveVerification), "Steam answered with status 400",
		},
		"a server failure": {
			steamAnswer(http.StatusInternalServerError, marker), "Steam answered with status 500",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			steam := newTestSteam(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return test.response, nil
			}))

			_, err := steam.Identify(t.Context(), readTestCallback(t, steam))
			expectSteamRefused(t, err, test.reason)
		})
	}
}

// A redirect from Steam is an answer in its own right, never followed: following
// it would send the assertion wherever the answer named.
func TestSteamRedirectIsRefusedAndNotFollowed(t *testing.T) {
	t.Parallel()

	var asked atomic.Int32

	steam := newTestSteam(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		asked.Add(1)

		redirect := steamAnswer(http.StatusFound, "")
		redirect.Header.Set("Location", "https://"+marker+".example.test/openid/login")

		return redirect, nil
	}))

	_, err := steam.Identify(t.Context(), readTestCallback(t, steam))
	expectSteamRefused(t, err, "Steam answered with status 302")

	if asked.Load() != 1 {
		t.Errorf("%d requests were made, want only the one to Steam", asked.Load())
	}
}

func TestSteamThatCannotBeReachedIsRefusal(t *testing.T) {
	t.Parallel()

	unreachable := newTestSteam(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("placeholder transport failure " + marker)
	}))

	_, err := unreachable.Identify(t.Context(), readTestCallback(t, unreachable))
	expectSteamRefused(t, err, "Steam could not be reached")

	stalled := newTestSteam(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()

		return nil, request.Context().Err()
	}))

	if stalled.client.Timeout != requestTimeout {
		t.Errorf("the Steam client's deadline is %v, want %v", stalled.client.Timeout, requestTimeout)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, err = stalled.Identify(ctx, readTestCallback(t, stalled))
	expectSteamRefused(t, err, "Steam could not be reached")
}
