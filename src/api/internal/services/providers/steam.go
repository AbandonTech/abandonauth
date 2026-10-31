package providers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
)

// Where Steam is reached, and how it names a person. These are constants, and
// no constructor accepts another address, so neither a setting nor a test can
// move an assertion's verification to another host.
const (
	steamEndpoint        = "https://steamcommunity.com/openid/login"
	steamClaimedIDPrefix = "https://steamcommunity.com/openid/id/"
)

// The OpenID 2.0 values a Steam sign-in uses.
const (
	openIDNamespace        = "http://specs.openid.net/auth/2.0"
	openIDIdentifierSelect = "http://specs.openid.net/auth/2.0/identifier_select"
	openIDFieldPrefix      = "openid."
	steamStateParameter    = "state"
)

// How far a response nonce's timestamp may be from this service's clock. The
// oldest acceptable one was issued no earlier than the login it answers began.
const (
	steamNonceClockSkew = 30 * time.Second
	steamNonceMaxAge    = oauth.StateLifetime + steamNonceClockSkew
)

// steamRequiredFields are the fields a positive assertion must carry, each
// non-empty.
var steamRequiredFields = []string{
	"ns", "mode", "op_endpoint", "claimed_id", "identity", "return_to",
	"response_nonce", "assoc_handle", "signed", "sig",
}

// steamRequiredSignatures are the fields Steam's signature must cover, which
// are the ones that say who the person is and which login the answer is for.
var steamRequiredSignatures = []string{"op_endpoint", "claimed_id", "identity", "return_to", "response_nonce"}

// steamNonceTimestamp is the leading UTC timestamp of a response nonce.
var steamNonceTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z`)

// Steam signs a person in with their Steam account, through OpenID 2.0.
//
// An assertion is accepted only once its binding to this login has been checked
// here and Steam itself has confirmed, over HTTPS, that it signed it.
type Steam struct {
	callback string
	realm    string
	client   *http.Client
	now      func() time.Time
}

// NewSteam builds the client for a site, which Steam returns browsers to at
// callbackPath. The transport and clock are for tests; the address is always
// Steam's own.
func NewSteam(site urlpolicy.Origin, callbackPath string, transport http.RoundTripper, now func() time.Time) *Steam {
	if now == nil {
		now = time.Now
	}

	return &Steam{
		callback: site.String() + callbackPath,
		realm:    site.String() + "/",
		client:   newHTTPClient(transport),
		now:      now,
	}
}

// AuthorizationURL is where a browser is sent to start a sign-in. Steam returns
// it to the callback with the state appended, and signs that address.
func (s *Steam) AuthorizationURL(state string) string {
	return authorizationURL(steamEndpoint, url.Values{
		"openid.ns":         {openIDNamespace},
		"openid.mode":       {"checkid_setup"},
		"openid.claimed_id": {openIDIdentifierSelect},
		"openid.identity":   {openIDIdentifierSelect},
		"openid.realm":      {s.realm},
		"openid.return_to":  {s.returnTo(state)},
	})
}

// returnTo is the address a login's assertion must be signed for: the callback
// with the state appended.
func (s *Steam) returnTo(state string) string {
	return s.callback + "?" + url.Values{steamStateParameter: {state}}.Encode()
}

// SteamCallback is a browser's return from Steam that has passed every check
// needing neither the login state nor Steam.
type SteamCallback struct {
	// State is the login state the browser returned with.
	State string

	cancelled bool
	assertion url.Values
	steamID   string
}

// Cancelled reports a person who declined at Steam, or whom Steam sent back
// without signing them in.
func (c SteamCallback) Cancelled() bool {
	return c.cancelled
}

// ReadCallback reads the query a browser returned from Steam with.
//
// Nothing here depends on the login state or on Steam, so a callback refused
// here has spent no login and caused no request. A positive assertion must name
// Steam's endpoint, be signed over the fields that bind it, be returned for
// exactly this login's address, name a canonical Steam ID, and be fresh.
func (s *Steam) ReadCallback(rawQuery string) (SteamCallback, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return SteamCallback{}, refused("malformed Steam callback")
	}

	// Steam's signature covers one value per field, so a repeated parameter
	// leaves which value it signed ambiguous.
	for _, given := range values {
		if len(given) != 1 {
			return SteamCallback{}, refused("Steam callback repeats a parameter")
		}
	}

	state := values.Get(steamStateParameter)
	if state == "" {
		return SteamCallback{}, refused("Steam callback carries no state")
	}

	if values.Get("openid.ns") != openIDNamespace {
		return SteamCallback{}, refused("Steam callback is not OpenID 2.0")
	}

	switch values.Get("openid.mode") {
	case "cancel":
		return SteamCallback{State: state, cancelled: true}, nil
	case "id_res":
		return s.readAssertion(state, values)
	default:
		return SteamCallback{}, refused("Steam callback mode is not supported")
	}
}

func (s *Steam) readAssertion(state string, values url.Values) (SteamCallback, error) {
	assertion := make(url.Values)

	for key, value := range values {
		if strings.HasPrefix(key, openIDFieldPrefix) {
			assertion[key] = value
		}
	}

	for _, field := range steamRequiredFields {
		if assertion.Get(openIDFieldPrefix+field) == "" {
			return SteamCallback{}, refused("Steam assertion is missing a field")
		}
	}

	if assertion.Get("openid.op_endpoint") != steamEndpoint {
		return SteamCallback{}, refused("Steam assertion names another provider endpoint")
	}

	if assertion.Get("openid.return_to") != s.returnTo(state) {
		return SteamCallback{}, refused("Steam assertion was returned for another login")
	}

	claimed := assertion.Get("openid.claimed_id")
	if assertion.Get("openid.identity") != claimed {
		return SteamCallback{}, refused("Steam assertion identity differs from its claimed identifier")
	}

	steamID, err := steamIDFrom(claimed)
	if err != nil {
		return SteamCallback{}, err
	}

	if err := requireSteamSignatureCoverage(assertion.Get("openid.signed")); err != nil {
		return SteamCallback{}, err
	}

	if err := s.requireFreshNonce(assertion.Get("openid.response_nonce")); err != nil {
		return SteamCallback{}, err
	}

	return SteamCallback{State: state, assertion: assertion, steamID: steamID}, nil
}

// steamIDFrom reads the Steam ID from Steam's claimed identifier, which is its
// fixed prefix followed by the ID's canonical decimal spelling and nothing else.
func steamIDFrom(claimed string) (string, error) {
	digits, found := strings.CutPrefix(claimed, steamClaimedIDPrefix)
	if !found {
		return "", refused("Steam assertion claims an identifier Steam does not issue")
	}

	number, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || number == 0 || strconv.FormatUint(number, 10) != digits {
		return "", refused("Steam assertion claims an identifier Steam does not issue")
	}

	return digits, nil
}

// requireSteamSignatureCoverage refuses a signed-field list that leaves a
// binding field unsigned.
func requireSteamSignatureCoverage(list string) error {
	signed := make(map[string]bool)
	for _, field := range strings.Split(list, ",") {
		signed[field] = true
	}

	for _, field := range steamRequiredSignatures {
		if !signed[field] {
			return refused("Steam assertion leaves a field unsigned")
		}
	}

	return nil
}

// requireFreshNonce refuses a response nonce that does not begin with a UTC
// timestamp followed by a uniqueness value, or whose timestamp is from the
// future or older than the login it could answer.
func (s *Steam) requireFreshNonce(nonce string) error {
	stamp := steamNonceTimestamp.FindString(nonce)
	if stamp == "" || len(stamp) == len(nonce) {
		return refused("Steam assertion nonce is malformed")
	}

	issued, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return refused("Steam assertion nonce is malformed")
	}

	now := s.now().UTC()

	if issued.After(now.Add(steamNonceClockSkew)) {
		return refused("Steam assertion nonce is from the future")
	}

	if issued.Before(now.Add(-steamNonceMaxAge)) {
		return refused("Steam assertion nonce has expired")
	}

	return nil
}

// Identify asks Steam to confirm it signed the assertion a callback carried,
// and returns the person it names.
//
// The browser's copy of the assertion proves nothing on its own: Steam is asked
// directly, at its fixed HTTPS address.
func (s *Steam) Identify(ctx context.Context, callback SteamCallback) (accounts.Identity, error) {
	if callback.cancelled || callback.steamID == "" || len(callback.assertion) == 0 {
		return accounts.Identity{}, refused("Steam callback carries no assertion")
	}

	if err := s.verify(ctx, callback.assertion); err != nil {
		return accounts.Identity{}, err
	}

	return accounts.Identity{
		Provider: oauth.Steam,
		ID:       callback.steamID,
		Username: "steam:" + callback.steamID,
	}, nil
}

// verify sends Steam every OpenID field of the assertion, with only the mode
// changed, and requires Steam's answer to say that the assertion is valid.
func (s *Steam) verify(ctx context.Context, assertion url.Values) error {
	form := make(url.Values, len(assertion))
	for field, value := range assertion {
		form[field] = []string{value[0]}
	}

	form.Set("openid.mode", "check_authentication")

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, steamEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return refused("the Steam verification could not be built")
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := s.client.Do(request)
	if err != nil {
		return refused("Steam could not be reached")
	}

	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: Steam answered with status %d", ErrProviderRefused, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return refused("the Steam verification answer could not be read")
	}

	if len(body) > maxResponseBytes {
		return refused("the Steam verification answer is larger than this service will read")
	}

	return requirePositiveVerification(body)
}

// requirePositiveVerification reads Steam's answer as OpenID key-value form:
// one key and value per line, separated by the first colon. A malformed or
// repeated line refuses the whole answer, and only one OpenID 2.0 namespace and
// one is_valid of exactly true accept it.
func requirePositiveVerification(body []byte) error {
	text := strings.TrimSuffix(string(body), "\n")
	if text == "" {
		return refused("the Steam verification answer is malformed")
	}

	fields := make(map[string]string)

	for _, line := range strings.Split(text, "\n") {
		key, value, separated := strings.Cut(line, ":")
		if !separated || key == "" {
			return refused("the Steam verification answer is malformed")
		}

		if _, repeated := fields[key]; repeated {
			return refused("the Steam verification answer repeats a field")
		}

		fields[key] = value
	}

	if fields["ns"] != openIDNamespace {
		return refused("the Steam verification answer is not OpenID 2.0")
	}

	if fields["is_valid"] != "true" {
		return refused("Steam did not verify the assertion")
	}

	return nil
}
