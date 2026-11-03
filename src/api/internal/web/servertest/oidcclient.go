package servertest

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
)

// InstalledClient is a public client as a test drives it. It is test support
// that exercises the server's contract, never a client library: it holds only
// what an installed application holds, and nothing it does is shipped.
type InstalledClient struct {
	service  *Service
	ClientID uuid.UUID
}

// PendingAuthorization is what an installed client remembers between opening
// the browser and its loopback listener answering.
type PendingAuthorization struct {
	RedirectURI string
	Scope       string
	State       string
	Nonce       string
	Verifier    string
	Challenge   string
}

// InstalledClient drives a registered public client.
func (s *Service) InstalledClient(application Application) *InstalledClient {
	return &InstalledClient{service: s, ClientID: application.ID}
}

// Pending draws a fresh state, nonce and verifier for an authorization that
// is to be returned to a template with a port the client chose.
func (c *InstalledClient) Pending(template string, port int, scope string) PendingAuthorization {
	c.service.t.Helper()

	verifier := c.random()
	digest := sha256.Sum256([]byte(verifier))

	return PendingAuthorization{
		RedirectURI: WithPort(template, port),
		Scope:       scope,
		State:       c.random(),
		Nonce:       c.random(),
		Verifier:    verifier,
		Challenge:   base64.RawURLEncoding.EncodeToString(digest[:]),
	}
}

// WithPort inserts a port after a portless loopback template's address.
func WithPort(template string, port int) string {
	rest := strings.TrimPrefix(template, "http://")

	host, path, _ := strings.Cut(rest, "/")

	return "http://" + host + ":" + strconv.Itoa(port) + "/" + path
}

// Parameters are the authorization request this pending authorization makes.
func (p PendingAuthorization) Parameters(clientID uuid.UUID) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID.String()},
		"redirect_uri":          {p.RedirectURI},
		"scope":                 {p.Scope},
		"state":                 {p.State},
		"nonce":                 {p.Nonce},
		"code_challenge":        {p.Challenge},
		"code_challenge_method": {"S256"},
	}
}

// Authorize opens the browser at the authorization endpoint.
func (c *InstalledClient) Authorize(pending PendingAuthorization, prepare ...func(*http.Request)) *Response {
	c.service.t.Helper()

	return c.service.GET("/oauth/authorize?"+pending.Parameters(c.ClientID).Encode(), prepare...)
}

// PageHandle reads the handle from where a successful authorization sent the
// browser, which must be exactly the site's authorization page.
func (s *Service) PageHandle(begun *Response) string {
	s.t.Helper()

	begun.ExpectStatus(http.StatusSeeOther)

	prefix := s.Config.Site.String() + "/authorize#request="

	handle, found := strings.CutPrefix(begun.Header.Get("Location"), prefix)
	if !found || len(handle) != 43 {
		s.t.Fatalf("the browser was not sent to the authorization page: %q", begun.Header.Get("Location"))
	}

	return handle
}

// FromSite sends the site's exact origin, which the page's forms carry.
func (s *Service) FromSite(request *http.Request) {
	request.Header.Set("Origin", s.Config.Site.String())
}

// ChooseProvider submits the page's form for a provider and reads what the
// provider was sent, as StartLogin does.
func (s *Service) ChooseProvider(handle string, provider oauth.Provider) Authorization {
	s.t.Helper()

	response := s.POSTForm("/oauth/authorization/"+handle+"/"+string(provider), "", s.FromSite).
		ExpectStatus(http.StatusSeeOther)

	return s.readProviderRedirect(provider, response)
}

// BeginPublicSignIn authorizes, chooses a provider and returns what it was
// sent, ready for FinishLogin.
func (c *InstalledClient) BeginPublicSignIn(pending PendingAuthorization, provider oauth.Provider) Authorization {
	c.service.t.Helper()

	return c.service.ChooseProvider(c.service.PageHandle(c.Authorize(pending)), provider)
}

// SignIn runs a whole browser journey and returns the code the client's
// listener received.
func (c *InstalledClient) SignIn(pending PendingAuthorization, provider oauth.Provider, person string) string {
	c.service.t.Helper()

	return c.SignInAs(pending, provider, c.service.Providers.Someone(provider, person))
}

// SignInAs runs a whole browser journey for one provider identity, so a test
// can sign the same person in more than once.
func (c *InstalledClient) SignInAs(
	pending PendingAuthorization, provider oauth.Provider, identity providertest.Identity,
) string {
	c.service.t.Helper()

	started := c.BeginPublicSignIn(pending, provider)
	returned := c.service.FinishLogin(started, identity).ExpectStatus(http.StatusSeeOther)

	answer, err := pending.Read(returned.Header.Get("Location"), OpenIDIssuer)
	if err != nil || answer.Code == "" {
		c.service.t.Fatalf("the client was not returned a code: %v %+v", err, answer)
	}

	return answer.Code
}

// AuthorizationAnswer is what a client's listener received.
type AuthorizationAnswer struct {
	Code  string
	Error string
}

// Errors the client's listener refuses an answer with.
var (
	ErrUnexpectedAddress = errors.New("the answer did not arrive at the pending redirect")
	ErrAmbiguousAnswer   = errors.New("the answer repeats or combines its parameters")
	ErrUnsolicitedAnswer = errors.New("the answer belongs to no pending authorization")
)

// Read accepts an authorization response only at the exact pending redirect,
// with exactly one of code or error, this authorization's state and the
// expected issuer, each exactly once.
func (p PendingAuthorization) Read(location, expectedIssuer string) (AuthorizationAnswer, error) {
	base, rawQuery, _ := strings.Cut(location, "?")
	if registered, _, _ := strings.Cut(p.RedirectURI, "?"); base != registered {
		return AuthorizationAnswer{}, ErrUnexpectedAddress
	}

	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return AuthorizationAnswer{}, ErrAmbiguousAnswer
	}

	for _, name := range []string{"code", "error", "state", "iss"} {
		if len(query[name]) > 1 {
			return AuthorizationAnswer{}, ErrAmbiguousAnswer
		}
	}

	answer := AuthorizationAnswer{Code: query.Get("code"), Error: query.Get("error")}
	if (answer.Code == "") == (answer.Error == "") {
		return AuthorizationAnswer{}, ErrAmbiguousAnswer
	}

	if query.Get("state") != p.State || query.Get("iss") != expectedIssuer {
		return AuthorizationAnswer{}, ErrUnsolicitedAnswer
	}

	return answer, nil
}

// TokenSet is a token endpoint's successful answer.
type TokenSet struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int64  `json:"expires_in"`
	IDToken               string `json:"id_token"`
	Scope                 string `json:"scope"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
}

// ExchangeForm is the token request that redeems a code.
func (c *InstalledClient) ExchangeForm(pending PendingAuthorization, code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.ClientID.String()},
		"code":          {code},
		"redirect_uri":  {pending.RedirectURI},
		"code_verifier": {pending.Verifier},
	}
}

// Exchange redeems a code.
func (c *InstalledClient) Exchange(pending PendingAuthorization, code string) *Response {
	c.service.t.Helper()

	return c.service.POSTForm("/oauth/token", c.ExchangeForm(pending, code).Encode())
}

// Refresh rotates a refresh token, narrowing to scope when it is not empty.
func (c *InstalledClient) Refresh(token, scope string) *Response {
	c.service.t.Helper()

	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID.String()}, "refresh_token": {token}}
	if scope != "" {
		form.Set("scope", scope)
	}

	return c.service.POSTForm("/oauth/token", form.Encode())
}

// Revoke revokes a token with any hints the test adds.
func (c *InstalledClient) Revoke(token string, hints ...string) *Response {
	c.service.t.Helper()

	form := url.Values{"client_id": {c.ClientID.String()}, "token": {token}}
	for _, hint := range hints {
		form.Add("token_type_hint", hint)
	}

	return c.service.POSTForm("/oauth/revoke", form.Encode())
}

// Tokens signs a person in through Discord and returns the token set.
func (c *InstalledClient) Tokens(template, scope string, identity providertest.Identity) (PendingAuthorization, TokenSet) {
	c.service.t.Helper()

	pending := c.Pending(template, 49152, scope)
	code := c.SignInAs(pending, oauth.Discord, identity)

	var issued TokenSet

	c.Exchange(pending, code).ExpectStatus(http.StatusOK).DecodeInto(&issued)

	return pending, issued
}

func (c *InstalledClient) random() string {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		c.service.t.Fatalf("drawing a client value: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(value)
}

// readProviderRedirect reads what a provider was sent, as StartLogin does.
func (s *Service) readProviderRedirect(provider oauth.Provider, response *Response) Authorization {
	s.t.Helper()

	sentTo := response.Header.Get("Location")

	address, err := url.Parse(sentTo)
	if err != nil {
		s.t.Fatalf("the browser was sent to something that is not a URL: %v", err)
	}

	started := Authorization{
		Provider:         provider,
		AuthorizationURL: sentTo,
		State:            address.Query().Get("state"),
		Challenge:        address.Query().Get("code_challenge"),
		Nonce:            address.Query().Get("nonce"),
		Response:         response,
	}

	if provider == oauth.Steam {
		started.ReturnTo = address.Query().Get("openid.return_to")

		returnTo, err := url.Parse(started.ReturnTo)
		if err != nil {
			s.t.Fatalf("Steam was asked to return the browser to something that is not a URL: %v", err)
		}

		started.State = returnTo.Query().Get("state")
	}

	return started
}

// TokenValidator validates one token class as an external party does: from
// the issuer it was configured with, that issuer's discovery document, and the
// one key set the discovery document names for that class. It allows no clock
// tolerance.
type TokenValidator struct {
	issuer string
	keys   map[string]*rsa.PublicKey
	now    func() time.Time
}

// Errors a validator refuses a token or its configuration with.
var (
	ErrIssuerMismatch = errors.New("the discovery document names another issuer")
	ErrTokenRefused   = errors.New("the token is not accepted")
)

// IDTokenValidator builds a validator for ID tokens from the standard jwks_uri.
func (s *Service) IDTokenValidator(expectedIssuer string, now func() time.Time) (*TokenValidator, error) {
	return s.validatorFrom(expectedIssuer, "jwks_uri", now)
}

// AccessTokenValidator builds a resource server's validator for access tokens
// from access_token_jwks_uri.
func (s *Service) AccessTokenValidator(expectedIssuer string, now func() time.Time) (*TokenValidator, error) {
	return s.validatorFrom(expectedIssuer, "access_token_jwks_uri", now)
}

// Discovery fetches the discovery document from the expected issuer's own
// location.
func (s *Service) Discovery(expectedIssuer string) (map[string]any, error) {
	s.t.Helper()

	fetched, err := s.fetchAbsolute(expectedIssuer + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}

	var document map[string]any
	fetched.DecodeInto(&document)

	if document["issuer"] != expectedIssuer {
		return nil, ErrIssuerMismatch
	}

	return document, nil
}

// fetchAbsolute fetches an address this service would be reached at, and
// refuses one it does not serve.
func (s *Service) fetchAbsolute(address string) (*Response, error) {
	s.t.Helper()

	target, found := strings.CutPrefix(address, APIOrigin)
	if !found || !strings.HasPrefix(target, "/") {
		return nil, ErrIssuerMismatch
	}

	fetched := s.AtExactTarget(http.MethodGet, target)
	if fetched.Status != http.StatusOK {
		return nil, ErrIssuerMismatch
	}

	return fetched, nil
}

// KeySet fetches a published key set by its absolute address.
func (s *Service) KeySet(address string) (map[string]*rsa.PublicKey, error) {
	s.t.Helper()

	fetched, err := s.fetchAbsolute(address)
	if err != nil {
		return nil, err
	}

	var set struct {
		Keys []map[string]string `json:"keys"`
	}

	fetched.DecodeInto(&set)

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))

	for _, key := range set.Keys {
		modulus, err := base64.RawURLEncoding.DecodeString(key["n"])
		if err != nil {
			return nil, err
		}

		exponent, err := base64.RawURLEncoding.DecodeString(key["e"])
		if err != nil {
			return nil, err
		}

		keys[key["kid"]] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}
	}

	return keys, nil
}

func (s *Service) validatorFrom(expectedIssuer, member string, now func() time.Time) (*TokenValidator, error) {
	document, err := s.Discovery(expectedIssuer)
	if err != nil {
		return nil, err
	}

	address, _ := document[member].(string)

	keys, err := s.KeySet(address)
	if err != nil {
		return nil, err
	}

	if now == nil {
		now = time.Now
	}

	return &TokenValidator{issuer: expectedIssuer, keys: keys, now: now}, nil
}

var (
	pairwiseSubject = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	canonicalUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidateIDToken accepts exactly the ID token profile for one client. A code
// response's token must carry the pending nonce; a refreshed one carries none.
func (v *TokenValidator) ValidateIDToken(token, clientID, nonce string) (map[string]any, error) {
	claims, err := v.verify(token, "JWT")
	if err != nil {
		return nil, err
	}

	allowed := []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "preferred_username"}
	for name := range claims {
		if !slices.Contains(allowed, name) {
			return nil, ErrTokenRefused
		}
	}

	issuedAt, issued := integerClaim(claims, "iat")
	expiresAt, expires := integerClaim(claims, "exp")
	_, authenticated := integerClaim(claims, "auth_time")

	subject, _ := claims["sub"].(string)
	audience, _ := claims["aud"].(string)
	presented, hasNonce := claims["nonce"].(string)

	if !issued || !expires || !authenticated || claims["iss"] != v.issuer || !pairwiseSubject.MatchString(subject) ||
		audience != clientID || expiresAt-issuedAt != 300 || !v.within(issuedAt, expiresAt) {
		return nil, ErrTokenRefused
	}

	if (nonce == "" && hasNonce) || (nonce != "" && presented != nonce) {
		return nil, ErrTokenRefused
	}

	return claims, nil
}

// ValidateAccessToken accepts exactly the RFC 9068 profile for one client.
func (v *TokenValidator) ValidateAccessToken(token, clientID string) (map[string]any, error) {
	claims, err := v.verify(token, "at+jwt")
	if err != nil {
		return nil, err
	}

	if len(claims) != 10 {
		return nil, ErrTokenRefused
	}

	issuedAt, issued := integerClaim(claims, "iat")
	notBefore, valid := integerClaim(claims, "nbf")
	expiresAt, expires := integerClaim(claims, "exp")

	texts := map[string]string{}
	for _, name := range []string{"iss", "sub", "aud", "client_id", "scope", "jti", "auth_epoch"} {
		text, isText := claims[name].(string)
		if !isText {
			return nil, ErrTokenRefused
		}

		texts[name] = text
	}

	if !issued || !valid || !expires || texts["iss"] != v.issuer || texts["aud"] != clientID ||
		texts["client_id"] != clientID || !pairwiseSubject.MatchString(texts["sub"]) ||
		!canonicalUUID.MatchString(texts["jti"]) || !canonicalUUID.MatchString(texts["auth_epoch"]) ||
		notBefore != issuedAt || expiresAt-issuedAt != 900 || !v.within(notBefore, expiresAt) {
		return nil, ErrTokenRefused
	}

	return claims, nil
}

func (v *TokenValidator) within(from, until int64) bool {
	now := v.now().Unix()

	return now >= from && now < until
}

// verify checks a compact token's RS256 signature with a key of this set only,
// and its header type, and returns its claims.
func (v *TokenValidator) verify(token, tokenType string) (map[string]any, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, ErrTokenRefused
	}

	header, err := decodeSegment(segments[0])
	if err != nil || len(header) != 3 || header["alg"] != "RS256" || header["typ"] != tokenType {
		return nil, ErrTokenRefused
	}

	keyID, _ := header["kid"].(string)

	key, found := v.keys[keyID]
	if !found {
		return nil, ErrTokenRefused
	}

	signature, err := base64.RawURLEncoding.Strict().DecodeString(segments[2])
	if err != nil {
		return nil, ErrTokenRefused
	}

	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, ErrTokenRefused
	}

	return decodeSegment(segments[1])
}

func decodeSegment(segment string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var members map[string]any
	if err := decoder.Decode(&members); err != nil {
		return nil, err
	}

	return members, nil
}

func integerClaim(claims map[string]any, name string) (int64, bool) {
	number, isNumber := claims[name].(json.Number)
	if !isNumber {
		return 0, false
	}

	value, err := strconv.ParseInt(number.String(), 10, 64)

	return value, err == nil
}

// DecodeClaims reads a token's claims without checking anything, for a test
// that states what a genuine token carries.
func DecodeClaims(token string) map[string]any {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil
	}

	claims, err := decodeSegment(segments[1])
	if err != nil {
		return nil
	}

	return claims
}

// SignAs signs claims with a private key under a header, so a test can present
// a token this service never issued.
func SignAs(key *rsa.PrivateKey, header, claims map[string]any) (string, error) {
	encodedHeader, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	encodedClaims, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	input := base64.RawURLEncoding.EncodeToString(encodedHeader) + "." +
		base64.RawURLEncoding.EncodeToString(encodedClaims)
	digest := sha256.Sum256([]byte(input))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing a test token: %w", err)
	}

	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
