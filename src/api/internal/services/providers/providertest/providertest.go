// Package providertest answers the identity providers locally.
//
// The addresses the service calls are constants in the provider clients, so the
// double does not move them: it supplies a transport that carries a request
// addressed to Discord, GitHub or Google to a local server instead. A test
// therefore proves that the service asked the real provider's address, and no
// test reaches the internet.
package providertest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// The hosts and paths each provider publishes. They are repeated here rather
// than shared with the provider clients: a test that agreed with the code it
// exercises by construction would not notice the address changing.
const (
	discordHost  = "discord.com"
	discordToken = "/api/v10/oauth2/token"
	discordUser  = "/api/v10/users/@me"

	gitHubHost         = "github.com"
	gitHubToken        = "/login/oauth/access_token"
	gitHubIdentityHost = "api.github.com"
	gitHubUser         = "/user"

	googleAccountsHost = "accounts.google.com"
	googleDiscovery    = "/.well-known/openid-configuration"
	googleTokenHost    = "oauth2.googleapis.com"
	googleToken        = "/token"
	googleKeysHost     = "www.googleapis.com"
	googleKeys         = "/oauth2/v3/certs"

	googleIssuer    = "https://accounts.google.com"
	googleAuthorize = "https://accounts.google.com/o/oauth2/v2/auth"
)

// identityTokenLifetime is how long the identity token Google issues is valid
// for. It only has to outlast the request that verifies it.
const identityTokenLifetime = 5 * time.Minute

// signingKeyIdentifier names the key the double publishes and signs with.
const signingKeyIdentifier = "providertest-rs256"

// Identity is a person as a provider describes them.
type Identity struct {
	// ID is the identifier in the provider's own spelling: decimal for Discord
	// and GitHub, and an opaque subject for Google.
	ID string

	Username string
}

// Grant is an authorization a provider will honour once.
type Grant struct {
	Identity Identity

	// Challenge, when set, is the PKCE challenge the service sent to the
	// provider. The exchange then has to present the verifier it was derived
	// from, exactly as the real provider requires.
	Challenge string

	// Nonce is the value the identity token carries, for the provider that
	// issues one.
	Nonce string
}

// Providers is a set of identity providers answering on the loopback interface.
type Providers struct {
	t *testing.T

	googleClientID string
	faults         Options

	server *httptest.Server
	key    *rsa.PrivateKey

	// anotherKey is not in the published set, so a token signed with it is one
	// the service must refuse.
	anotherKey *rsa.PrivateKey

	held    sync.Mutex
	grants  map[string]Grant
	granted map[string]Identity
}

// Options are the registrations the double has to agree with.
type Options struct {
	// GoogleClientID is the audience the identity tokens are issued for.
	GoogleClientID string

	// AlterIdentityToken changes what Google claims about a person before the
	// token is signed, so a test can describe an answer this service is
	// required to refuse. It is left unset by a test about a working sign-in.
	AlterIdentityToken func(jwt.MapClaims)

	// SignIdentityTokenWithAnotherKey signs with a key the published set does
	// not carry, which is what a forged token looks like.
	SignIdentityTokenWithAnotherKey bool

	// IdentityTokenAlgorithm signs with something other than RS256. A symmetric
	// algorithm here is signed with the client identifier, which is what an
	// attacker holding only public values could manage.
	IdentityTokenAlgorithm jwt.SigningMethod
}

// New starts the providers and stops them when the test ends.
func New(t *testing.T, choices Options) *Providers {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the provider signing key: %v", err)
	}

	another, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a second provider signing key: %v", err)
	}

	providers := &Providers{
		t:              t,
		googleClientID: choices.GoogleClientID,
		faults:         choices,
		key:            key,
		anotherKey:     another,
		grants:         make(map[string]Grant),
		granted:        make(map[string]Identity),
	}

	providers.server = httptest.NewServer(http.HandlerFunc(providers.answer))
	t.Cleanup(providers.server.Close)

	return providers
}

// Transport carries a request addressed to a provider to the double.
func (p *Providers) Transport() http.RoundTripper {
	return &transport{host: strings.TrimPrefix(p.server.URL, "http://")}
}

// Issue records an authorization code a provider will honour.
func (p *Providers) Issue(provider oauth.Provider, grant Grant) string {
	p.t.Helper()

	code := codeFor(provider, p.random())

	p.held.Lock()
	defer p.held.Unlock()

	p.grants[code] = grant

	return code
}

// Someone returns an identity nobody else in the test run has, so a test that
// signs two people in does not accidentally sign in one.
func (p *Providers) Someone(provider oauth.Provider, username string) Identity {
	p.t.Helper()

	value, err := rand.Int(rand.Reader, big.NewInt(1<<31-1))
	if err != nil {
		p.t.Fatalf("generating a provider identity: %v", err)
	}

	number := value.Int64()
	if number == 0 {
		number = 1
	}

	if provider == oauth.Google {
		return Identity{ID: fmt.Sprintf("google-subject-%d", number), Username: username}
	}

	return Identity{ID: fmt.Sprintf("%d", number), Username: username}
}

func (p *Providers) answer(writer http.ResponseWriter, request *http.Request) {
	switch request.Host + request.URL.Path {
	case discordHost + discordToken, gitHubHost + gitHubToken:
		p.exchange(writer, request, false)
	case googleTokenHost + googleToken:
		p.exchange(writer, request, true)
	case discordHost + discordUser:
		p.describePerson(writer, request, personFields{ID: "id", Name: "username"})
	case gitHubIdentityHost + gitHubUser:
		p.describePerson(writer, request, personFields{ID: "id", Name: "login", NumericID: true})
	case googleAccountsHost + googleDiscovery:
		p.publishConfiguration(writer)
	case googleKeysHost + googleKeys:
		p.publishKeys(writer)
	default:
		http.Error(writer, "no provider serves this address", http.StatusNotFound)
	}
}

// exchange spends an authorization code, checking the proof of possession the
// service is required to send with it.
func (p *Providers) exchange(writer http.ResponseWriter, request *http.Request, withIdentityToken bool) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "the request is not a form", http.StatusBadRequest)

		return
	}

	code := request.PostFormValue("code")

	p.held.Lock()
	grant, known := p.grants[code]
	delete(p.grants, code)
	p.held.Unlock()

	if !known {
		http.Error(writer, "no such authorization code", http.StatusBadRequest)

		return
	}

	verifier := request.PostFormValue("code_verifier")
	if grant.Challenge != "" && challengeFor(verifier) != grant.Challenge {
		http.Error(writer, "the verifier does not match the challenge", http.StatusBadRequest)

		return
	}

	accessToken := p.random()

	p.held.Lock()
	p.granted[accessToken] = grant.Identity
	p.held.Unlock()

	granted := map[string]any{"access_token": accessToken, "token_type": "Bearer"}

	if withIdentityToken {
		granted["id_token"] = p.identityToken(grant, accessToken)
	}

	writeJSON(writer, granted)
}

// personFields is how one provider spells a person: Discord sends the
// identifier as a decimal string and GitHub as a number, and the service has to
// read both.
type personFields struct {
	ID        string
	Name      string
	NumericID bool
}

// describePerson answers with whoever the access token was granted for.
func (p *Providers) describePerson(writer http.ResponseWriter, request *http.Request, fields personFields) {
	accessToken := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")

	p.held.Lock()
	identity, known := p.granted[accessToken]
	p.held.Unlock()

	if !known {
		http.Error(writer, "no such access token", http.StatusUnauthorized)

		return
	}

	var id any = identity.ID
	if fields.NumericID {
		id = json.Number(identity.ID)
	}

	writeJSON(writer, map[string]any{fields.ID: id, fields.Name: identity.Username})
}

func (p *Providers) publishConfiguration(writer http.ResponseWriter) {
	writeJSON(writer, map[string]any{
		"issuer":                 googleIssuer,
		"authorization_endpoint": googleAuthorize,
		"token_endpoint":         "https://" + googleTokenHost + googleToken,
		"jwks_uri":               "https://" + googleKeysHost + googleKeys,
	})
}

func (p *Providers) publishKeys(writer http.ResponseWriter) {
	public := p.key.PublicKey

	writeJSON(writer, map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": signingKeyIdentifier,
		"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}})
}

// identityToken builds the token Google returns alongside the access token,
// bound to the login by its nonce and to the access token by its hash.
func (p *Providers) identityToken(grant Grant, accessToken string) string {
	p.t.Helper()

	now := time.Now()

	claims := jwt.MapClaims{
		"iss":     googleIssuer,
		"aud":     p.googleClientID,
		"sub":     grant.Identity.ID,
		"name":    grant.Identity.Username,
		"nonce":   grant.Nonce,
		"iat":     now.Unix(),
		"exp":     now.Add(identityTokenLifetime).Unix(),
		"at_hash": accessTokenSum(accessToken),
	}

	if p.faults.AlterIdentityToken != nil {
		p.faults.AlterIdentityToken(claims)
	}

	algorithm := jwt.SigningMethod(jwt.SigningMethodRS256)
	if p.faults.IdentityTokenAlgorithm != nil {
		algorithm = p.faults.IdentityTokenAlgorithm
	}

	token := jwt.NewWithClaims(algorithm, claims)
	token.Header["kid"] = signingKeyIdentifier

	var signWith any = p.key

	switch {
	case algorithm.Alg() == jwt.SigningMethodRS256.Alg() && p.faults.SignIdentityTokenWithAnotherKey:
		signWith = p.anotherKey
	case algorithm.Alg() != jwt.SigningMethodRS256.Alg():
		// A symmetric algorithm is keyed on a value an attacker could hold,
		// which is the point of refusing anything but RS256.
		signWith = []byte(p.googleClientID)
	}

	signed, err := token.SignedString(signWith)
	if err != nil {
		p.t.Fatalf("signing an identity token: %v", err)
	}

	return signed
}

func (p *Providers) random() string {
	p.t.Helper()

	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		p.t.Fatalf("generating a provider value: %v", err)
	}

	return hex.EncodeToString(value)
}

// transport addresses every provider request to the double, keeping the host
// the service asked for so the double can tell the providers apart.
type transport struct {
	host string
}

func (t *transport) RoundTrip(request *http.Request) (*http.Response, error) {
	routed := request.Clone(request.Context())
	routed.URL.Scheme = "http"
	routed.URL.Host = t.host
	routed.Host = request.URL.Host

	return http.DefaultTransport.RoundTrip(routed)
}

func writeJSON(writer http.ResponseWriter, body any) {
	writer.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(writer).Encode(body)
}

func challengeFor(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func accessTokenSum(accessToken string) string {
	digest := sha256.Sum256([]byte(accessToken))

	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
}

// codeFor prefixes a code with the provider it belongs to, so a value seen in a
// failing test says which provider issued it.
func codeFor(provider oauth.Provider, value string) string {
	return string(provider) + "-" + value
}
