package providers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// Where Google is reached. The discovery document is fetched, but it is checked
// against these rather than obeyed: a document that named anywhere else would
// otherwise be able to move the sign-in.
const (
	googleDiscoveryEndpoint = "https://accounts.google.com/.well-known/openid-configuration"
	googleIssuer            = "https://accounts.google.com"
	googleAuthorizeEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint     = "https://oauth2.googleapis.com/token"
	googleJWKSEndpoint      = "https://www.googleapis.com/oauth2/v3/certs"
)

// googleScope asks for the identity token and the person's display name, which
// is what an account is created with.
const googleScope = "openid profile"

// identityTokenAlgorithm is the only signature this service accepts on an
// identity token. It is asymmetric, so a token cannot be forged with anything
// Google publishes.
const identityTokenAlgorithm = "RS256"

// maxIdentityClockSkew is how far the clock verifying an identity token may be
// from the clock that issued it.
const maxIdentityClockSkew = 30 * time.Second

// GoogleEndpoints are the addresses Google is expected to be at. A test passes
// its own; a deployment always gets the constants above.
type GoogleEndpoints struct {
	Discovery string
	Issuer    string
	Authorize string
	Token     string
	JWKS      string
}

// Google signs a person in with their Google account, through OpenID Connect.
//
// The identity token is the whole of the answer: this service reads who the
// person is from claims it has verified the signature of, and never spends the
// access token on a second request whose answer it could not check.
type Google struct {
	clientID     string
	clientSecret config.Secret
	callback     string
	expected     GoogleEndpoints
	client       *http.Client
	now          func() time.Time

	discovery sync.Mutex
	keys      *oidc.RemoteKeySet
}

// NewGoogle builds the client from the registration this service holds with
// Google.
func NewGoogle(
	registration config.Provider, endpoints GoogleEndpoints, transport http.RoundTripper, now func() time.Time,
) *Google {
	if now == nil {
		now = time.Now
	}

	return &Google{
		clientID:     registration.ClientID,
		clientSecret: registration.ClientSecret,
		callback:     registration.Callback.String(),
		expected:     withGoogleDefaults(endpoints),
		client:       newHTTPClient(transport),
		now:          now,
	}
}

// AuthorizationURL is where a browser is sent to start a sign-in.
//
// It uses the expected endpoint rather than a discovered one, so starting a
// login does not depend on Google's discovery document being reachable.
func (g *Google) AuthorizationURL(state, challenge, nonce string) string {
	return authorizationURL(g.expected.Authorize, url.Values{
		"client_id":             {g.clientID},
		"redirect_uri":          {g.callback},
		"response_type":         {"code"},
		"scope":                 {googleScope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})
}

// Identify exchanges an authorization code for the person it stands for, and
// proves the identity token was issued by Google for this login.
func (g *Google) Identify(
	ctx context.Context, code, verifier string, nonceDigest []byte,
) (accounts.Identity, error) {
	keys, err := g.keySet(ctx)
	if err != nil {
		return accounts.Identity{}, err
	}

	var granted struct {
		AccessToken   string `json:"access_token"`
		IdentityToken string `json:"id_token"`
	}

	err = postForm(ctx, g.client, g.expected.Token, url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret.Reveal()},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {g.callback},
		"code_verifier": {verifier},
	}, &granted)
	if err != nil {
		return accounts.Identity{}, err
	}

	if granted.IdentityToken == "" {
		return accounts.Identity{}, ErrProviderRefused
	}

	claims, err := g.verifyIdentityToken(ctx, keys, granted.IdentityToken, granted.AccessToken, nonceDigest)
	if err != nil {
		return accounts.Identity{}, err
	}

	return accounts.Identity{
		Provider: oauth.Google,
		ID:       claims.Subject,
		Username: claims.Name,
	}, nil
}

// identityClaims are the claims this service reads from an identity token.
type identityClaims struct {
	Issuer         string   `json:"iss"`
	Subject        string   `json:"sub"`
	Name           string   `json:"name"`
	Nonce          string   `json:"nonce"`
	AuthorizedTo   string   `json:"azp"`
	AccessTokenSum string   `json:"at_hash"`
	Audience       audience `json:"aud"`
	ExpiresAt      *int64   `json:"exp"`
	IssuedAt       *int64   `json:"iat"`
	NotBefore      *int64   `json:"nbf"`
}

// audience is the aud claim, which OpenID Connect allows to be either one
// string or a list of them.
type audience []string

func (a *audience) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*a = audience{single}

		return nil
	}

	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return fmt.Errorf("the audience is neither a string nor a list: %w", err)
	}

	*a = many

	return nil
}

func (g *Google) verifyIdentityToken(
	ctx context.Context, keys *oidc.RemoteKeySet, identityToken, accessToken string, nonceDigest []byte,
) (identityClaims, error) {
	if err := requireIdentityTokenAlgorithm(identityToken); err != nil {
		return identityClaims{}, err
	}

	payload, err := keys.VerifySignature(ctx, identityToken)
	if err != nil {
		return identityClaims{}, fmt.Errorf("%w: the identity token is not signed by it", ErrProviderRefused)
	}

	var claims identityClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return identityClaims{}, fmt.Errorf("%w: the identity token is not the expected shape", ErrProviderRefused)
	}

	if claims.Issuer != g.expected.Issuer {
		return identityClaims{}, fmt.Errorf("%w: the identity token names another issuer", ErrProviderRefused)
	}

	if err := g.verifyAudience(claims); err != nil {
		return identityClaims{}, err
	}

	if err := g.verifyValidity(claims); err != nil {
		return identityClaims{}, err
	}

	if claims.Nonce == "" ||
		!credentials.Equal(nonceDigest, credentials.Digest(credentials.DomainIdentityNonce, claims.Nonce)) {
		return identityClaims{}, fmt.Errorf("%w: the identity token belongs to another login", ErrProviderRefused)
	}

	if claims.Subject == "" || claims.Name == "" {
		return identityClaims{}, ErrUnusableIdentity
	}

	if err := verifyAccessTokenSum(claims.AccessTokenSum, accessToken); err != nil {
		return identityClaims{}, err
	}

	return claims, nil
}

// verifyAudience refuses a token that was not issued for this service.
//
// A token issued for several audiences must say which one it was authorised
// for, and that has to be this service; a token that names an authorised party
// at all must not name a different one.
func (g *Google) verifyAudience(claims identityClaims) error {
	intended := false

	for _, entry := range claims.Audience {
		if entry == g.clientID {
			intended = true
		}
	}

	if !intended {
		return fmt.Errorf("%w: the identity token was issued for another application", ErrProviderRefused)
	}

	if len(claims.Audience) > 1 && claims.AuthorizedTo == "" {
		return fmt.Errorf("%w: the identity token does not say who it was authorised for", ErrProviderRefused)
	}

	if claims.AuthorizedTo != "" && claims.AuthorizedTo != g.clientID {
		return fmt.Errorf("%w: the identity token was authorised for another application", ErrProviderRefused)
	}

	return nil
}

func (g *Google) verifyValidity(claims identityClaims) error {
	if claims.ExpiresAt == nil || claims.IssuedAt == nil {
		return fmt.Errorf("%w: the identity token does not say when it is valid", ErrProviderRefused)
	}

	now := g.now().UTC()

	if now.After(time.Unix(*claims.ExpiresAt, 0).UTC().Add(maxIdentityClockSkew)) {
		return fmt.Errorf("%w: the identity token has expired", ErrProviderRefused)
	}

	if now.Before(time.Unix(*claims.IssuedAt, 0).UTC().Add(-maxIdentityClockSkew)) {
		return fmt.Errorf("%w: the identity token was issued in the future", ErrProviderRefused)
	}

	if claims.NotBefore != nil &&
		now.Before(time.Unix(*claims.NotBefore, 0).UTC().Add(-maxIdentityClockSkew)) {
		return fmt.Errorf("%w: the identity token is not valid yet", ErrProviderRefused)
	}

	return nil
}

// requireIdentityTokenAlgorithm refuses anything but the one asymmetric
// signature, before the token is handed to a verifier that would accept more.
func requireIdentityTokenAlgorithm(identityToken string) error {
	parts := strings.Split(identityToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: the identity token is not a signed token", ErrProviderRefused)
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("%w: the identity token's header cannot be read", ErrProviderRefused)
	}

	var header struct {
		Algorithm string   `json:"alg"`
		Critical  []string `json:"crit"`
	}

	if err := json.Unmarshal(raw, &header); err != nil {
		return fmt.Errorf("%w: the identity token's header cannot be read", ErrProviderRefused)
	}

	if header.Algorithm != identityTokenAlgorithm {
		return fmt.Errorf("%w: the identity token is signed with an algorithm this service does not accept",
			ErrProviderRefused)
	}

	if len(header.Critical) > 0 {
		return fmt.Errorf("%w: the identity token requires an extension this service does not implement",
			ErrProviderRefused)
	}

	return nil
}

// verifyAccessTokenSum checks the identity token's claim about the access token
// it came with. When the claim is absent the access token is simply not used
// for anything, so there is nothing to bind.
func verifyAccessTokenSum(claimed, accessToken string) error {
	if claimed == "" {
		return nil
	}

	if accessToken == "" {
		return fmt.Errorf("%w: the identity token describes an access token that did not arrive",
			ErrProviderRefused)
	}

	digest := sha256.Sum256([]byte(accessToken))
	expected := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])

	if !credentials.Equal([]byte(claimed), []byte(expected)) {
		return fmt.Errorf("%w: the identity token does not match the access token it came with",
			ErrProviderRefused)
	}

	return nil
}

// keySet fetches the discovery document once and checks that it still describes
// the Google this service was built against.
func (g *Google) keySet(ctx context.Context) (*oidc.RemoteKeySet, error) {
	g.discovery.Lock()
	defer g.discovery.Unlock()

	if g.keys != nil {
		return g.keys, nil
	}

	var document struct {
		Issuer               string `json:"issuer"`
		AuthorizationEndoint string `json:"authorization_endpoint"`
		TokenEndpoint        string `json:"token_endpoint"`
		JWKSURI              string `json:"jwks_uri"`
	}

	if err := get(ctx, g.client, g.expected.Discovery, "", &document); err != nil {
		return nil, err
	}

	found := GoogleEndpoints{
		Issuer:    document.Issuer,
		Authorize: document.AuthorizationEndoint,
		Token:     document.TokenEndpoint,
		JWKS:      document.JWKSURI,
	}

	for _, address := range []string{found.Issuer, found.Authorize, found.Token, found.JWKS} {
		if err := requireHTTPS(address); err != nil {
			return nil, err
		}
	}

	if found.Issuer != g.expected.Issuer ||
		found.Authorize != g.expected.Authorize ||
		found.Token != g.expected.Token ||
		found.JWKS != g.expected.JWKS {
		return nil, fmt.Errorf("%w: its published configuration is not the one this service was built for",
			ErrProviderRefused)
	}

	// The key set outlives the request that first needed it, because it caches
	// the published keys and refetches them when a token names one it has not
	// seen.
	g.keys = oidc.NewRemoteKeySet(oidc.ClientContext(context.WithoutCancel(ctx), g.client), g.expected.JWKS)

	return g.keys, nil
}

func withGoogleDefaults(given GoogleEndpoints) GoogleEndpoints {
	if given.Discovery == "" {
		given.Discovery = googleDiscoveryEndpoint
	}

	if given.Issuer == "" {
		given.Issuer = googleIssuer
	}

	if given.Authorize == "" {
		given.Authorize = googleAuthorizeEndpoint
	}

	if given.Token == "" {
		given.Token = googleTokenEndpoint
	}

	if given.JWKS == "" {
		given.JWKS = googleJWKSEndpoint
	}

	return given
}
