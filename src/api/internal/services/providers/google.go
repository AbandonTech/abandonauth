package providers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// Google authenticates a user with their Google account, through OpenID
// Connect.
//
// The identity token is the only identity source: this service reads the
// subject and name from claims whose signature it has verified, and never
// spends the access token on a second request whose response it could not
// verify.
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

// Identify exchanges an authorization code for the authenticated identity, and
// verifies the identity token was issued by Google for this login.
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

// errInvalidAudienceClaimType replaces the JSON library's error, which can
// quote the claim.
var errInvalidAudienceClaimType = errors.New("invalid audience claim type")

func (a *audience) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*a = audience{single}

		return nil
	}

	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return errInvalidAudienceClaimType
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
		return identityClaims{}, refused("identity token signature validation failed")
	}

	var claims identityClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		if errors.Is(err, errInvalidAudienceClaimType) {
			return identityClaims{}, refused("invalid audience claim type")
		}

		return identityClaims{}, refused("invalid identity token claims")
	}

	if claims.Issuer != g.expected.Issuer {
		return identityClaims{}, refused("identity token issuer mismatch")
	}

	if err := g.verifyAudience(claims); err != nil {
		return identityClaims{}, err
	}

	if err := g.verifyValidity(claims); err != nil {
		return identityClaims{}, err
	}

	if claims.Nonce == "" ||
		!credentials.Equal(nonceDigest, credentials.Digest(credentials.DomainIdentityNonce, claims.Nonce)) {
		return identityClaims{}, refused("identity token nonce mismatch")
	}

	if claims.Subject == "" || claims.Name == "" {
		return identityClaims{}, ErrUnusableIdentity
	}

	if err := verifyAccessTokenSum(claims.AccessTokenSum, accessToken); err != nil {
		return identityClaims{}, err
	}

	return claims, nil
}

// verifyAudience refuses a token whose aud claim does not contain this
// service's client ID.
//
// A token with several audiences must carry an azp claim, and any non-empty azp
// claim must equal this service's client ID.
func (g *Google) verifyAudience(claims identityClaims) error {
	intended := false

	for _, entry := range claims.Audience {
		if entry == g.clientID {
			intended = true
		}
	}

	if !intended {
		return refused("identity token audience mismatch")
	}

	if len(claims.Audience) > 1 && claims.AuthorizedTo == "" {
		return refused("identity token missing authorized party claim")
	}

	if claims.AuthorizedTo != "" && claims.AuthorizedTo != g.clientID {
		return refused("identity token authorized party mismatch")
	}

	return nil
}

func (g *Google) verifyValidity(claims identityClaims) error {
	if claims.ExpiresAt == nil || claims.IssuedAt == nil {
		return refused("identity token missing exp or iat claim")
	}

	now := g.now().UTC()

	if now.After(time.Unix(*claims.ExpiresAt, 0).UTC().Add(maxIdentityClockSkew)) {
		return refused("identity token expired")
	}

	if now.Before(time.Unix(*claims.IssuedAt, 0).UTC().Add(-maxIdentityClockSkew)) {
		return refused("identity token iat claim is in the future")
	}

	if claims.NotBefore != nil &&
		now.Before(time.Unix(*claims.NotBefore, 0).UTC().Add(-maxIdentityClockSkew)) {
		return refused("identity token is not active")
	}

	return nil
}

// requireIdentityTokenAlgorithm refuses anything but the one asymmetric
// signature, before the token is handed to a verifier that would accept more.
func requireIdentityTokenAlgorithm(identityToken string) error {
	parts := strings.Split(identityToken, ".")
	if len(parts) != 3 {
		return refused("malformed identity token")
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return refused("invalid identity token header")
	}

	var header struct {
		Algorithm string   `json:"alg"`
		Critical  []string `json:"crit"`
	}

	if err := json.Unmarshal(raw, &header); err != nil {
		return refused("invalid identity token header")
	}

	if header.Algorithm != identityTokenAlgorithm {
		return refused("unsupported identity token signing algorithm")
	}

	if len(header.Critical) > 0 {
		return refused("unsupported critical identity token header")
	}

	return nil
}

// verifyAccessTokenSum checks the identity token's at_hash claim against the
// access token returned with it. Without the claim the access token is not used
// for anything, so there is nothing to bind.
func verifyAccessTokenSum(claimed, accessToken string) error {
	if claimed == "" {
		return nil
	}

	if accessToken == "" {
		return refused("identity token at_hash has no access token")
	}

	digest := sha256.Sum256([]byte(accessToken))
	expected := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])

	if !credentials.Equal([]byte(claimed), []byte(expected)) {
		return refused("identity token at_hash mismatch")
	}

	return nil
}

// refused wraps ErrProviderRefused with one package-owned reason. No token,
// claim value or provider response is ever appended.
func refused(reason string) error {
	return fmt.Errorf("%w: %s", ErrProviderRefused, reason)
}

// keySet fetches the discovery document once and checks that its issuer and
// endpoints equal the compiled-in ones.
func (g *Google) keySet(ctx context.Context) (*oidc.RemoteKeySet, error) {
	g.discovery.Lock()
	defer g.discovery.Unlock()

	if g.keys != nil {
		return g.keys, nil
	}

	var document struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}

	if err := get(ctx, g.client, g.expected.Discovery, "", &document); err != nil {
		return nil, err
	}

	found := GoogleEndpoints{
		Issuer:    document.Issuer,
		Authorize: document.AuthorizationEndpoint,
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
		return nil, refused("provider discovery configuration mismatch")
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
