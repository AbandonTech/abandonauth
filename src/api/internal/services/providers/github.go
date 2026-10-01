package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// Where GitHub is reached.
const (
	gitHubAuthorizeEndpoint = "https://github.com/login/oauth/authorize"
	gitHubTokenEndpoint     = "https://github.com/login/oauth/access_token"
	gitHubIdentityEndpoint  = "https://api.github.com/user"
)

// gitHubScope reads the signed-in person's profile and nothing else.
const gitHubScope = "read:user"

// GitHub signs a person in with their GitHub account.
type GitHub struct {
	clientID     string
	clientSecret config.Secret
	callback     string
	endpoints    Endpoints
	client       *http.Client
}

// NewGitHub builds the client from the registration this service holds with
// GitHub.
func NewGitHub(
	registration config.Provider, endpoints Endpoints, transport http.RoundTripper,
) *GitHub {
	return &GitHub{
		clientID:     registration.ClientID,
		clientSecret: registration.ClientSecret,
		callback:     registration.Callback.String(),
		endpoints: withDefaults(endpoints, Endpoints{
			Authorize: gitHubAuthorizeEndpoint,
			Token:     gitHubTokenEndpoint,
			Identity:  gitHubIdentityEndpoint,
		}),
		client: newHTTPClient(transport),
	}
}

// AuthorizationURL is where a browser is sent to start a sign-in.
func (g *GitHub) AuthorizationURL(state, challenge string) string {
	return authorizationURL(g.endpoints.Authorize, url.Values{
		"client_id":             {g.clientID},
		"redirect_uri":          {g.callback},
		"response_type":         {"code"},
		"scope":                 {gitHubScope},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})
}

// Identify exchanges an authorization code for the person it stands for.
func (g *GitHub) Identify(ctx context.Context, code, verifier string) (accounts.Identity, error) {
	var granted struct {
		AccessToken string `json:"access_token"`
	}

	err := postForm(ctx, g.client, g.endpoints.Token, url.Values{
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

	if granted.AccessToken == "" {
		return accounts.Identity{}, ErrProviderRefused
	}

	var person struct {
		ID    json.Number `json:"id"`
		Login string      `json:"login"`
	}

	if err := get(ctx, g.client, g.endpoints.Identity, granted.AccessToken, &person); err != nil {
		return accounts.Identity{}, err
	}

	identifier, err := strconv.ParseInt(person.ID.String(), 10, 32)
	if err != nil || identifier <= 0 || person.Login == "" {
		return accounts.Identity{}, ErrUnusableIdentity
	}

	return accounts.Identity{
		Provider: oauth.GitHub,
		ID:       strconv.FormatInt(identifier, 10),
		Username: person.Login,
	}, nil
}
