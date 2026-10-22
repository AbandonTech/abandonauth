package providers

import (
	"context"
	"net/http"
	"net/url"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// Where Discord is reached. These are constants so that no setting can move an
// authorization code or a client secret to another host.
const (
	discordAuthorizeEndpoint = "https://discord.com/oauth2/authorize"
	discordTokenEndpoint     = "https://discord.com/api/v10/oauth2/token"
	discordIdentityEndpoint  = "https://discord.com/api/v10/users/@me"
)

// discordScope is the least Discord will grant that still names the person.
const discordScope = "identify"

// Discord signs a person in with their Discord account.
type Discord struct {
	clientID     string
	clientSecret config.Secret
	callback     string
	endpoints    Endpoints
	client       *http.Client
}

// Endpoints are the addresses of one provider. A test passes its own; a
// deployment always gets the constants above.
type Endpoints struct {
	Authorize string
	Token     string
	Identity  string
}

// NewDiscord builds the client from the registration this service holds with
// Discord. Endpoints and transport are for tests; leaving them empty uses
// Discord itself.
func NewDiscord(
	registration config.Provider, endpoints Endpoints, transport http.RoundTripper,
) *Discord {
	return &Discord{
		clientID:     registration.ClientID,
		clientSecret: registration.ClientSecret,
		callback:     registration.Callback.String(),
		endpoints: withDefaults(endpoints, Endpoints{
			Authorize: discordAuthorizeEndpoint,
			Token:     discordTokenEndpoint,
			Identity:  discordIdentityEndpoint,
		}),
		client: newHTTPClient(transport),
	}
}

// AuthorizationURL is where a browser is sent to start a sign-in.
func (d *Discord) AuthorizationURL(state, challenge string) string {
	return authorizationURL(d.endpoints.Authorize, url.Values{
		"client_id":             {d.clientID},
		"redirect_uri":          {d.callback},
		"response_type":         {"code"},
		"scope":                 {discordScope},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		// Discord remembers a previous authorization, which would sign a person
		// back in without them choosing to.
		"prompt": {"consent"},
	})
}

// Identify exchanges an authorization code for the person it stands for.
func (d *Discord) Identify(ctx context.Context, code, verifier string) (accounts.Identity, error) {
	var granted struct {
		AccessToken string `json:"access_token"`
	}

	err := postForm(ctx, d.client, d.endpoints.Token, url.Values{
		"client_id":     {d.clientID},
		"client_secret": {d.clientSecret.Reveal()},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {d.callback},
		"code_verifier": {verifier},
	}, &granted)
	if err != nil {
		return accounts.Identity{}, err
	}

	if granted.AccessToken == "" {
		return accounts.Identity{}, ErrProviderRefused
	}

	var person struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}

	if err := get(ctx, d.client, d.endpoints.Identity, granted.AccessToken, &person); err != nil {
		return accounts.Identity{}, err
	}

	if person.ID == "" || person.Username == "" {
		return accounts.Identity{}, ErrUnusableIdentity
	}

	return accounts.Identity{
		Provider: oauth.Discord,
		ID:       person.ID,
		Username: person.Username,
	}, nil
}

func withDefaults(given, standard Endpoints) Endpoints {
	if given.Authorize == "" {
		given.Authorize = standard.Authorize
	}

	if given.Token == "" {
		given.Token = standard.Token
	}

	if given.Identity == "" {
		given.Identity = standard.Identity
	}

	return given
}

func authorizationURL(endpoint string, parameters url.Values) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}

	parsed.RawQuery = parameters.Encode()

	return parsed.String()
}
