// Package models is what the API sends and receives.
//
// These types are the published contract. A field name, its spelling and
// whether it is present are what applications parse, so they are written out
// here rather than derived from the database rows or the service types they
// happen to resemble today.
package models

// JwtDto carries an access token to a client.
type JwtDto struct {
	Token string `json:"token"`
}

// UserDto is what an application may learn about the person who signed in.
type UserDto struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// DeveloperApplicationDto is a developer application.
type DeveloperApplicationDto struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	OwnerID    string `json:"owner_id"`
	ClientType string `json:"client_type"`
}

// DeveloperApplicationWithCallbackURIDto is a developer application together
// with the exact URIs it may be returned to.
type DeveloperApplicationWithCallbackURIDto struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	OwnerID      string   `json:"owner_id"`
	ClientType   string   `json:"client_type"`
	CallbackUris []string `json:"callback_uris"`
}

// CreateDeveloperApplicationDto is a developer application and, for a
// confidential one, its refresh token, which is the only time the token is
// readable. A public client has no token, and the member is absent.
type CreateDeveloperApplicationDto struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	OwnerID    string `json:"owner_id"`
	ClientType string `json:"client_type"`
	Token      string `json:"token,omitempty"`
}

// DeveloperApplicationName names an application being created.
type DeveloperApplicationName struct {
	Name string `json:"name"`
}

// LoginDeveloperApplicationDto is an application's own credentials.
type LoginDeveloperApplicationDto struct {
	ID           string `json:"id"`
	RefreshToken string `json:"refresh_token"`
}

// ProviderSelectionDto is what the provider selection page displays, and
// nothing else.
type ProviderSelectionDto struct {
	ApplicationName string   `json:"application_name"`
	ExpiresAt       string   `json:"expires_at"`
	Providers       []string `json:"providers"`
}

// PendingConsentDto is what the consent screen displays, and nothing else.
type PendingConsentDto struct {
	ApplicationName string   `json:"application_name"`
	Scopes          []string `json:"scopes"`
	ExpiresAt       string   `json:"expires_at"`
}

// TokenSetDto is a token endpoint's successful answer. The refresh members are
// present exactly when offline_access is granted.
type TokenSetDto struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int64  `json:"expires_in"`
	IDToken               string `json:"id_token"`
	Scope                 string `json:"scope"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in,omitempty"`
}

// UserInfoDto is the claims an access token's grant releases: the user's
// canonical AbandonAuth identifier, and the username only under profile.
type UserInfoDto struct {
	Subject           string  `json:"sub"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
}

// OpenIDProviderMetadataDto is the discovery document, with exactly the
// members of the implemented profile.
type OpenIDProviderMetadataDto struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	UserInfoEndpoint                       string   `json:"userinfo_endpoint"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	JWKSURI                                string   `json:"jwks_uri"`
	AccessTokenJWKSURI                     string   `json:"access_token_jwks_uri"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	ResponseModesSupported                 []string `json:"response_modes_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                        []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssSupported      bool     `json:"authorization_response_iss_parameter_supported"`
}
