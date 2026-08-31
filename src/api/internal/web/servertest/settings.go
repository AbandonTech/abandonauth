package servertest

import "github.com/abandontech/abandonauth/src/api/internal/config"

// Settings a test service runs with. Every value is a placeholder. The signing
// secret is a repeated phrase long enough to pass the 64-byte minimum, and the
// hosts are under .test, which RFC 6761 reserves and which does not resolve.
const (
	// SigningSecret is the root the per-purpose signing keys are derived from.
	SigningSecret = "placeholder-signing-secret-placeholder-signing-secret-placeholder"
	// SiteOrigin is where the browser-facing site is served from.
	SiteOrigin = "https://auth.example.test"
	// APIOrigin is where this service is reached, and the issuer of its tokens.
	APIOrigin = "https://api.auth.example.test"
)

func placeholderSettings() config.Settings {
	return config.Settings{
		// The listener belongs to httptest; this address is only validated.
		BindAddress: "127.0.0.1:8000",

		// The connection string is replaced by the test database's own pool,
		// which is already open, so this only has to parse.
		DatabaseURL: "postgres://placeholder:placeholder@127.0.0.1:5432/placeholder",

		SigningSecret:         SigningSecret,
		SigningAlgorithm:      config.SigningAlgorithm,
		ExchangeCodeSeconds:   120,
		BrowserSessionSeconds: 2592000,

		// InternalApplicationID is filled in by New, from the application it
		// registers for the site.

		SiteURL: SiteOrigin,
		APIURL:  APIOrigin,

		DiscordClientID:     "discord-client-id",
		DiscordClientSecret: "discord-client-secret-placeholder",
		DiscordCallback:     APIOrigin + "/ui/discord-callback",

		GitHubClientID:     "github-client-id",
		GitHubClientSecret: "github-client-secret-placeholder",
		GitHubCallback:     APIOrigin + "/ui/github-callback",

		GoogleClientID:     "google-client-id",
		GoogleClientSecret: "google-client-secret-placeholder",
		GoogleCallback:     APIOrigin + "/google",

		TrustedProxyCIDRs: config.DefaultTrustedProxyCIDRs,
	}
}
