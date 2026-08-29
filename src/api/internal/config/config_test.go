package config_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/config"
)

const (
	// A 64 byte value, the shortest signing secret the service accepts.
	placeholderSigningSecret = "0000000000000000000000000000000000000000000000000000000000000000"
	placeholderApplicationID = "cd022be1-35af-4248-8d70-4205ed1c20c6"
)

// productionSettings returns a complete, valid set of production settings.
// Individual tests change one field to show which rule rejects it.
func productionSettings() config.Settings {
	return config.Settings{
		DatabaseURL:           "postgresql://abandonauth:placeholder@database:5432/abandonauth",
		SigningSecret:         placeholderSigningSecret,
		SigningAlgorithm:      "HS512",
		ExchangeCodeSeconds:   120,
		BrowserSessionSeconds: 2592000,
		InternalApplicationID: placeholderApplicationID,
		SiteURL:               "https://auth.example.test",
		APIURL:                "https://api.example.test",
		DiscordClientID:       "1002632179794329630",
		DiscordClientSecret:   "placeholder-discord-secret",
		DiscordCallback:       "https://api.example.test/api/ui/discord-callback",
		GitHubClientID:        "e2e4eac6e97af84d9f69",
		GitHubClientSecret:    "placeholder-github-secret",
		GitHubCallback:        "https://api.example.test/api/ui/github-callback",
		GoogleClientID:        "placeholder.apps.googleusercontent.com",
		GoogleClientSecret:    "placeholder-google-secret",
		GoogleCallback:        "https://api.example.test/api/google",
	}
}

func developmentSettings() config.Settings {
	settings := productionSettings()
	settings.DevelopmentBuild = true
	settings.Debug = true
	settings.SiteURL = "http://localhost:3000"
	settings.APIURL = "http://localhost:8000"
	settings.DiscordCallback = "http://localhost:8000/ui/discord-callback"
	settings.GitHubCallback = "http://localhost:8000/ui/github-callback"
	settings.GoogleCallback = "http://localhost:8000/google"

	return settings
}

func TestLoadAcceptsProductionSettings(t *testing.T) {
	t.Parallel()

	loaded, err := config.Load(productionSettings())
	if err != nil {
		t.Fatalf("Load() = %v, want no error", err)
	}

	if loaded.BindAddress != "0.0.0.0:8000" {
		t.Errorf("BindAddress = %q, want 0.0.0.0:8000", loaded.BindAddress)
	}

	if loaded.Site.String() != "https://auth.example.test" {
		t.Errorf("Site = %q", loaded.Site)
	}

	if loaded.API.String() != "https://api.example.test" {
		t.Errorf("API = %q", loaded.API)
	}

	if loaded.InternalApplicationID.String() != placeholderApplicationID {
		t.Errorf("InternalApplicationID = %q", loaded.InternalApplicationID)
	}

	if loaded.ExchangeCodeLifetime != 120*time.Second {
		t.Errorf("ExchangeCodeLifetime = %v, want 2m", loaded.ExchangeCodeLifetime)
	}

	if loaded.BrowserSessionLifetime != 30*24*time.Hour {
		t.Errorf("BrowserSessionLifetime = %v, want 720h", loaded.BrowserSessionLifetime)
	}

	if loaded.Debug {
		t.Error("Debug = true for production settings")
	}

	if !loaded.RequireSecureCookies() {
		t.Error("RequireSecureCookies() = false for an https site")
	}
}

func TestLoadDefaultsTrustedProxiesToLoopback(t *testing.T) {
	t.Parallel()

	loaded, err := config.Load(productionSettings())
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	got := make([]string, 0, len(loaded.TrustedProxies))
	for _, prefix := range loaded.TrustedProxies {
		got = append(got, prefix.String())
	}

	want := []string{"127.0.0.1/32", "::1/128"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("TrustedProxies = %v, want %v", got, want)
	}
}

func TestLoadRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		change func(*config.Settings)
		// setting is the name that must appear in the error so an operator can
		// find what to fix.
		setting string
	}{
		{"no database url", func(s *config.Settings) { s.DatabaseURL = "" }, "DATABASE_URL"},
		{"database url is not postgres", func(s *config.Settings) { s.DatabaseURL = "mysql://host/db" }, "DATABASE_URL"},
		{"no signing secret", func(s *config.Settings) { s.SigningSecret = "" }, "JWT_SECRET"},
		{
			"short signing secret",
			func(s *config.Settings) { s.SigningSecret = strings.Repeat("a", 63) },
			"JWT_SECRET",
		},
		{"signing algorithm HS256", func(s *config.Settings) { s.SigningAlgorithm = "HS256" }, "JWT_HASHING_ALGO"},
		{"signing algorithm none", func(s *config.Settings) { s.SigningAlgorithm = "none" }, "JWT_HASHING_ALGO"},
		{"signing algorithm RS512", func(s *config.Settings) { s.SigningAlgorithm = "RS512" }, "JWT_HASHING_ALGO"},
		{"signing algorithm empty", func(s *config.Settings) { s.SigningAlgorithm = "" }, "JWT_HASHING_ALGO"},
		{
			"signing algorithm wrong case",
			func(s *config.Settings) { s.SigningAlgorithm = "hs512" },
			"JWT_HASHING_ALGO",
		},
		{
			"exchange lifetime zero",
			func(s *config.Settings) { s.ExchangeCodeSeconds = 0 },
			"JWT_EXPIRES_IN_SECONDS_SHORT_LIVED",
		},
		{
			"exchange lifetime negative",
			func(s *config.Settings) { s.ExchangeCodeSeconds = -1 },
			"JWT_EXPIRES_IN_SECONDS_SHORT_LIVED",
		},
		{
			"exchange lifetime above cap",
			func(s *config.Settings) { s.ExchangeCodeSeconds = 121 },
			"JWT_EXPIRES_IN_SECONDS_SHORT_LIVED",
		},
		{
			"session lifetime zero",
			func(s *config.Settings) { s.BrowserSessionSeconds = 0 },
			"JWT_EXPIRES_IN_SECONDS_LONG_LIVED",
		},
		{
			"session lifetime above cap",
			func(s *config.Settings) { s.BrowserSessionSeconds = 2592001 },
			"JWT_EXPIRES_IN_SECONDS_LONG_LIVED",
		},
		{
			"application id is not a uuid",
			func(s *config.Settings) { s.InternalApplicationID = "not-a-uuid" },
			"ABANDON_AUTH_DEVELOPER_APP_ID",
		},
		{
			"application id is empty",
			func(s *config.Settings) { s.InternalApplicationID = "" },
			"ABANDON_AUTH_DEVELOPER_APP_ID",
		},
		{"site url is http", func(s *config.Settings) { s.SiteURL = "http://auth.example.test" }, "ABANDON_AUTH_SITE_URL"},
		{
			"site url has a path",
			func(s *config.Settings) { s.SiteURL = "https://auth.example.test/app" },
			"ABANDON_AUTH_SITE_URL",
		},
		{
			"site url has a query",
			func(s *config.Settings) { s.SiteURL = "https://auth.example.test/?a=b" },
			"ABANDON_AUTH_SITE_URL",
		},
		{
			"site url has credentials",
			func(s *config.Settings) { s.SiteURL = "https://user:pw@auth.example.test" },
			"ABANDON_AUTH_SITE_URL",
		},
		{"site url is empty", func(s *config.Settings) { s.SiteURL = "" }, "ABANDON_AUTH_SITE_URL"},
		{"api url is http", func(s *config.Settings) { s.APIURL = "http://api.example.test" }, "ABANDON_AUTH_URL"},
		{"api url is empty", func(s *config.Settings) { s.APIURL = "" }, "ABANDON_AUTH_URL"},
		{"no discord client id", func(s *config.Settings) { s.DiscordClientID = "" }, "DISCORD_CLIENT_ID"},
		{"no discord client secret", func(s *config.Settings) { s.DiscordClientSecret = "" }, "DISCORD_CLIENT_SECRET"},
		{
			"discord callback is http",
			func(s *config.Settings) { s.DiscordCallback = "http://api.example.test/ui/discord-callback" },
			"ABANDON_AUTH_DISCORD_CALLBACK",
		},
		{
			"discord callback is relative",
			func(s *config.Settings) { s.DiscordCallback = "/ui/discord-callback" },
			"ABANDON_AUTH_DISCORD_CALLBACK",
		},
		{"no github client id", func(s *config.Settings) { s.GitHubClientID = "" }, "GITHUB_CLIENT_ID"},
		{"no github client secret", func(s *config.Settings) { s.GitHubClientSecret = "" }, "GITHUB_CLIENT_SECRET"},
		{
			"github callback has a fragment",
			func(s *config.Settings) { s.GitHubCallback = "https://api.example.test/ui/github-callback#x" },
			"ABANDON_AUTH_GITHUB_CALLBACK",
		},
		{"no google client id", func(s *config.Settings) { s.GoogleClientID = "" }, "GOOGLE_CLIENT_ID"},
		{"no google client secret", func(s *config.Settings) { s.GoogleClientSecret = "" }, "GOOGLE_CLIENT_SECRET"},
		{"no google callback", func(s *config.Settings) { s.GoogleCallback = "" }, "GOOGLE_CALLBACK"},
		{"debug in a production build", func(s *config.Settings) { s.Debug = true }, "DEBUG"},
		{
			"trusted proxy is not a prefix",
			func(s *config.Settings) { s.TrustedProxyCIDRs = "127.0.0.1" },
			"TRUSTED_PROXY_CIDRS",
		},
		{
			"trusted proxy is a host name",
			func(s *config.Settings) { s.TrustedProxyCIDRs = "proxy.example.test/32" },
			"TRUSTED_PROXY_CIDRS",
		},
		{
			"trusted proxy repeated",
			func(s *config.Settings) { s.TrustedProxyCIDRs = "10.0.0.0/8,10.0.0.0/8" },
			"TRUSTED_PROXY_CIDRS",
		},
		{
			"trusted proxy has an empty entry",
			func(s *config.Settings) { s.TrustedProxyCIDRs = "10.0.0.0/8,," },
			"TRUSTED_PROXY_CIDRS",
		},
		{"bind address has no port", func(s *config.Settings) { s.BindAddress = "0.0.0.0" }, "BIND_ADDRESS"},
		{"bind address port is zero", func(s *config.Settings) { s.BindAddress = "0.0.0.0:0" }, "BIND_ADDRESS"},
		{
			"bind address port is not a number",
			func(s *config.Settings) { s.BindAddress = "0.0.0.0:http" },
			"BIND_ADDRESS",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			settings := productionSettings()
			testCase.change(&settings)

			_, err := config.Load(settings)
			if err == nil {
				t.Fatalf("Load() = nil error, want rejection")
			}

			if !strings.Contains(err.Error(), testCase.setting) {
				t.Errorf("error %q does not name the setting %q", err, testCase.setting)
			}
		})
	}
}

// The development build may serve the site over plain HTTP on the loopback
// interface, and only there.
func TestLoadDevelopmentBuild(t *testing.T) {
	t.Parallel()

	loaded, err := config.Load(developmentSettings())
	if err != nil {
		t.Fatalf("Load() = %v, want no error", err)
	}

	if !loaded.Debug {
		t.Error("Debug = false")
	}

	if loaded.RequireSecureCookies() {
		t.Error("RequireSecureCookies() = true for a loopback site, cookies would never be sent")
	}

	remoteSite := developmentSettings()
	remoteSite.SiteURL = "http://auth.example.test"

	if _, err := config.Load(remoteSite); err == nil {
		t.Error("Load() accepted plain http for a site that is not on the loopback interface")
	}
}

// A development build that is not in debug mode is a production deployment and
// must satisfy every production rule.
func TestDevelopmentBuildWithoutDebugIsStrict(t *testing.T) {
	t.Parallel()

	settings := developmentSettings()
	settings.Debug = false

	if _, err := config.Load(settings); err == nil {
		t.Fatal("Load() accepted a plain http site without debug mode")
	}
}

// Password sign-in reaches accounts without a provider, so the development build
// refuses to offer it on an address other machines can reach.
func TestPasswordSignInRequiresLoopbackBind(t *testing.T) {
	t.Parallel()

	cases := []struct {
		bind string
		want bool
	}{
		{"127.0.0.1:8000", true},
		{"localhost:8000", true},
		{"[::1]:8000", true},
		{"0.0.0.0:8000", false},
		{"192.168.1.10:8000", false},
		{":8000", false},
	}

	for _, testCase := range cases {
		t.Run(testCase.bind, func(t *testing.T) {
			t.Parallel()

			settings := developmentSettings()
			settings.BindAddress = testCase.bind

			loaded, err := config.Load(settings)
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}

			if loaded.PasswordSignInEnabled() != testCase.want {
				t.Errorf("PasswordSignInEnabled() = %v, want %v", loaded.PasswordSignInEnabled(), testCase.want)
			}
		})
	}
}

func TestPasswordSignInNeedsDebugAndDevelopmentBuild(t *testing.T) {
	t.Parallel()

	settings := developmentSettings()
	settings.BindAddress = "127.0.0.1:8000"
	settings.Debug = false
	settings.SiteURL = "https://auth.example.test"
	settings.APIURL = "https://api.example.test"
	settings.DiscordCallback = "https://api.example.test/ui/discord-callback"
	settings.GitHubCallback = "https://api.example.test/ui/github-callback"
	settings.GoogleCallback = "https://api.example.test/google"

	loaded, err := config.Load(settings)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	if loaded.PasswordSignInEnabled() {
		t.Error("PasswordSignInEnabled() = true without debug mode")
	}
}

func TestTrustedProxiesAreParsed(t *testing.T) {
	t.Parallel()

	settings := productionSettings()
	settings.TrustedProxyCIDRs = "10.0.0.0/8, 192.168.0.0/16 ,::1/128"

	loaded, err := config.Load(settings)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	if len(loaded.TrustedProxies) != 3 {
		t.Fatalf("TrustedProxies = %v, want 3 entries", loaded.TrustedProxies)
	}
}

// Nothing that prints a Config may reveal a secret, whether through fmt, the
// structured logger, or an error that embeds the value.
func TestSecretsAreNotPrintable(t *testing.T) {
	t.Parallel()

	loaded, err := config.Load(productionSettings())
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	rendered := []string{
		fmt.Sprintf("%v", loaded),
		fmt.Sprintf("%+v", loaded),
		fmt.Sprintf("%#v", loaded),
		fmt.Sprintf("%s", loaded.SigningSecret),
		fmt.Sprintf("%v", loaded.SigningSecret),
		fmt.Sprintf("%#v", loaded.DatabaseURL),
		loaded.SigningSecret.String(),
		loaded.DatabaseURL.String(),
	}

	encoded, err := json.Marshal(loaded)
	if err == nil {
		rendered = append(rendered, string(encoded))
	}

	secrets := []string{
		placeholderSigningSecret,
		"placeholder-discord-secret",
		"placeholder-github-secret",
		"placeholder-google-secret",
		"postgresql://abandonauth:placeholder@database:5432/abandonauth",
	}

	for _, text := range rendered {
		for _, secret := range secrets {
			if strings.Contains(text, secret) {
				t.Errorf("rendered configuration exposes a secret value")
			}
		}
	}

	if loaded.SigningSecret.Reveal() != placeholderSigningSecret {
		t.Error("Reveal() did not return the configured secret")
	}
}

func TestZeroSecretRevealsNothing(t *testing.T) {
	t.Parallel()

	var empty config.Secret

	if empty.Reveal() != "" {
		t.Error("zero Secret revealed a value")
	}

	if empty.String() == "" {
		t.Error("zero Secret should still render a redaction marker")
	}
}
