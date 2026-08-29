package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/abandontech/abandonauth/src/api/internal/config"
)

// placeholders are settings that pass validation. None of them is a real
// credential: the signing secret is a repeated word long enough to satisfy the
// length rule, and the client secrets name themselves.
const (
	placeholderDatabaseURL   = "postgres://abandonauth:abandonauth@127.0.0.1:5432/abandonauth"
	placeholderSigningSecret = "placeholder-signing-secret-placeholder-signing-secret-placeholder"
	placeholderApplicationID = "6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0"
)

func placeholderEnvironment() map[string]string {
	return map[string]string{
		"DATABASE_URL":                       placeholderDatabaseURL,
		"JWT_SECRET":                         placeholderSigningSecret,
		"JWT_HASHING_ALGO":                   "HS512",
		"JWT_EXPIRES_IN_SECONDS_SHORT_LIVED": "120",
		"JWT_EXPIRES_IN_SECONDS_LONG_LIVED":  "2592000",
		"ABANDON_AUTH_DEVELOPER_APP_ID":      placeholderApplicationID,
		"ABANDON_AUTH_SITE_URL":              "https://auth.example.test",
		"ABANDON_AUTH_URL":                   "https://api.auth.example.test",
		"DISCORD_CLIENT_ID":                  "discord-client-id",
		"DISCORD_CLIENT_SECRET":              "discord-client-secret-placeholder",
		"ABANDON_AUTH_DISCORD_CALLBACK":      "https://api.auth.example.test/ui/discord-callback",
		"GITHUB_CLIENT_ID":                   "github-client-id",
		"GITHUB_CLIENT_SECRET":               "github-client-secret-placeholder",
		"ABANDON_AUTH_GITHUB_CALLBACK":       "https://api.auth.example.test/ui/github-callback",
		"GOOGLE_CLIENT_ID":                   "google-client-id",
		"GOOGLE_CLIENT_SECRET":               "google-client-secret-placeholder",
		"GOOGLE_CALLBACK":                    "https://api.auth.example.test/google",
	}
}

func applyEnvironment(t *testing.T, environment map[string]string) {
	t.Helper()

	for name, value := range environment {
		t.Setenv(name, value)
	}
}

// recorder stands in for the work each command does, so the command tree, the
// settings it collects and the validation it applies can be tested without
// opening a listener or a database connection.
type recorder struct {
	served              bool
	maintained          bool
	adopted             bool
	rotated             bool
	verifyOnly          bool
	maintenanceAddress  string
	configuration       config.Config
	errorToReturnOnCall error
}

func (r *recorder) Serve(_ context.Context, configuration config.Config) error {
	r.served = true
	r.configuration = configuration

	return r.errorToReturnOnCall
}

func (r *recorder) Maintenance(_ context.Context, address string) error {
	r.maintained = true
	r.maintenanceAddress = address

	return r.errorToReturnOnCall
}

func (r *recorder) AdoptExistingSchema(_ context.Context, configuration config.Config, verifyOnly bool) error {
	r.adopted = true
	r.verifyOnly = verifyOnly
	r.configuration = configuration

	return r.errorToReturnOnCall
}

func (r *recorder) RotateAuthority(_ context.Context, configuration config.Config) error {
	r.rotated = true
	r.configuration = configuration

	return r.errorToReturnOnCall
}

func runCommand(t *testing.T, arguments ...string) (*recorder, error) {
	t.Helper()

	perform := &recorder{}
	err := newCommand(perform).Run(t.Context(), append([]string{"abandonauth"}, arguments...))

	return perform, err
}

func TestServeReadsEverySettingFromItsEnvironmentName(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment())

	perform, err := runCommand(t, "serve")
	if err != nil {
		t.Fatalf("serve failed: %v", err)
	}

	if !perform.served {
		t.Fatal("serve did not run")
	}

	loaded := perform.configuration

	if loaded.DatabaseURL.Reveal() != placeholderDatabaseURL {
		t.Error("DATABASE_URL did not reach the configuration")
	}

	if loaded.SigningSecret.Reveal() != placeholderSigningSecret {
		t.Error("JWT_SECRET did not reach the configuration")
	}

	if loaded.InternalApplicationID.String() != placeholderApplicationID {
		t.Errorf("ABANDON_AUTH_DEVELOPER_APP_ID reached the configuration as %q", loaded.InternalApplicationID)
	}

	if loaded.Site.String() != "https://auth.example.test" {
		t.Errorf("ABANDON_AUTH_SITE_URL reached the configuration as %q", loaded.Site)
	}

	if loaded.API.String() != "https://api.auth.example.test" {
		t.Errorf("ABANDON_AUTH_URL reached the configuration as %q", loaded.API)
	}

	if loaded.ExchangeCodeLifetime.Seconds() != 120 {
		t.Errorf("JWT_EXPIRES_IN_SECONDS_SHORT_LIVED reached the configuration as %v", loaded.ExchangeCodeLifetime)
	}

	if loaded.BrowserSessionLifetime.Hours() != 720 {
		t.Errorf("JWT_EXPIRES_IN_SECONDS_LONG_LIVED reached the configuration as %v", loaded.BrowserSessionLifetime)
	}

	providers := map[string]config.Provider{
		"Discord": loaded.Discord,
		"GitHub":  loaded.GitHub,
		"Google":  loaded.Google,
	}

	for name, provider := range providers {
		if provider.ClientID == "" || provider.ClientSecret.IsEmpty() || provider.Callback == nil {
			t.Errorf("the %s registration did not reach the configuration: %+v", name, provider)
		}
	}
}

func TestServeBindsToPortEightThousandByDefault(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment())

	perform, err := runCommand(t, "serve")
	if err != nil {
		t.Fatalf("serve failed: %v", err)
	}

	if perform.configuration.BindAddress != config.DefaultBindAddress {
		t.Errorf("bind address = %q, want %q", perform.configuration.BindAddress, config.DefaultBindAddress)
	}
}

func TestSettingsAreAlsoAcceptedOnTheCommandLine(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment())

	perform, err := runCommand(t, "--bind-address", "127.0.0.1:9000", "serve")
	if err != nil {
		t.Fatalf("serve failed: %v", err)
	}

	if perform.configuration.BindAddress != "127.0.0.1:9000" {
		t.Errorf("bind address = %q, want the value given on the command line", perform.configuration.BindAddress)
	}
}

func TestAMissingRequiredSettingStopsTheCommandWithoutRevealingIt(t *testing.T) {
	environment := placeholderEnvironment()
	delete(environment, "JWT_SECRET")

	applyEnvironment(t, environment)
	t.Setenv("JWT_SECRET", "")

	perform, err := runCommand(t, "serve")
	if err == nil {
		t.Fatal("serve started without a signing secret")
	}

	if perform.served {
		t.Error("serve ran despite the invalid configuration")
	}

	if !strings.Contains(err.Error(), "JWT_SECRET") {
		t.Errorf("the error does not name the setting: %v", err)
	}
}

func TestAnInvalidSettingValueIsNotRepeatedInTheError(t *testing.T) {
	environment := placeholderEnvironment()
	environment["JWT_SECRET"] = "too-short"

	applyEnvironment(t, environment)

	_, err := runCommand(t, "serve")
	if err == nil {
		t.Fatal("serve started with a signing secret below the minimum length")
	}

	if strings.Contains(err.Error(), "too-short") {
		t.Errorf("the error repeats the rejected value: %v", err)
	}
}

func TestMaintenanceNeedsOnlyAnAddress(t *testing.T) {
	perform, err := runCommand(t, "maintenance")
	if err != nil {
		t.Fatalf("maintenance failed with no settings configured: %v", err)
	}

	if !perform.maintained {
		t.Fatal("maintenance did not run")
	}

	if perform.maintenanceAddress != config.DefaultBindAddress {
		t.Errorf("maintenance address = %q, want %q", perform.maintenanceAddress, config.DefaultBindAddress)
	}
}

func TestDatabaseCommands(t *testing.T) {
	tests := []struct {
		name       string
		arguments  []string
		wantAdopt  bool
		wantRotate bool
		wantVerify bool
	}{
		{
			name:      "adoption changes the database",
			arguments: []string{"database", "adopt-existing-schema"},
			wantAdopt: true,
		},
		{
			name:       "adoption can only report",
			arguments:  []string{"database", "adopt-existing-schema", "--verify-only"},
			wantAdopt:  true,
			wantVerify: true,
		},
		{
			name:       "rotation replaces the authority",
			arguments:  []string{"database", "rotate-auth-epoch"},
			wantRotate: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			applyEnvironment(t, placeholderEnvironment())

			perform, err := runCommand(t, test.arguments...)
			if err != nil {
				t.Fatalf("%v failed: %v", test.arguments, err)
			}

			if perform.adopted != test.wantAdopt {
				t.Errorf("adoption ran = %t, want %t", perform.adopted, test.wantAdopt)
			}

			if perform.rotated != test.wantRotate {
				t.Errorf("rotation ran = %t, want %t", perform.rotated, test.wantRotate)
			}

			if perform.verifyOnly != test.wantVerify {
				t.Errorf("verify-only = %t, want %t", perform.verifyOnly, test.wantVerify)
			}
		})
	}
}

func TestAnUnknownCommandIsRefused(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment())

	perform, err := runCommand(t, "migrate-everything")
	if err == nil {
		t.Fatal("an unknown command was accepted")
	}

	if perform.served || perform.adopted || perform.rotated || perform.maintained {
		t.Error("an unknown command ran one of the real commands")
	}
}

func TestCommandFailuresAreReported(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment())

	perform := &recorder{errorToReturnOnCall: errors.New("the database did not answer")}

	err := newCommand(perform).Run(t.Context(), []string{"abandonauth", "serve"})
	if err == nil {
		t.Fatal("a failing command reported success")
	}
}

func TestDebugModeIsRefusedByABuildThatCannotServeIt(t *testing.T) {
	if buildServesDevelopmentRoutes {
		t.Skip("this build compiles the development routes in")
	}

	environment := placeholderEnvironment()
	environment["DEBUG"] = "true"

	applyEnvironment(t, environment)

	perform, err := runCommand(t, "serve")
	if err == nil {
		t.Fatal("the production build accepted DEBUG=true")
	}

	if perform.served {
		t.Error("the production build served with debug mode requested")
	}
}

func TestEveryCommandIsDocumented(t *testing.T) {
	var check func(commands []*cli.Command, path string)

	check = func(commands []*cli.Command, path string) {
		for _, command := range commands {
			name := strings.TrimSpace(path + " " + command.Name)

			if command.Usage == "" {
				t.Errorf("command %q has no usage line", name)
			}

			check(command.Commands, name)
		}
	}

	root := newCommand(&recorder{})

	if root.Usage == "" {
		t.Error("the root command has no usage line")
	}

	check(root.Commands, "")

	for _, flag := range root.Flags {
		documented, ok := flag.(interface{ GetUsage() string })
		if !ok || documented.GetUsage() == "" {
			t.Errorf("flag %v has no usage line", flag.Names())
		}
	}
}
