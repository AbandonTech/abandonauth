package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/urfave/cli/v3"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/oidc"
	"github.com/abandontech/abandonauth/src/api/internal/services/siteapplication"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// placeholders are settings that pass validation. None of them is a real
// credential: the signing secret is a repeated word long enough to satisfy the
// length rule, and the client secrets name themselves.
const (
	placeholderDatabaseURL   = "postgres://abandonauth:abandonauth@127.0.0.1:5432/abandonauth"
	placeholderSigningSecret = "placeholder-signing-secret-placeholder-signing-secret-placeholder"
	placeholderApplicationID = "00000000-0000-0000-0000-000000000001"
	placeholderAPIOrigin     = "https://auth.example.test:8443"
)

// placeholderEnvironment is a complete valid environment, with the command
// reading signing key files written for this test at run time.
func placeholderEnvironment(t *testing.T) map[string]string {
	t.Helper()

	keys := servertest.SigningKeyFiles(t)
	useSigningKeyFiles(t, keys.IDTokenFile, keys.AccessTokenFile)

	return map[string]string{
		"DATABASE_URL":                       placeholderDatabaseURL,
		"JWT_SECRET":                         placeholderSigningSecret,
		"JWT_HASHING_ALGO":                   "HS512",
		"JWT_EXPIRES_IN_SECONDS_SHORT_LIVED": "120",
		"JWT_EXPIRES_IN_SECONDS_LONG_LIVED":  "2592000",
		"ABANDON_AUTH_DEVELOPER_APP_ID":      placeholderApplicationID,
		"ABANDON_AUTH_SITE_URL":              "https://auth.example.test",
		"ABANDON_AUTH_URL":                   placeholderAPIOrigin,
		"DISCORD_CLIENT_ID":                  "discord-client-id",
		"DISCORD_CLIENT_SECRET":              "discord-client-secret-placeholder",
		"ABANDON_AUTH_DISCORD_CALLBACK":      placeholderAPIOrigin + "/ui/discord-callback",
		"GITHUB_CLIENT_ID":                   "github-client-id",
		"GITHUB_CLIENT_SECRET":               "github-client-secret-placeholder",
		"ABANDON_AUTH_GITHUB_CALLBACK":       placeholderAPIOrigin + "/ui/github-callback",
		"GOOGLE_CLIENT_ID":                   "google-client-id",
		"GOOGLE_CLIENT_SECRET":               "google-client-secret-placeholder",
		"GOOGLE_CALLBACK":                    placeholderAPIOrigin + "/google",
	}
}

// useSigningKeyFiles points the command at the given key files until the test
// ends.
func useSigningKeyFiles(t *testing.T, idToken, accessToken string) {
	t.Helper()

	mounted := signingKeyFiles
	signingKeyFiles.idToken, signingKeyFiles.accessToken = idToken, accessToken

	t.Cleanup(func() { signingKeyFiles = mounted })
}

func thumbprintOf(key *rsa.PrivateKey) string {
	return oidc.Thumbprint(
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	)
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
	rotated             bool
	provisioned         bool
	configuration       config.Config
	databaseURL         config.Secret
	applicationID       uuid.UUID
	callback            string
	outcomeToReturn     siteapplication.Outcome
	errorToReturnOnCall error
}

func (r *recorder) Serve(_ context.Context, configuration config.Config) error {
	r.served = true
	r.configuration = configuration

	return r.errorToReturnOnCall
}

func (r *recorder) RotateAuthority(_ context.Context, configuration config.Config) error {
	r.rotated = true
	r.configuration = configuration

	return r.errorToReturnOnCall
}

func (r *recorder) Provision(
	_ context.Context, databaseURL config.Secret, applicationID uuid.UUID, callback string,
) (siteapplication.Outcome, error) {
	r.provisioned = true
	r.databaseURL = databaseURL
	r.applicationID = applicationID
	r.callback = callback

	if r.outcomeToReturn == 0 {
		return siteapplication.Created, r.errorToReturnOnCall
	}

	return r.outcomeToReturn, r.errorToReturnOnCall
}

func runCommand(t *testing.T, arguments ...string) (*recorder, error) {
	t.Helper()

	perform := &recorder{}
	err := newCommand(perform).Run(t.Context(), append([]string{"abandonauth"}, arguments...))

	return perform, err
}

func TestServeReadsEverySettingFromItsEnvironmentName(t *testing.T) {
	environment := placeholderEnvironment(t)
	applyEnvironment(t, environment)

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

	if loaded.API.String() != placeholderAPIOrigin {
		t.Errorf("ABANDON_AUTH_URL reached the configuration as %q", loaded.API)
	}

	if loaded.OpenIDIssuer != placeholderAPIOrigin+"/api" {
		t.Errorf("the OpenID issuer is %q, want ABANDON_AUTH_URL followed by /api", loaded.OpenIDIssuer)
	}

	keys := servertest.SigningKeyFiles(t)

	if loaded.SigningKeys.IDToken().ActiveKeyID() != thumbprintOf(keys.IDTokenPrivate) {
		t.Error("the ID token signing key file did not reach the configuration")
	}

	if loaded.SigningKeys.AccessToken().ActiveKeyID() != thumbprintOf(keys.AccessTokenPrivate) {
		t.Error("the access token signing key file did not reach the configuration")
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
		if provider.ClientID == "" || provider.ClientSecret.IsEmpty() || provider.Callback.IsZero() {
			t.Errorf("the %s registration did not reach the configuration: %+v", name, provider)
		}
	}
}

func TestServeBindsToPortEightThousandByDefault(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment(t))

	perform, err := runCommand(t, "serve")
	if err != nil {
		t.Fatalf("serve failed: %v", err)
	}

	if perform.configuration.BindAddress != config.DefaultBindAddress {
		t.Errorf("bind address = %q, want %q", perform.configuration.BindAddress, config.DefaultBindAddress)
	}
}

func TestSettingsAreAlsoAcceptedOnCommandLine(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment(t))

	perform, err := runCommand(t, "--bind-address", "127.0.0.1:9000", "serve")
	if err != nil {
		t.Fatalf("serve failed: %v", err)
	}

	if perform.configuration.BindAddress != "127.0.0.1:9000" {
		t.Errorf("bind address = %q, want the value given on the command line", perform.configuration.BindAddress)
	}
}

func TestMissingRequiredSettingStopsCommandWithoutRevealingIt(t *testing.T) {
	environment := placeholderEnvironment(t)
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

func TestInvalidSettingValueIsNotRepeatedInError(t *testing.T) {
	environment := placeholderEnvironment(t)
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

func TestDatabaseCommands(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment(t))

	perform, err := runCommand(t, "database", "rotate-auth-epoch")
	if err != nil {
		t.Fatalf("rotating the authority failed: %v", err)
	}

	if !perform.rotated {
		t.Error("rotation did not run")
	}
}

func TestUnknownCommandIsRefused(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment(t))

	perform, err := runCommand(t, "migrate-everything")
	if err == nil {
		t.Fatal("an unknown command was accepted")
	}

	if perform.served || perform.rotated || perform.provisioned {
		t.Error("an unknown command ran one of the real commands")
	}
}

// Every top-level command is one this service supports; anything else that
// opened a listener would bypass the checks serving applies.
func TestOnlySupportedCommandsAreRegistered(t *testing.T) {
	want := []string{"serve", "database", "provision", "validate-config"}

	var registered []string
	for _, command := range newCommand(&recorder{}).Commands {
		registered = append(registered, command.Name)
	}

	if !slices.Equal(registered, want) {
		t.Errorf("registered commands = %v, want exactly %v", registered, want)
	}
}

// validate-config checks exactly what serving would and then says so, and
// nothing else: it opens no database or listener and prints no setting or key.
func TestValidateConfigReportsOnlyThatConfigurationIsValid(t *testing.T) {
	environment := placeholderEnvironment(t)
	applyEnvironment(t, environment)

	var output, diagnostics strings.Builder

	perform := &recorder{}
	command := newCommand(perform)
	command.Writer = &output
	command.ErrWriter = &diagnostics

	if err := command.Run(t.Context(), []string{"abandonauth", "validate-config"}); err != nil {
		t.Fatalf("validate-config refused a valid configuration: %v", err)
	}

	if output.String() != "configuration valid\n" {
		t.Errorf("validate-config printed %q, want exactly the fixed line", output.String())
	}

	if diagnostics.Len() != 0 {
		t.Errorf("validate-config wrote %q to the error stream", diagnostics.String())
	}

	if perform.served || perform.rotated || perform.provisioned {
		t.Error("validate-config did work beyond checking the configuration")
	}

	keyFile, err := os.ReadFile(signingKeyFiles.idToken)
	if err != nil {
		t.Fatalf("reading the test key file: %v", err)
	}

	if strings.Contains(output.String(), string(keyFile[200:240])) {
		t.Error("validate-config printed key material")
	}
}

// Every way a signing key file can be wrong stops validate-config and serve
// alike, repeating neither a file's contents nor a key.
func TestSigningKeyFilesAreRequiredAndNeverEchoed(t *testing.T) {
	const keySentinel = "AbandonAuthKeySentinel6Vq2Lp9Xz3Rt"

	for name, adjust := range map[string]func(*testing.T, map[string]string){
		"a missing ID token key file": func(t *testing.T, _ map[string]string) {
			useSigningKeyFiles(t, filepath.Join(t.TempDir(), "absent"), signingKeyFiles.accessToken)
		},
		"a missing access token key file": func(t *testing.T, _ map[string]string) {
			useSigningKeyFiles(t, signingKeyFiles.idToken, filepath.Join(t.TempDir(), "absent"))
		},
		"one key for both purposes": func(t *testing.T, _ map[string]string) {
			useSigningKeyFiles(t, signingKeyFiles.idToken, signingKeyFiles.idToken)
		},
		"different API and site hosts": func(_ *testing.T, e map[string]string) {
			e["ABANDON_AUTH_URL"] = "https://" + keySentinel + ".example.test"
		},
	} {
		t.Run(name, func(t *testing.T) {
			environment := placeholderEnvironment(t)
			adjust(t, environment)
			applyEnvironment(t, environment)

			for _, commandName := range []string{"validate-config", "serve"} {
				var output strings.Builder

				perform := &recorder{}
				command := newCommand(perform)
				command.Writer = &output

				err := command.Run(t.Context(), []string{"abandonauth", commandName})
				if err == nil {
					t.Fatalf("%s accepted %s", commandName, name)
				}

				if perform.served || output.Len() != 0 {
					t.Errorf("%s did work or printed despite %s", commandName, name)
				}

				if strings.Contains(err.Error(), keySentinel) || strings.Contains(err.Error(), "BEGIN PRIVATE KEY") {
					t.Errorf("%s repeated what it refused: %v", commandName, err)
				}
			}
		})
	}
}

func TestVersionFlagReportsBuildVersion(t *testing.T) {
	if version == "" {
		t.Fatal("the build carries no version")
	}

	var output strings.Builder

	command := newCommand(&recorder{})
	command.Writer = &output

	if err := command.Run(t.Context(), []string{"abandonauth", "--version"}); err != nil {
		t.Fatalf("--version failed: %v", err)
	}

	if want := "abandonauth version " + version + "\n"; output.String() != want {
		t.Errorf("--version printed %q, want %q", output.String(), want)
	}
}

func TestCommandFailuresAreReported(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment(t))

	perform := &recorder{errorToReturnOnCall: errors.New("the database did not answer")}

	err := newCommand(perform).Run(t.Context(), []string{"abandonauth", "serve"})
	if err == nil {
		t.Fatal("a failing command reported success")
	}
}

func TestDebugModeIsRefusedByBuildThatCannotServeIt(t *testing.T) {
	if buildServesDevelopmentRoutes {
		t.Skip("this build compiles the development routes in")
	}

	environment := placeholderEnvironment(t)
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

	for _, flag := range commandFlags(root) {
		documented, ok := flag.(interface{ GetUsage() string })
		if !ok || documented.GetUsage() == "" {
			t.Errorf("flag %v has no usage line", flag.Names())
		}
	}
}

// commandFlags returns the flags a command and every command below it accept.
func commandFlags(command *cli.Command) []cli.Flag {
	flags := append([]cli.Flag{}, command.Flags...)

	for _, below := range command.Commands {
		flags = append(flags, commandFlags(below)...)
	}

	return flags
}
