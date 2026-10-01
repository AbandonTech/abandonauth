// AbandonAuth is an identity provider and OAuth application broker.
//
// @title                      AbandonAuth
// @version                    0.0.1
// @description                Identity provider and OAuth application broker.
// @securityDefinitions.apikey JWTBearer
// @in                         header
// @name                       Authorization
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/urfave/cli/v3"

	"github.com/abandontech/abandonauth/src/api/internal/buildmode"
	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/services/siteapplication"
	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
	"github.com/abandontech/abandonauth/src/api/internal/web"
)

// version identifies the build in the API schema, in log lines and in image
// labels.
const version = "0.0.1"

// buildServesDevelopmentRoutes reports whether this binary was compiled with the
// password sign-in and documentation routes.
const buildServesDevelopmentRoutes = buildmode.Devtools

// Command-line names of the settings that carry no secret. Each also reads the
// environment variable named alongside it in settingFlags.
const (
	flagBindAddress           = "bind-address"
	flagDebug                 = "debug"
	flagVerbose               = "verbose"
	flagPretty                = "pretty"
	flagSigningAlgorithm      = "jwt-hashing-algo"
	flagExchangeCodeSeconds   = "exchange-code-seconds"
	flagBrowserSessionSeconds = "browser-session-seconds"
	flagInternalApplicationID = "internal-application-id"
	flagSiteURL               = "site-url"
	flagAPIURL                = "api-url"
	flagDiscordClientID       = "discord-client-id"
	flagDiscordCallback       = "discord-callback"
	flagGitHubClientID        = "github-client-id"
	flagGitHubCallback        = "github-callback"
	flagGoogleClientID        = "google-client-id"
	flagGoogleCallback        = "google-callback"
	flagTrustedProxyCIDRs     = "trusted-proxy-cidrs"
)

// Command-line names of the provision command's inputs. Neither reads the
// environment, so an unset one is never filled in from a deployment's settings.
const (
	flagProvisionApplicationID = "application-id"
	flagProvisionSiteURL       = "site-url"
)

// environmentApplicationID is the setting the provisioned identifier is
// reported under, so an operator can copy the line into a deployment's
// environment.
const environmentApplicationID = "ABANDON_AUTH_DEVELOPER_APP_ID"

// Environment variables the secrets are read from. They have no command-line
// equivalent, because an argument is readable by every process on the machine
// and is recorded by whatever started this one.
const (
	environmentDatabaseURL         = "DATABASE_URL"
	environmentSigningSecret       = "JWT_SECRET"
	environmentDiscordClientSecret = "DISCORD_CLIENT_SECRET"
	environmentGitHubClientSecret  = "GITHUB_CLIENT_SECRET"
	environmentGoogleClientSecret  = "GOOGLE_CLIENT_SECRET"
)

// operations is the work behind each command, kept behind an interface so the
// command tree, the settings it collects and the validation it applies can be
// exercised without opening a listener or a database connection.
type operations interface {
	Serve(ctx context.Context, configuration config.Config) error
	Maintenance(ctx context.Context, address string) error
	RotateAuthority(ctx context.Context, configuration config.Config) error
	Provision(
		ctx context.Context, databaseURL config.Secret, applicationID uuid.UUID, callback string,
	) (siteapplication.Outcome, error)
}

func main() {
	// A stop signal cancels the context, which is how a request in flight is
	// given the chance to finish before the process exits.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newCommand(service{}).Run(ctx, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "abandonauth:", err)
		os.Exit(1)
	}
}

func newCommand(perform operations) *cli.Command {
	return &cli.Command{
		Name:                  "abandonauth",
		Usage:                 "run the AbandonAuth identity service",
		Version:               version,
		Flags:                 settingFlags(),
		EnableShellCompletion: true,
		Commands: []*cli.Command{
			serveCommand(perform),
			maintenanceCommand(perform),
			databaseCommand(perform),
			provisionCommand(perform),
		},
		// There is deliberately no default command. A mistyped command must not
		// fall through to one that starts serving requests.
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Present() {
				return fmt.Errorf("unknown command %q", cmd.Args().First())
			}

			return cli.ShowAppHelp(cmd)
		},
	}
}

func serveCommand(perform operations) *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "answer API requests",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			configuration, err := configure(cmd)
			if err != nil {
				return err
			}

			return perform.Serve(ctx, configuration)
		},
	}
}

func maintenanceCommand(perform operations) *cli.Command {
	return &cli.Command{
		Name: "maintenance",
		Usage: "answer every request with a temporary failure, " +
			"for a deployment that must not serve",
		Description: "Nothing is read from the database and no credential is accepted, so this command " +
			"starts even when the settings a serving deployment needs are absent or wrong.",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			address := cmd.String(flagBindAddress)
			if address == "" {
				address = config.DefaultBindAddress
			}

			return perform.Maintenance(ctx, address)
		},
	}
}

func databaseCommand(perform operations) *cli.Command {
	return &cli.Command{
		Name:  "database",
		Usage: "operate on the authority behind issued credentials",
		Commands: []*cli.Command{
			{
				Name:  "rotate-auth-epoch",
				Usage: "withdraw every issued credential and install a new authority",
				Description: "Every access token, login in progress, one-time code and browser session " +
					"stops being accepted. Run it during a maintenance window, and after every change " +
					"of the signing secret.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					configuration, err := configure(cmd)
					if err != nil {
						return err
					}

					return perform.RotateAuthority(ctx, configuration)
				},
			},
		},
	}
}

func provisionCommand(perform operations) *cli.Command {
	return &cli.Command{
		Name:  "provision",
		Usage: "create the developer application that represents the AbandonAuth site",
		Description: "Creates an owner nobody can sign in as, the application under the given identifier, " +
			"and the site's callback, together. When an application already holds the identifier nothing " +
			"is changed. Without flags it asks for both inputs; with flags it asks for nothing and needs both. " +
			"The database is read from DATABASE_URL only.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  flagProvisionApplicationID,
				Usage: "the `UUID` the site's application is created under, kept stable for the deployment's life",
				Local: true,
			},
			&cli.StringFlag{
				Name:  flagProvisionSiteURL,
				Usage: "the `ORIGIN` the AbandonAuth site is served from; the site's callback is this origin followed by " + web.SiteEntryPath,
				Local: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// The arguments are not repeated: a value typed in the wrong place may
			// be the one secret this command must not print.
			if cmd.Args().Present() {
				return errors.New("provision takes no positional arguments")
			}

			databaseURL, err := config.ParseDatabaseURL(os.Getenv(environmentDatabaseURL))
			if err != nil {
				return err
			}

			rawID, rawOrigin, err := provisionInputs(ctx, cmd)
			if err != nil {
				return err
			}

			applicationID, callback, err := provisioningTarget(rawID, rawOrigin, cmd.Bool(flagDebug))
			if err != nil {
				return err
			}

			outcome, err := perform.Provision(ctx, databaseURL, applicationID, callback)
			if err != nil {
				return err
			}

			if outcome == siteapplication.AlreadyPresent {
				fmt.Fprintln(cmd.ErrWriter, "an application already holds this identifier; nothing was changed")
			} else {
				fmt.Fprintln(cmd.ErrWriter, "the site's application was created")
			}

			_, err = fmt.Fprintf(cmd.Writer, "%s=%s\n", environmentApplicationID, applicationID)

			return err
		},
	}
}

// provisionInputs reads both inputs from their flags when either is given, and
// otherwise asks for both. Given one flag, it never asks for the other: a
// command run by automation must fail rather than wait for an answer.
func provisionInputs(ctx context.Context, cmd *cli.Command) (string, string, error) {
	idGiven := cmd.IsSet(flagProvisionApplicationID)
	originGiven := cmd.IsSet(flagProvisionSiteURL)

	if idGiven || originGiven {
		if !idGiven || !originGiven {
			return "", "", fmt.Errorf(
				"--%s and --%s are given together or not at all", flagProvisionApplicationID, flagProvisionSiteURL,
			)
		}

		return cmd.String(flagProvisionApplicationID), cmd.String(flagProvisionSiteURL), nil
	}

	answers := bufio.NewReader(cmd.Reader)

	rawID, err := ask(ctx, answers, cmd.ErrWriter, "application UUID", "Application UUID: ")
	if err != nil {
		return "", "", err
	}

	rawOrigin, err := ask(ctx, answers, cmd.ErrWriter, "site origin", "Site origin (for example https://auth.example.com): ")
	if err != nil {
		return "", "", err
	}

	return rawID, rawOrigin, nil
}

// ask reads one line in answer to a prompt. End of input without an answer is a
// failure rather than a reason to ask again, and a stop signal ends the wait.
func ask(ctx context.Context, answers *bufio.Reader, prompts io.Writer, subject, prompt string) (string, error) {
	fmt.Fprint(prompts, prompt)

	type reply struct {
		line string
		err  error
	}

	replied := make(chan reply, 1)

	go func() {
		line, err := answers.ReadString('\n')
		replied <- reply{line, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case answer := <-replied:
		if answer.err != nil && !errors.Is(answer.err, io.EOF) {
			return "", fmt.Errorf("reading the %s: %w", subject, answer.err)
		}

		line := strings.TrimSpace(answer.line)
		if line == "" {
			return "", fmt.Errorf("no %s was given", subject)
		}

		return line, nil
	}
}

// provisioningTarget validates the identifier and the site origin, and derives
// the callback the site's own sign-in returns a browser to.
//
// The origin is judged by the rules serving applies for this build and debug
// setting. The callback keeps the origin's spelling, because the site builds
// the same address from the same setting and the two are matched exactly; only
// the one trailing slash an origin may carry is dropped before the path.
func provisioningTarget(rawID, rawOrigin string, debug bool) (uuid.UUID, string, error) {
	applicationID, err := uuid.Parse(rawID)
	if err != nil {
		return uuid.Nil, "", errors.New("the application identifier must be a UUID")
	}

	if applicationID == uuid.Nil {
		return uuid.Nil, "", siteapplication.ErrNilApplicationID
	}

	if _, err := config.ParseSiteOrigin(rawOrigin, debug, buildServesDevelopmentRoutes); err != nil {
		return uuid.Nil, "", err
	}

	callback := strings.TrimSuffix(rawOrigin, "/") + web.SiteEntryPath

	if _, err := urlpolicy.ParseRegisteredCallbackURI(callback); err != nil {
		return uuid.Nil, "", fmt.Errorf("the site origin does not make a callback this service will return a browser to: %w", err)
	}

	return applicationID, callback, nil
}

// configure collects the settings and validates them, so that no command starts
// work against a configuration the service would refuse to serve with.
func configure(cmd *cli.Command) (config.Config, error) {
	return config.Load(config.Settings{
		BindAddress:      cmd.String(flagBindAddress),
		Debug:            cmd.Bool(flagDebug),
		Verbose:          cmd.Bool(flagVerbose),
		Pretty:           cmd.Bool(flagPretty),
		DevelopmentBuild: buildServesDevelopmentRoutes,

		DatabaseURL: os.Getenv(environmentDatabaseURL),

		SigningSecret:         os.Getenv(environmentSigningSecret),
		SigningAlgorithm:      cmd.String(flagSigningAlgorithm),
		ExchangeCodeSeconds:   cmd.Int(flagExchangeCodeSeconds),
		BrowserSessionSeconds: cmd.Int(flagBrowserSessionSeconds),

		InternalApplicationID: cmd.String(flagInternalApplicationID),

		SiteURL: cmd.String(flagSiteURL),
		APIURL:  cmd.String(flagAPIURL),

		DiscordClientID:     cmd.String(flagDiscordClientID),
		DiscordClientSecret: os.Getenv(environmentDiscordClientSecret),
		DiscordCallback:     cmd.String(flagDiscordCallback),

		GitHubClientID:     cmd.String(flagGitHubClientID),
		GitHubClientSecret: os.Getenv(environmentGitHubClientSecret),
		GitHubCallback:     cmd.String(flagGitHubCallback),

		GoogleClientID:     cmd.String(flagGoogleClientID),
		GoogleClientSecret: os.Getenv(environmentGoogleClientSecret),
		GoogleCallback:     cmd.String(flagGoogleCallback),

		TrustedProxyCIDRs: cmd.String(flagTrustedProxyCIDRs),
	})
}

func settingFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    flagBindAddress,
			Usage:   "the `HOST:PORT` to listen on",
			Value:   config.DefaultBindAddress,
			Sources: cli.EnvVars("BIND_ADDRESS"),
		},
		&cli.BoolFlag{
			Name:    flagDebug,
			Usage:   "relax transport rules for local development; refused by a build that cannot serve them",
			Sources: cli.EnvVars("DEBUG"),
		},
		&cli.BoolFlag{
			Name:  flagVerbose,
			Usage: "log at debug level; it does not widen what any log event may contain",
		},
		&cli.BoolFlag{
			Name:  flagPretty,
			Usage: "write human-readable log lines instead of JSON",
		},
		&cli.StringFlag{
			Name:    flagSigningAlgorithm,
			Usage:   "the token signing `ALGORITHM`; the only accepted value is HS512",
			Value:   config.SigningAlgorithm,
			Sources: cli.EnvVars("JWT_HASHING_ALGO"),
		},
		&cli.IntFlag{
			Name:    flagExchangeCodeSeconds,
			Usage:   "how many `SECONDS` a one-time code handed to an application stays usable",
			Value:   config.DefaultExchangeCodeSeconds,
			Sources: cli.EnvVars("JWT_EXPIRES_IN_SECONDS_SHORT_LIVED"),
		},
		&cli.IntFlag{
			Name:    flagBrowserSessionSeconds,
			Usage:   "how many `SECONDS` a browser stays signed in",
			Value:   config.DefaultBrowserSessionSeconds,
			Sources: cli.EnvVars("JWT_EXPIRES_IN_SECONDS_LONG_LIVED"),
		},
		&cli.StringFlag{
			Name:    flagInternalApplicationID,
			Usage:   "the `UUID` of the developer application that represents the AbandonAuth site itself",
			Sources: cli.EnvVars(environmentApplicationID),
		},
		&cli.StringFlag{
			Name:    flagSiteURL,
			Usage:   "the `ORIGIN` the AbandonAuth site is served from",
			Sources: cli.EnvVars("ABANDON_AUTH_SITE_URL"),
		},
		&cli.StringFlag{
			Name:    flagAPIURL,
			Usage:   "the `ORIGIN` this API is reached at, which is also the issuer of its tokens",
			Sources: cli.EnvVars("ABANDON_AUTH_URL"),
		},
		&cli.StringFlag{
			Name:    flagDiscordClientID,
			Usage:   "the Discord application's client `ID`",
			Sources: cli.EnvVars("DISCORD_CLIENT_ID"),
		},
		&cli.StringFlag{
			Name:    flagDiscordCallback,
			Usage:   "the `URI` registered with Discord for this service",
			Sources: cli.EnvVars("ABANDON_AUTH_DISCORD_CALLBACK"),
		},
		&cli.StringFlag{
			Name:    flagGitHubClientID,
			Usage:   "the GitHub application's client `ID`",
			Sources: cli.EnvVars("GITHUB_CLIENT_ID"),
		},
		&cli.StringFlag{
			Name:    flagGitHubCallback,
			Usage:   "the `URI` registered with GitHub for this service",
			Sources: cli.EnvVars("ABANDON_AUTH_GITHUB_CALLBACK"),
		},
		&cli.StringFlag{
			Name:    flagGoogleClientID,
			Usage:   "the Google application's client `ID`",
			Sources: cli.EnvVars("GOOGLE_CLIENT_ID"),
		},
		&cli.StringFlag{
			Name:    flagGoogleCallback,
			Usage:   "the `URI` registered with Google for this service",
			Sources: cli.EnvVars("GOOGLE_CALLBACK"),
		},
		&cli.StringFlag{
			Name: flagTrustedProxyCIDRs,
			Usage: "comma-separated `RANGES` whose forwarding headers name the real client; " +
				"a header from any other peer is ignored",
			Value:   config.DefaultTrustedProxyCIDRs,
			Sources: cli.EnvVars("TRUSTED_PROXY_CIDRS"),
		},
	}
}
