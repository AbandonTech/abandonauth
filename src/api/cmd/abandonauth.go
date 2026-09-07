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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/abandontech/abandonauth/src/api/internal/buildmode"
	"github.com/abandontech/abandonauth/src/api/internal/config"
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

// secretEnvironment lists those variables for the checks that must cover every
// one of them.
func secretEnvironment() []string {
	return []string{
		environmentDatabaseURL,
		environmentSigningSecret,
		environmentDiscordClientSecret,
		environmentGitHubClientSecret,
		environmentGoogleClientSecret,
	}
}

// Lifetimes a deployment that does not set them explicitly gets. Both are also
// bounded by the configuration rules, which reject a longer value.
const (
	defaultExchangeCodeSeconds   = 120
	defaultBrowserSessionSeconds = 2592000
)

// operations is the work behind each command, kept behind an interface so the
// command tree, the settings it collects and the validation it applies can be
// exercised without opening a listener or a database connection.
type operations interface {
	Serve(ctx context.Context, configuration config.Config) error
	Maintenance(ctx context.Context, address string) error
	RotateAuthority(ctx context.Context, configuration config.Config) error
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
		Usage: "operate on the schema and on the authority behind issued credentials",
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
			Value:   defaultExchangeCodeSeconds,
			Sources: cli.EnvVars("JWT_EXPIRES_IN_SECONDS_SHORT_LIVED"),
		},
		&cli.IntFlag{
			Name:    flagBrowserSessionSeconds,
			Usage:   "how many `SECONDS` a browser stays signed in",
			Value:   defaultBrowserSessionSeconds,
			Sources: cli.EnvVars("JWT_EXPIRES_IN_SECONDS_LONG_LIVED"),
		},
		&cli.StringFlag{
			Name:    flagInternalApplicationID,
			Usage:   "the `UUID` of the developer application that represents the AbandonAuth site itself",
			Sources: cli.EnvVars("ABANDON_AUTH_DEVELOPER_APP_ID"),
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
