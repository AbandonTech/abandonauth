package main

import (
	"os"

	"github.com/abandontech/abandonauth/internal/config"
	"github.com/abandontech/abandonauth/internal/database"
	"github.com/abandontech/abandonauth/internal/http"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func main() {
	// Note: we can make this be populated from a file, overwriten by arguments.
	//    as we have alot of configuration, for oauth services, it may make configruation
	//    more managable for an abandonauth admin.
	var config config.Config

	app := &cli.App{
		Name:                 "abandonauth",
		Usage:                "an authentic auth service...",
		Suggest:              true,
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "host",
				Value:       "0.0.0.0:8000",
				Usage:       "bind listener socket to this host",
				Destination: &config.Server.Host,
			},
			&cli.StringFlag{
				Name:        "dbHost",
				Value:       "127.0.0.1",
				Destination: &config.Database.Host,
			},
			&cli.UintFlag{
				Name:        "dbPort",
				Value:       uint(5432),
				Destination: &config.Database.Port,
			},
			&cli.StringFlag{
				Name:        "dbUser",
				Value:       "postgres",
				Destination: &config.Database.User,
			},
			&cli.StringFlag{
				Name:        "dbPassword",
				Value:       "postgres",
				Destination: &config.Database.Password,
			},
			&cli.StringFlag{
				Name:        "dbName",
				Value:       "postgres",
				Destination: &config.Database.Database,
			},
			&cli.StringFlag{
				Name:        "gitHubClientID",
				Destination: &config.GitHub.ClientID,
				EnvVars:     []string{"GITHUB_CLIENT_ID"},
			},
			&cli.StringFlag{
				Name:        "gitHubClientSecret",
				Destination: &config.GitHub.ClientSecret,
				EnvVars:     []string{"GITHUB_CLIENT_SECRET"},
			},
			&cli.StringFlag{
				Name:        "gitHubClientRedirectURL",
				Destination: &config.GitHub.RedirectURL,
				EnvVars:     []string{"GITHUB_REDIRECT_URL"},
			},
			&cli.StringFlag{
				Name:        "discordClientID",
				Destination: &config.Discord.ClientID,
				EnvVars:     []string{"DISCORD_CLIENT_ID"},
			},
			&cli.StringFlag{
				Name:        "discordClientSecret",
				Destination: &config.Discord.ClientSecret,
				EnvVars:     []string{"DISCORD_CLIENT_SECRET"},
			},
			&cli.StringFlag{
				Name:        "discordClientRedirectURL",
				Destination: &config.Discord.RedirectURL,
				EnvVars:     []string{"DISCORD_REDIRECT_URL"},
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Usage:   "verbose log output",
				Aliases: []string{"v"},
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "pretty",
				Usage:   "pretty log output",
				Aliases: []string{"p"},
				Value:   false,
			},
		},
		Before: func(context *cli.Context) error {
			zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			if context.Bool("verbose") {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}

			if context.Bool("pretty") {
				log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
			}

			log.Debug().
				Bool("Verbose", context.Bool("verbose")).
				Bool("Pretty", context.Bool("pretty")).
				Msg("Configured logging")
			return nil
		},
		Action: func(ctx *cli.Context) error {
			database.InitializeDatabase(config.Database)
			return http.NewServer(config).ListenAndServe()
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().
			Err(err).
			Msg("Error while running application")
	}
}
