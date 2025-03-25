package main

import (
	"fmt"
	"os"

	"github.com/abandontech/abandonauth/internal/http"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func main() {
	var host string
	var port uint

	app := &cli.App{
		Name:                 "abandonauth",
		Usage:                "an authentic auth service...",
		Suggest:              true,
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "host",
				Value:       "0.0.0.0",
				Usage:       "bind listener socket to this host",
				Destination: &host,
			},
			&cli.UintFlag{
				Name:        "port",
				Value:       8000,
				Usage:       "bind listener socket to this port",
				Destination: &port,
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
			hostAddress := fmt.Sprintf("%s:%d", host, port)
			log.Info().
				Str("address", hostAddress).
				Msg("Server starting")

			server := http.NewServer(hostAddress)
			return server.ListenAndServe()
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().
			Err(err).
			Msg("Error while running application")
	}
}
