package http

import (
	"net/http"

	"github.com/abandontech/abandonauth/internal/config"
	"github.com/abandontech/abandonauth/internal/http/routers/developer_application"
	"github.com/abandontech/abandonauth/internal/http/routers/index"
	"github.com/abandontech/abandonauth/internal/http/routers/ui"
	"github.com/rs/zerolog/log"
)

func NewServer(conf config.Config) *http.Server {
	mux := http.NewServeMux()

	mux.Handle("/developer_application/", Middleware(developer_application.NewDeveloperApplicationRouter()))
	mux.Handle("/ui/", Middleware(ui.NewUiRouter(conf.Discord, conf.GitHub)))
	mux.Handle("/", Middleware(index.NewIndexRouter()))

	server := &http.Server{
		Addr:    conf.Server.Host,
		Handler: mux,
	}
	server.RegisterOnShutdown(func() {
		log.Info().Msg("Server shutting down")
	})

	return server
}
