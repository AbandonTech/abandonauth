package http

import (
	"net/http"

	"github.com/abandontech/abandonauth/internal/http/routers/developer_application"
	"github.com/abandontech/abandonauth/internal/http/routers/index"
	"github.com/abandontech/abandonauth/internal/http/routers/ui"
	"github.com/rs/zerolog/log"
)

func NewServer(address string) *http.Server {
	mux := http.NewServeMux()

	mux.Handle("/developer_application/", Middleware(developer_application.NewDeveloperApplicationRouter()))
	mux.Handle("/ui/", Middleware(ui.NewUiRouter()))
	mux.Handle("/", Middleware(index.NewIndexRouter()))

	server := &http.Server{
		Addr:    address,
		Handler: mux,
	}
	server.RegisterOnShutdown(func() {
		log.Info().Msg("Server shutting down")
	})

	return server
}
