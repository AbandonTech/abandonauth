package http

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

func NewServer(address string) *http.Server {
	mux := http.NewServeMux()

	server := &http.Server{
		Addr:    address,
		Handler: mux,
	}
	server.RegisterOnShutdown(func() {
		log.Info().Msg("Server shutting down")
	})

	return server
}
