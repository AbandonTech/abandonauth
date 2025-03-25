package http

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

func Middleware(next http.Handler) http.Handler {
	return LoggingMiddleware(next)
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug().
			Str("method", r.Method).
			Str("query", r.URL.RawQuery).
			Str("path", r.URL.Path).
			Str("remote", r.RemoteAddr).
			Send()

		next.ServeHTTP(w, r)
	})
}
