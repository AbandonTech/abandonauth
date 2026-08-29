//go:build devtools

package web

import "net/http"

// devtoolsHandlers binds the routes only the development build declares.
func (s *Server) devtoolsHandlers() map[RouteName]http.Handler {
	return map[RouteName]http.Handler{}
}
