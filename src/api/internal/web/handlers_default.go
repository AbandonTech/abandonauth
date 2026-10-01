//go:build !devtools

package web

import "net/http"

// devtoolsHandlers is empty in this build. Password sign-in is not compiled in,
// so there is nothing to bind.
func (s *Server) devtoolsHandlers() map[RouteName]http.Handler {
	return nil
}
