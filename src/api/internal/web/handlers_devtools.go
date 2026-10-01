//go:build devtools

package web

import "net/http"

// devtoolsHandlers are the routes only the development build serves.
func (s *Server) devtoolsHandlers() map[RouteName]http.Handler {
	return map[RouteName]http.Handler{
		RouteCreateTestUser: s.createPasswordAccount(),
		RouteLoginTestUser:  s.signInWithPassword(),
	}
}
