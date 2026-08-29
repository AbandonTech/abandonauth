package web

import (
	"maps"
	"net/http"
)

// handlers binds every route this build declares to the code that answers it.
//
// The map is keyed by route name rather than by pattern so that a route's URL
// can only be written once, in the route table.
func (s *Server) handlers() map[RouteName]http.Handler {
	handlers := map[RouteName]http.Handler{
		RouteIndex: s.index(),
	}

	maps.Copy(handlers, s.devtoolsHandlers())

	return handlers
}
