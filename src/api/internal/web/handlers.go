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
		RouteIndex:            s.index(),
		RouteIndexBare:        s.indexEntry(),
		RouteCurrentUser:      s.currentUser(),
		RouteUserApplications: s.userApplications(),
		RouteLogin:            s.login(),
		RouteBurnToken:        s.burnToken(),

		RouteApplicationCreate:   s.createApplication(),
		RouteApplicationLogin:    s.applicationLogin(),
		RouteApplicationCurrent:  s.currentApplication(),
		RouteApplicationGet:      s.getApplication(),
		RouteApplicationDelete:   s.deleteApplication(),
		RouteApplicationReset:    s.resetApplicationCredential(),
		RouteApplicationCallback: s.replaceCallbackURIs(),

		RouteGoogleCallback:  s.googleCallback(),
		RouteDiscordCallback: s.discordCallback(),
		RouteGitHubCallback:  s.githubCallback(),

		RouteProviderAuthorize: s.providerAuthorize(),
		RouteSiteEntry:         s.siteEntry(),
		RouteSiteEntryBare:     s.siteEntry(),
		RouteLogout:            s.logout(),
	}

	maps.Copy(handlers, s.documentationHandlers())
	maps.Copy(handlers, s.devtoolsHandlers())

	return handlers
}
