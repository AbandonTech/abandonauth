// Package web serves the AbandonAuth HTTP API.
package web

import (
	"slices"
	"strings"

	"github.com/abandontech/abandonauth/src/api/internal/buildmode"
)

// DevtoolsBuild reports whether this binary serves the development-only routes.
const DevtoolsBuild = buildmode.Devtools

// RouteName identifies a route independently of its URL, so a handler can be
// attached to it and a test can name it without repeating the pattern.
type RouteName string

// Names of every route this service serves.
const (
	RouteIndex               RouteName = "index"
	RouteCurrentUser         RouteName = "current-user"
	RouteUserApplications    RouteName = "user-applications"
	RouteLogin               RouteName = "login"
	RouteBurnToken           RouteName = "burn-token"
	RouteApplicationCreate   RouteName = "application-create"
	RouteApplicationLogin    RouteName = "application-login"
	RouteApplicationCurrent  RouteName = "application-current"
	RouteApplicationGet      RouteName = "application-get"
	RouteApplicationDelete   RouteName = "application-delete"
	RouteApplicationReset    RouteName = "application-reset-token"
	RouteApplicationCallback RouteName = "application-callback-uris"
	RouteGoogleCallback      RouteName = "google-callback"
	RouteSiteEntry           RouteName = "site-entry"
	RouteSiteEntryBare       RouteName = "site-entry-bare"
	RouteDiscordCallback     RouteName = "discord-callback"
	RouteGitHubCallback      RouteName = "github-callback"
	RouteProviderAuthorize   RouteName = "provider-authorize"
	RouteLogout              RouteName = "logout"
)

// Route is one endpoint of the service.
//
// Pattern is a net/http ServeMux pattern. Patterns that must match a single
// path exactly, rather than a subtree, are anchored with {$}.
type Route struct {
	Name    RouteName
	Method  string
	Pattern string

	// Documented marks routes that belong to the published API schema.
	// Browser redirects and the documentation UI are not part of it.
	Documented bool
}

// Path returns the URL the route matches, without router anchoring syntax, as
// it appears in the API schema.
func (r Route) Path() string {
	return strings.TrimSuffix(r.Pattern, "{$}")
}

// baseRoutes are served by every build of the service.
var baseRoutes = []Route{
	{Name: RouteIndex, Method: "GET", Pattern: "/{$}"},
	{Name: RouteCurrentUser, Method: "GET", Pattern: "/me", Documented: true},
	{Name: RouteUserApplications, Method: "GET", Pattern: "/user/applications", Documented: true},
	{Name: RouteLogin, Method: "POST", Pattern: "/login", Documented: true},
	{Name: RouteBurnToken, Method: "POST", Pattern: "/burn-token", Documented: true},

	{Name: RouteApplicationCreate, Method: "POST", Pattern: "/developer_application", Documented: true},
	{Name: RouteApplicationLogin, Method: "POST", Pattern: "/developer_application/login", Documented: true},
	{Name: RouteApplicationCurrent, Method: "GET", Pattern: "/developer_application/me", Documented: true},
	{Name: RouteApplicationGet, Method: "GET", Pattern: "/developer_application/{application_id}", Documented: true},
	{Name: RouteApplicationDelete, Method: "DELETE", Pattern: "/developer_application/{application_id}", Documented: true},
	{
		Name:       RouteApplicationReset,
		Method:     "PATCH",
		Pattern:    "/developer_application/{application_id}/reset_token",
		Documented: true,
	},
	{
		Name:       RouteApplicationCallback,
		Method:     "PATCH",
		Pattern:    "/developer_application/{application_id}/callback_uris",
		Documented: true,
	},

	{Name: RouteGoogleCallback, Method: "GET", Pattern: "/google", Documented: true},

	{Name: RouteSiteEntryBare, Method: "GET", Pattern: "/ui"},
	{Name: RouteSiteEntry, Method: "GET", Pattern: "/ui/{$}"},
	{Name: RouteDiscordCallback, Method: "GET", Pattern: "/ui/discord-callback", Documented: true},
	{Name: RouteGitHubCallback, Method: "GET", Pattern: "/ui/github-callback", Documented: true},
	{Name: RouteProviderAuthorize, Method: "GET", Pattern: "/ui/{provider}/authorize", Documented: true},
	{Name: RouteLogout, Method: "POST", Pattern: "/ui/logout", Documented: true},
}

// Routes returns every route this build serves.
func Routes() []Route {
	return append(slices.Clone(baseRoutes), devtoolsRoutes...)
}

// Lookup returns the route with the given name.
func Lookup(name RouteName) (Route, bool) {
	for _, route := range Routes() {
		if route.Name == name {
			return route, true
		}
	}

	return Route{}, false
}
