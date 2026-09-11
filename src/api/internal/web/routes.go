// Package web serves the AbandonAuth HTTP API.
package web

import (
	"slices"
	"strings"

	"github.com/abandontech/abandonauth/src/api/internal/buildmode"
)

// DevtoolsBuild reports whether this binary serves the development-only routes.
const DevtoolsBuild = buildmode.Devtools

// APIRoot is the path every route of this service is served under. It belongs
// to the API's contract: no other component of a deployment adds it or takes it
// away, so a caller reaching this service directly uses the same addresses a
// browser does.
const APIRoot = "/api"

// RouteName identifies a route independently of its URL, so a handler can be
// attached to it and a test can name it without repeating the pattern.
type RouteName string

// Names of every route this service serves.
const (
	RouteIndex               RouteName = "index"
	RouteIndexBare           RouteName = "index-bare"
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
	RouteSwaggerUI           RouteName = "swagger-ui"
	RouteSwaggerUIIndex      RouteName = "swagger-ui-index"
	RouteSwaggerOAuth2       RouteName = "swagger-oauth2-redirect"
	RouteAPISchema           RouteName = "api-schema"
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
	{Name: RouteIndexBare, Method: "GET", Pattern: APIRoot},
	{Name: RouteIndex, Method: "GET", Pattern: APIRoot + "/{$}"},
	{Name: RouteCurrentUser, Method: "GET", Pattern: APIRoot + "/me", Documented: true},
	{Name: RouteUserApplications, Method: "GET", Pattern: APIRoot + "/user/applications", Documented: true},
	{Name: RouteLogin, Method: "POST", Pattern: APIRoot + "/login", Documented: true},
	{Name: RouteBurnToken, Method: "POST", Pattern: APIRoot + "/burn-token", Documented: true},

	{Name: RouteApplicationCreate, Method: "POST", Pattern: APIRoot + "/developer_application", Documented: true},
	{
		Name:       RouteApplicationLogin,
		Method:     "POST",
		Pattern:    APIRoot + "/developer_application/login",
		Documented: true,
	},
	{
		Name:       RouteApplicationCurrent,
		Method:     "GET",
		Pattern:    APIRoot + "/developer_application/me",
		Documented: true,
	},
	{
		Name:       RouteApplicationGet,
		Method:     "GET",
		Pattern:    APIRoot + "/developer_application/{application_id}",
		Documented: true,
	},
	{
		Name:       RouteApplicationDelete,
		Method:     "DELETE",
		Pattern:    APIRoot + "/developer_application/{application_id}",
		Documented: true,
	},
	{
		Name:       RouteApplicationReset,
		Method:     "PATCH",
		Pattern:    APIRoot + "/developer_application/{application_id}/reset_token",
		Documented: true,
	},
	{
		Name:       RouteApplicationCallback,
		Method:     "PATCH",
		Pattern:    APIRoot + "/developer_application/{application_id}/callback_uris",
		Documented: true,
	},

	{Name: RouteGoogleCallback, Method: "GET", Pattern: APIRoot + "/google", Documented: true},

	{Name: RouteSiteEntryBare, Method: "GET", Pattern: APIRoot + "/ui"},
	{Name: RouteSiteEntry, Method: "GET", Pattern: APIRoot + "/ui/{$}"},
	{Name: RouteDiscordCallback, Method: "GET", Pattern: APIRoot + "/ui/discord-callback", Documented: true},
	{Name: RouteGitHubCallback, Method: "GET", Pattern: APIRoot + "/ui/github-callback", Documented: true},
	{Name: RouteProviderAuthorize, Method: "GET", Pattern: APIRoot + "/ui/{provider}/authorize", Documented: true},
	{Name: RouteLogout, Method: "POST", Pattern: APIRoot + "/ui/logout", Documented: true},

	{Name: RouteSwaggerUI, Method: "GET", Pattern: APIRoot + "/docs"},
	{Name: RouteSwaggerUIIndex, Method: "GET", Pattern: APIRoot + "/docs/"},
	{Name: RouteSwaggerOAuth2, Method: "GET", Pattern: APIRoot + "/docs/oauth2-redirect"},
	{Name: RouteAPISchema, Method: "GET", Pattern: APISchemaPath},
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
