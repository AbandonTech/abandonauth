//go:build devtools

package web

// Names of the routes only the development build serves.
const (
	RouteCreateTestUser RouteName = "create-test-user"
	RouteLoginTestUser  RouteName = "login-test-user"
	RouteSwaggerUI      RouteName = "swagger-ui"
	RouteSwaggerUIIndex RouteName = "swagger-ui-index"
	RouteSwaggerOAuth2  RouteName = "swagger-oauth2-redirect"
	RouteAPISchema      RouteName = "api-schema"
)

// devtoolsRoutes are password sign-in, which seeds local accounts without
// contacting a provider, and the documentation UI. Neither is published API.
var devtoolsRoutes = []Route{
	{Name: RouteCreateTestUser, Method: "POST", Pattern: "/create_test_user", Documented: true},
	{Name: RouteLoginTestUser, Method: "POST", Pattern: "/login_test_user", Documented: true},

	{Name: RouteSwaggerUI, Method: "GET", Pattern: "/docs"},
	{Name: RouteSwaggerUIIndex, Method: "GET", Pattern: "/docs/"},
	{Name: RouteSwaggerOAuth2, Method: "GET", Pattern: "/docs/oauth2-redirect"},
	{Name: RouteAPISchema, Method: "GET", Pattern: "/openapi.json"},
}
