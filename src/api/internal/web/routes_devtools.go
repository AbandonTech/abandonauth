//go:build devtools

package web

// Names of the routes only the development build serves.
const (
	RouteCreateTestUser RouteName = "create-test-user"
	RouteLoginTestUser  RouteName = "login-test-user"
)

// devtoolsRoutes are password sign-in, which seeds local accounts without
// contacting a provider. It is not published API.
var devtoolsRoutes = []Route{
	{Name: RouteCreateTestUser, Method: "POST", Pattern: "/create_test_user", Documented: true},
	{Name: RouteLoginTestUser, Method: "POST", Pattern: "/login_test_user", Documented: true},
}
