//go:build !devtools

package web

import (
	"fmt"
	"slices"
	"testing"
)

// passwordOperations are the two addresses password sign-in is reached at,
// written as the schema writes them. A deployment serves neither.
var passwordOperations = []string{"POST /api/create_test_user", "POST /api/login_test_user"}

// Every documented route must appear in the deployment schema and every schema
// operation must be served, so documentation cannot drift away from the router.
func TestDocumentedRoutesMatchTheDeployedAPISchema(t *testing.T) {
	t.Parallel()

	want := documentedOperations(loadAPISchema(t, apiSchemaFile))
	got := documentedRoutes(Routes())

	if !slices.Equal(got, want) {
		t.Errorf("documented routes do not match %s\n got: %v\nwant: %v", apiSchemaFile, got, want)
	}
}

// The password routes exist only to seed local development data. Serving them
// from a deployment would expose account creation without a provider.
func TestADeploymentDeclaresNoPasswordRoute(t *testing.T) {
	t.Parallel()

	served := make(map[string]bool, len(Routes()))
	for _, route := range Routes() {
		served[fmt.Sprintf("%s %s", route.Method, route.Path())] = true
	}

	for _, route := range passwordOperations {
		if served[route] {
			t.Errorf("route %s is declared by a build that does not carry password sign-in", route)
		}
	}
}

// The reference for what a deployment publishes is committed, so an operation
// added to it is a decision to serve that address in every build. Password
// sign-in is not one a deployment carries.
func TestThePublishedReferencePromisesNoPasswordSignIn(t *testing.T) {
	t.Parallel()

	published := documentedOperations(loadAPISchema(t, apiSchemaFile))

	for _, operation := range passwordOperations {
		if slices.Contains(published, operation) {
			t.Errorf("%s names %s, which a deployment does not serve", apiSchemaFile, operation)
		}
	}
}
