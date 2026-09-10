//go:build devtools

package web

import (
	"fmt"
	"slices"
	"testing"
)

// passwordOperations are the two addresses password sign-in is reached at,
// written as the schema writes them.
var passwordOperations = []string{"POST /api/create_test_user", "POST /api/login_test_user"}

// The routes exist to seed a machine no other machine can reach, and this is
// the build that carries them.
func TestDevtoolsDeclaresBothPasswordRoutes(t *testing.T) {
	t.Parallel()

	if !DevtoolsBuild {
		t.Fatal("this file compiled into a build that does not serve the development routes")
	}

	served := make(map[string]bool, len(Routes()))
	for _, route := range Routes() {
		served[fmt.Sprintf("%s %s", route.Method, route.Path())] = true
	}

	for _, operation := range passwordOperations {
		if !served[operation] {
			t.Errorf("route %s is not declared by the build that carries password sign-in", operation)
		}
	}
}

// A declared route with no handler would answer with a surprise rather than
// with its contract, and these two are declared in a file of their own.
func TestDevtoolsBindsAHandlerToEachPasswordRoute(t *testing.T) {
	t.Parallel()

	bound := composed().handlers()

	for _, name := range []RouteName{RouteCreateTestUser, RouteLoginTestUser} {
		if _, defined := bound[name]; !defined {
			t.Errorf("route %q is declared but nothing answers it", name)
		}
	}
}

// The route table, the annotations and the committed reference are written
// separately, so only a comparison keeps this build's documentation describing
// what it serves.
func TestDevtoolsPublishesExactlyWhatTheDevelopmentReferencePromises(t *testing.T) {
	t.Parallel()

	published := documentedOperations(publishedSchema(t))

	if want := documentedRoutes(Routes()); !slices.Equal(published, want) {
		t.Errorf("the published schema and the routes disagree\n got: %v\nwant: %v", published, want)
	}

	if want := documentedOperations(loadAPISchema(t, apiSchemaDevtoolsFile)); !slices.Equal(published, want) {
		t.Errorf("the published schema and %s disagree\n got: %v\nwant: %v",
			apiSchemaDevtoolsFile, published, want)
	}

	for _, operation := range passwordOperations {
		if !slices.Contains(published, operation) {
			t.Errorf("the published schema omits %s, which this build serves", operation)
		}
	}
}
