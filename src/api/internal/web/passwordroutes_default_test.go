//go:build !devtools

package web

import (
	"fmt"
	"testing"
)

// The password routes exist only to seed local development data. Serving them
// from a deployment would expose account creation without a provider.
func TestDeploymentDeclaresNoPasswordRoute(t *testing.T) {
	t.Parallel()

	served := make(map[string]bool, len(Routes()))
	for _, route := range Routes() {
		served[fmt.Sprintf("%s %s", route.Method, route.Path())] = true
	}

	for _, route := range developmentOperations {
		if served[route] {
			t.Errorf("route %s is declared by a build that does not carry password sign-in", route)
		}
	}
}
