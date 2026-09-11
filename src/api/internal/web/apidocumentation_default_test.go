//go:build !devtools

package web

import (
	"slices"
	"testing"
)

// Password sign-in is annotated in a file only the development build compiles,
// and swag reads the annotations without honouring that. Narrowing the document
// to what is served is the only thing that keeps a deployment from publishing
// an address it answers 404 at.
func TestADeploymentPublishesNoPasswordSignIn(t *testing.T) {
	t.Parallel()

	published := documentedOperations(publishedSchema(t))
	generated := documentedOperations(generatedSchema(t))

	for _, operation := range passwordOperations {
		if !slices.Contains(generated, operation) {
			t.Errorf("the annotations no longer describe %s, so this proves nothing", operation)
		}

		if slices.Contains(published, operation) {
			t.Errorf("the published schema names %s, which a deployment answers 404 at", operation)
		}
	}
}
