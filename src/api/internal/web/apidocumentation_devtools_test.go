//go:build devtools

package web

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// generatedSchema is the document produced from the handler annotations, which
// is what a reader of the documentation actually gets. It is regenerated on
// every run, so it is the half of the pair that can drift.
func generatedSchema(t *testing.T) apiSchema {
	t.Helper()

	var schema apiSchema

	// Unlike the checked-in reference, this document carries fields the service
	// does not commit to, so unknown ones are ignored rather than refused.
	if err := json.Unmarshal([]byte(generatedAPISchema()), &schema); err != nil {
		t.Fatalf("the generated schema is not an OpenAPI document: %v", err)
	}

	return schema
}

// The annotations and the route table are written separately, so nothing but a
// comparison keeps the published document describing what is served.
func TestTheGeneratedSchemaDocumentsExactlyWhatIsServed(t *testing.T) {
	t.Parallel()

	generated := documentedOperations(generatedSchema(t))

	if want := documentedRoutes(Routes()); !slices.Equal(generated, want) {
		t.Errorf("the generated schema and the routes disagree\n got: %v\nwant: %v", generated, want)
	}

	if want := documentedOperations(loadAPISchema(t, apiSchemaDevtoolsFile)); !slices.Equal(generated, want) {
		t.Errorf("the generated schema and %s disagree\n got: %v\nwant: %v",
			apiSchemaDevtoolsFile, generated, want)
	}
}

// A document that names an endpoint but says nothing about it is not
// documentation, and a reader would have to try the endpoint to find out.
func TestEveryGeneratedOperationSaysWhatItDoesAndWhatItAnswers(t *testing.T) {
	t.Parallel()

	schema := generatedSchema(t)

	if schema.OpenAPI != "3.1.0" {
		t.Errorf("openapi version = %q, want 3.1.0", schema.OpenAPI)
	}

	if schema.Info.Title != "AbandonAuth" {
		t.Errorf("info.title = %q, want AbandonAuth", schema.Info.Title)
	}

	for path, operations := range schema.Paths {
		for method, operation := range operations {
			if operation.Summary == "" {
				t.Errorf("%s %s has no summary", strings.ToUpper(method), path)
			}

			if len(operation.Responses) == 0 {
				t.Errorf("%s %s documents no responses", strings.ToUpper(method), path)
			}
		}
	}
}

// The documentation is served to a browser, so an example that carried a real
// credential would hand it to everyone who opened the page.
func TestTheGeneratedSchemaHoldsNoCredentials(t *testing.T) {
	t.Parallel()

	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}`),
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		regexp.MustCompile(`\$2[aby]\$\d{2}\$`),
		regexp.MustCompile(`(?i)client_secret\s*[=:]\s*\S`),
		regexp.MustCompile(`(?i)\bset-cookie\b`),
	}

	generated := []byte(generatedAPISchema())

	for _, pattern := range forbidden {
		if pattern.Match(generated) {
			t.Errorf("the generated schema matches forbidden pattern %s", pattern)
		}
	}
}
