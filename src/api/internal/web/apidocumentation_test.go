package web

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// generatedSchema is the document produced from the handler annotations. The
// annotations carry no build constraints, so it describes every annotated
// endpoint whichever build read them.
func generatedSchema(t *testing.T) apiSchema {
	t.Helper()

	return decodeSchema(t, generatedAPISchema())
}

// publishedSchema is what a reader of the documentation actually gets: the
// generated document narrowed to the addresses this build serves.
func publishedSchema(t *testing.T) apiSchema {
	t.Helper()

	document, err := publishedAPISchema()
	if err != nil {
		t.Fatalf("the published schema could not be produced: %v", err)
	}

	return decodeSchema(t, document)
}

func decodeSchema(t *testing.T, document string) apiSchema {
	t.Helper()

	var schema apiSchema

	// Unlike the checked-in reference, this document carries fields the service
	// does not commit to, so unknown ones are ignored rather than refused.
	if err := json.Unmarshal([]byte(document), &schema); err != nil {
		t.Fatalf("the schema is not an OpenAPI document: %v", err)
	}

	return schema
}

// The annotations and the route table are written separately, so nothing but a
// comparison keeps the published document describing what is served.
func TestThePublishedSchemaDocumentsExactlyWhatIsServed(t *testing.T) {
	t.Parallel()

	published := documentedOperations(publishedSchema(t))

	if want := documentedRoutes(Routes()); !slices.Equal(published, want) {
		t.Errorf("the published schema and the routes disagree\n got: %v\nwant: %v", published, want)
	}

	schemaFile := apiSchemaFile
	if DevtoolsBuild {
		schemaFile = apiSchemaDevtoolsFile
	}

	if want := documentedOperations(loadAPISchema(t, schemaFile)); !slices.Equal(published, want) {
		t.Errorf("the published schema and %s disagree\n got: %v\nwant: %v", schemaFile, published, want)
	}
}

// Password sign-in is annotated in a file only the development build compiles,
// and swag reads the annotations without honouring that. Narrowing the document
// to what is served is the only thing that keeps a deployment from publishing
// an address it answers 404 at.
func TestThePublishedSchemaNamesPasswordSignInOnlyWhereItIsServed(t *testing.T) {
	t.Parallel()

	published := documentedOperations(publishedSchema(t))
	generated := documentedOperations(generatedSchema(t))

	for _, operation := range []string{"POST /api/create_test_user", "POST /api/login_test_user"} {
		if !slices.Contains(generated, operation) {
			t.Errorf("the annotations no longer describe %s, so this proves nothing", operation)
		}

		if slices.Contains(published, operation) != DevtoolsBuild {
			t.Errorf("the published schema names %s = %v, want %v",
				operation, slices.Contains(published, operation), DevtoolsBuild)
		}
	}
}

// Every annotated endpoint is one this repository promises somewhere, so an
// operation that reached the annotations without reaching the reference is a
// change nobody agreed to publish.
func TestTheGeneratedSchemaDescribesEveryEndpointTheReferencePromises(t *testing.T) {
	t.Parallel()

	generated := documentedOperations(generatedSchema(t))

	if want := documentedOperations(loadAPISchema(t, apiSchemaDevtoolsFile)); !slices.Equal(generated, want) {
		t.Errorf("the generated schema and %s disagree\n got: %v\nwant: %v",
			apiSchemaDevtoolsFile, generated, want)
	}
}

// A reader combines a published address with the origin the document came from,
// so every address has to be the whole one this service answers at, and nothing
// in the document may claim that something else adds or removes part of it.
func TestThePublishedSchemaNamesWholeAddressesAndNoServerOfItsOwn(t *testing.T) {
	t.Parallel()

	for name, schema := range map[string]apiSchema{
		"the published schema": publishedSchema(t),
		"the generated schema": generatedSchema(t),
	} {
		if len(schema.Servers) != 0 {
			t.Errorf("%s declares a server of its own", name)
		}

		for path := range schema.Paths {
			if !strings.HasPrefix(path, APIRoot+"/") {
				t.Errorf("%s names %q, which is not an address of this API", name, path)
			}
		}
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

// A document this service cannot narrow is one it cannot prove describes only
// what it serves, so it is refused rather than published as it stands.
func TestASchemaThatCannotBeReadIsNotPublished(t *testing.T) {
	t.Parallel()

	for _, document := range []string{"", "{}", `{"paths": []}`, "not a document"} {
		if _, err := schemaLimitedTo(document, documentedPaths()); err == nil {
			t.Errorf("%q was accepted as a schema", document)
		}
	}
}
