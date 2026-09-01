package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The files under testdata hold the AbandonAuth API schema that this service
// publishes. They are the reference for the served surface: a route that is not
// in the schema, or a schema operation that no route serves, is a defect in one
// of the two. Change them only when the published API is meant to change.
const (
	apiSchemaFile         = "testdata/api_schema.json"
	apiSchemaDevtoolsFile = "testdata/api_schema_devtools.json"
)

// apiSchema is the part of an OpenAPI document that carries meaning for the
// published API. Fields the service does not commit to, such as operation
// identifiers, are deliberately absent so they cannot be asserted on.
type apiSchema struct {
	OpenAPI string `json:"openapi"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Paths      map[string]map[string]apiOperation `json:"paths"`
	Components struct {
		Schemas         map[string]json.RawMessage `json:"schemas"`
		SecuritySchemes map[string]struct {
			Type   string `json:"type"`
			Scheme string `json:"scheme"`
		} `json:"securitySchemes"`
	} `json:"components"`
}

type apiOperation struct {
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Parameters  []struct {
		Name     string          `json:"name"`
		In       string          `json:"in"`
		Required bool            `json:"required"`
		Schema   json.RawMessage `json:"schema"`
	} `json:"parameters"`
	RequestBody *struct {
		Required bool                       `json:"required"`
		Content  map[string]json.RawMessage `json:"content"`
	} `json:"requestBody"`
	Responses map[string]json.RawMessage `json:"responses"`
	Security  []map[string][]any         `json:"security"`
}

func loadAPISchema(t *testing.T, name string) apiSchema {
	t.Helper()

	raw, err := os.ReadFile(filepath.FromSlash(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	var schema apiSchema

	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&schema); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}

	return schema
}

// documentedOperations returns "METHOD /path" for every operation in a schema.
func documentedOperations(schema apiSchema) []string {
	keys := make([]string, 0, len(schema.Paths))

	for path, operations := range schema.Paths {
		for method := range operations {
			keys = append(keys, fmt.Sprintf("%s %s", strings.ToUpper(method), path))
		}
	}

	slices.Sort(keys)

	return keys
}

// documentedRoutes returns "METHOD /path" for every route the service declares
// as documented, using the path syntax the API schema uses.
func documentedRoutes(routes []Route) []string {
	keys := make([]string, 0, len(routes))

	for _, route := range routes {
		if !route.Documented {
			continue
		}

		keys = append(keys, fmt.Sprintf("%s %s", route.Method, route.Path()))
	}

	slices.Sort(keys)

	return keys
}

func TestAPISchemaIsWellFormed(t *testing.T) {
	t.Parallel()

	for _, name := range []string{apiSchemaFile, apiSchemaDevtoolsFile} {
		schema := loadAPISchema(t, name)

		if schema.OpenAPI != "3.1.0" {
			t.Errorf("%s: openapi version = %q, want 3.1.0", name, schema.OpenAPI)
		}

		if schema.Info.Title != "AbandonAuth" {
			t.Errorf("%s: info.title = %q, want AbandonAuth", name, schema.Info.Title)
		}

		if schema.Info.Version == "" {
			t.Errorf("%s: info.version is empty", name)
		}

		if len(schema.Paths) == 0 {
			t.Errorf("%s: declares no paths", name)
		}

		for path, operations := range schema.Paths {
			if !strings.HasPrefix(path, "/") {
				t.Errorf("%s: path %q is not absolute", name, path)
			}

			for method, operation := range operations {
				if operation.Summary == "" {
					t.Errorf("%s: %s %s has no summary", name, strings.ToUpper(method), path)
				}

				if len(operation.Responses) == 0 {
					t.Errorf("%s: %s %s documents no responses", name, strings.ToUpper(method), path)
				}
			}
		}

		for schemeName, scheme := range schema.Components.SecuritySchemes {
			if scheme.Type != "http" || scheme.Scheme != "bearer" {
				t.Errorf("%s: security scheme %q = %+v, want http bearer", name, schemeName, scheme)
			}
		}
	}
}

// The schema is committed to the repository, so a credential pasted into it
// would be published. Nothing in it may look like one.
func TestAPISchemaHoldsNoCredentials(t *testing.T) {
	t.Parallel()

	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}`),
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		regexp.MustCompile(`\$2[aby]\$\d{2}\$`),
		regexp.MustCompile(`(?i)client_secret\s*[=:]\s*\S`),
		regexp.MustCompile(`(?i)\bset-cookie\b`),
	}

	for _, name := range []string{apiSchemaFile, apiSchemaDevtoolsFile} {
		raw, err := os.ReadFile(filepath.FromSlash(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		for _, pattern := range forbidden {
			if pattern.Match(raw) {
				t.Errorf("%s: matches forbidden pattern %s", name, pattern)
			}
		}
	}
}

// Every documented route must appear in the schema and every schema operation
// must be served, so documentation cannot drift away from the router.
func TestDocumentedRoutesMatchAPISchema(t *testing.T) {
	t.Parallel()

	schemaFile := apiSchemaFile
	if DevtoolsBuild {
		schemaFile = apiSchemaDevtoolsFile
	}

	want := documentedOperations(loadAPISchema(t, schemaFile))
	got := documentedRoutes(Routes())

	if !slices.Equal(got, want) {
		t.Errorf("documented routes do not match %s\n got: %v\nwant: %v", schemaFile, got, want)
	}
}

// Undocumented routes are deliberate: browser redirects and the documentation
// UI are not part of the published API. Listing them here keeps that decision
// visible and stops a route from becoming undocumented by accident.
func TestUndocumentedRoutesAreExpected(t *testing.T) {
	t.Parallel()

	want := []string{
		"GET /",
		"GET /ui",
		"GET /ui/",
		"GET /docs",
		"GET /docs/",
		"GET /docs/oauth2-redirect",
		"GET /openapi.json",
	}

	slices.Sort(want)

	got := make([]string, 0, len(Routes()))

	for _, route := range Routes() {
		if route.Documented {
			continue
		}

		got = append(got, fmt.Sprintf("%s %s", route.Method, route.Path()))
	}

	slices.Sort(got)

	if !slices.Equal(got, want) {
		t.Errorf("undocumented routes\n got: %v\nwant: %v", got, want)
	}
}

// The password routes exist only to seed local development data. Compiling them
// into the production binary would expose account creation without a provider.
func TestPasswordRoutesAreDevtoolsOnly(t *testing.T) {
	t.Parallel()

	passwordRoutes := []string{"POST /create_test_user", "POST /login_test_user"}

	served := make(map[string]bool, len(Routes()))
	for _, route := range Routes() {
		served[fmt.Sprintf("%s %s", route.Method, route.Path())] = true
	}

	for _, route := range passwordRoutes {
		if served[route] != DevtoolsBuild {
			t.Errorf("route %s served = %v, want %v", route, served[route], DevtoolsBuild)
		}
	}
}

// The reference for what a deployment publishes is committed, so an operation
// added to it is a decision to serve that address in every build. Password
// sign-in is not one a deployment carries.
func TestThePublishedReferencePromisesNoPasswordSignIn(t *testing.T) {
	t.Parallel()

	published := documentedOperations(loadAPISchema(t, apiSchemaFile))

	for _, operation := range []string{"POST /create_test_user", "POST /login_test_user"} {
		if slices.Contains(published, operation) {
			t.Errorf("%s names %s, which a deployment does not serve", apiSchemaFile, operation)
		}
	}
}

// Routes must be unique and use patterns the router can register.
func TestRoutesAreUniqueAndAnchored(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, len(Routes()))

	for _, route := range Routes() {
		key := fmt.Sprintf("%s %s", route.Method, route.Pattern)
		if seen[key] {
			t.Errorf("duplicate route %s", key)
		}

		seen[key] = true

		if route.Method != strings.ToUpper(route.Method) || route.Method == "" {
			t.Errorf("route %s has a non-canonical method", key)
		}

		if !strings.HasPrefix(route.Pattern, "/") {
			t.Errorf("route %s pattern is not absolute", key)
		}

		if strings.Contains(route.Pattern, "//") {
			t.Errorf("route %s pattern has an empty segment", key)
		}
	}
}
