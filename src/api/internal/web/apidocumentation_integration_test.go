//go:build integration && !devtools

package web_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// This is a public API. Its documentation describes nothing a caller could not
// learn by trying an endpoint, so it is served whatever the build and whatever
// the configuration.
func TestEveryBuildPublishesDocumentation(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	for path, status := range map[string]int{
		"/docs":                 http.StatusTemporaryRedirect,
		"/docs/":                http.StatusOK,
		"/docs/oauth2-redirect": http.StatusOK,
		"/openapi.yaml":         http.StatusOK,
		"/openapi.json":         http.StatusOK,
	} {
		service.GET(path).ExpectStatus(status)
	}
}

func TestSchemaRepresentationsCarryTheirMediaTypes(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	for path, want := range map[string]string{
		"/openapi.yaml": "application/yaml; charset=utf-8",
		"/openapi.json": "application/json",
	} {
		if got := service.GET(path).ExpectStatus(http.StatusOK).Header.Get("Content-Type"); got != want {
			t.Errorf("%s: Content-Type = %q, want %q", path, got, want)
		}
	}
}

// A developer opening the API's address gets the documentation page, which is
// served under its own subtree so its files resolve.
func TestDocumentationEntryPointLeadsToPage(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/docs").
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo("docs/")

	page := service.GET("/docs/").ExpectStatus(http.StatusOK)

	// The page is loaded in a browser, so the schema is named relative to the
	// address that browser asked for rather than to an origin guessed here. The
	// address is written into a script, where the separators are escaped.
	unescaped := strings.ReplaceAll(string(page.Body), `\/`, "/")

	reference := "../openapi.yaml"
	if !strings.Contains(unescaped, reference) {
		t.Fatal("the page does not name the YAML schema relative to its own address")
	}

	from, err := url.Parse(service.EndpointURL("/docs/"))
	if err != nil {
		t.Fatalf("the documentation has no address: %v", err)
	}

	resolved, err := from.Parse(reference)
	if err != nil {
		t.Fatalf("the page names something that is not a reference: %v", err)
	}

	if resolved.Path != "/api/openapi.yaml" {
		t.Errorf("the page reads the schema from %q, want /api/openapi.yaml", resolved.Path)
	}

	service.AtExactTarget(http.MethodGet, resolved.Path).ExpectStatus(http.StatusOK)
}

// The address a provider returns to when the documentation is used to try a
// sign-in is the one registered with the providers, so it keeps working.
func TestDocumentationHasSomewhereForProviderToReturnTo(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/docs/oauth2-redirect").ExpectStatus(http.StatusOK)
}

// servedSchemas fetches both representations and decodes each to plain values.
func servedSchemas(t *testing.T, service *servertest.Service) (map[string]any, map[string]any) {
	t.Helper()

	var fromYAML map[string]any
	if err := yaml.Unmarshal(service.GET("/openapi.yaml").ExpectStatus(http.StatusOK).Body, &fromYAML); err != nil {
		t.Fatalf("the served YAML is not YAML: %v", err)
	}

	var fromJSON map[string]any
	if err := json.Unmarshal(service.GET("/openapi.json").ExpectStatus(http.StatusOK).Body, &fromJSON); err != nil {
		t.Fatalf("the served JSON is not JSON: %v", err)
	}

	return fromYAML, fromJSON
}

// decoderIndependent makes a decoded value independent of which decoder
// produced it: YAML yields integers where JSON yields floating point numbers.
func decoderIndependent(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		converted := make(map[string]any, len(typed))
		for key, member := range typed {
			converted[key] = decoderIndependent(member)
		}

		return converted
	case []any:
		converted := make([]any, len(typed))
		for index, element := range typed {
			converted[index] = decoderIndependent(element)
		}

		return converted
	case int:
		return float64(typed)
	default:
		return value
	}
}

// servedOperations lists "METHOD /path" for every operation in a served document,
// with whether it is labelled development-only.
func servedOperations(t *testing.T, document map[string]any) map[string]bool {
	t.Helper()

	paths, found := document["paths"].(map[string]any)
	if !found || len(paths) == 0 {
		t.Fatal("the served schema documents nothing")
	}

	operations := make(map[string]bool)

	for path, methods := range paths {
		for method, operation := range methods.(map[string]any) {
			described, _ := operation.(map[string]any)
			operations[fmt.Sprintf("%s %s", strings.ToUpper(method), path)] =
				described["x-abandonauth-build"] == "development"
		}
	}

	return operations
}

// Both representations come from one source, so a reader of either gets the
// same document.
func TestServedRepresentationsMatch(t *testing.T) {
	t.Parallel()

	fromYAML, fromJSON := servedSchemas(t, servertest.New(t))

	if !reflect.DeepEqual(decoderIndependent(fromYAML), decoderIndependent(fromJSON)) {
		t.Error("the YAML and JSON documents differ")
	}

	yamlOperations := servedOperations(t, fromYAML)
	jsonOperations := servedOperations(t, fromJSON)

	if !reflect.DeepEqual(yamlOperations, jsonOperations) {
		t.Errorf("the documents describe different operations\nYAML: %v\nJSON: %v", yamlOperations, jsonOperations)
	}

	if fromYAML["openapi"] != "3.1.0" {
		t.Errorf("openapi = %v, want 3.1.0", fromYAML["openapi"])
	}

	// The document is combined with the address it was read from. Naming a
	// server would claim that some other component adds or removes part of the
	// address, which nothing here does.
	if _, present := fromYAML["servers"]; present {
		t.Error("the served schema declares a server of its own")
	}
}

// Every operation the schema does not label development-only is one this
// deployment declares, and the two it does label answer 404 here, asked for
// with no body and no credential.
func TestServedSchemaDescribesWhatThisBuildServes(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	fromYAML, _ := servedSchemas(t, service)

	var development []string

	for key, labelled := range servedOperations(t, fromYAML) {
		method, path, _ := strings.Cut(key, " ")

		if !strings.HasPrefix(path, "/api/") {
			t.Errorf("the served schema names %q, which is not an address of this API", path)
		}

		if labelled {
			development = append(development, key)

			service.AtExactTarget(method, path).ExpectStatus(http.StatusNotFound)

			continue
		}

		if service.AtExactTarget(http.MethodGet, addressable(t, path)).Status == http.StatusNotFound {
			t.Errorf("the served schema names %s, which this build does not declare", path)
		}
	}

	slices.Sort(development)

	if want := []string{"POST /api/create_test_user", "POST /api/login_test_user"}; !slices.Equal(development, want) {
		t.Errorf("development-only operations = %v, want %v", development, want)
	}
}

// addressable fills in the template segments of a documented address so that it
// can be asked for. A template nobody has chosen a value for fails the test
// rather than being asked for as it stands.
func addressable(t *testing.T, path string) string {
	t.Helper()

	segments := strings.Split(path, "/")

	for index, segment := range segments {
		if !strings.HasPrefix(segment, "{") {
			continue
		}

		switch segment {
		case "{provider}":
			segments[index] = "discord"
		case "{application_id}":
			segments[index] = "00000000-0000-0000-0000-000000000001"
		default:
			t.Fatalf("%s carries %s, which no test knows a value for", path, segment)
		}
	}

	return strings.Join(segments, "/")
}

// One page documents this API, and it is at the API's own address. Nothing
// above the route root serves documentation, and no other address does either.
func TestOnlyOneAddressServesDocumentation(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/redoc").ExpectStatus(http.StatusNotFound)
	service.GET("/redoc/").ExpectStatus(http.StatusNotFound)

	for _, target := range []string{"/docs", "/docs/", "/docs/oauth2-redirect", "/openapi.yaml", "/openapi.json"} {
		service.AtExactTarget(http.MethodGet, target).ExpectStatus(http.StatusNotFound)
	}
}
