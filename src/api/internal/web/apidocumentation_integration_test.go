//go:build integration && !devtools

package web_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// This is a public API. Its documentation describes nothing a caller could not
// learn by trying an endpoint, so it is served whatever the build and whatever
// the configuration.
func TestEveryBuildPublishesTheDocumentation(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	for path, status := range map[string]int{
		"/docs":                 http.StatusTemporaryRedirect,
		"/docs/":                http.StatusOK,
		"/docs/oauth2-redirect": http.StatusOK,
		"/openapi.json":         http.StatusOK,
	} {
		service.GET(path).ExpectStatus(status)
	}
}

// A developer opening the API's address gets the documentation page, which is
// served under its own subtree so its files resolve.
func TestTheDocumentationEntryPointLeadsToThePage(t *testing.T) {
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

	reference := "../openapi.json"
	if !strings.Contains(unescaped, reference) {
		t.Fatal("the page does not name the schema relative to its own address")
	}

	from, err := url.Parse(service.EndpointURL("/docs/"))
	if err != nil {
		t.Fatalf("the documentation has no address: %v", err)
	}

	resolved, err := from.Parse(reference)
	if err != nil {
		t.Fatalf("the page names something that is not a reference: %v", err)
	}

	if resolved.Path != "/api/openapi.json" {
		t.Errorf("the page reads the schema from %q, want /api/openapi.json", resolved.Path)
	}

	service.AtExactTarget(http.MethodGet, resolved.Path).ExpectStatus(http.StatusOK)
}

// The address a provider returns to when the documentation is used to try a
// sign-in is the one registered with the providers, so it keeps working.
func TestTheDocumentationHasSomewhereForAProviderToReturnTo(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/docs/oauth2-redirect").ExpectStatus(http.StatusOK)
}

// The schema the page reads describes this build. An address in it that this
// build does not serve would send a reader to an endpoint answering 404.
func TestTheServedSchemaDescribesOnlyWhatThisBuildServes(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	served := service.GET("/openapi.json").ExpectStatus(http.StatusOK)

	if contentType := served.Header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", contentType)
	}

	var schema struct {
		OpenAPI string                     `json:"openapi"`
		Servers []json.RawMessage          `json:"servers"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}

	served.DecodeInto(&schema)

	if schema.OpenAPI != "3.1.0" {
		t.Errorf("openapi version = %q, want 3.1.0", schema.OpenAPI)
	}

	if len(schema.Paths) == 0 {
		t.Error("the served schema documents nothing")
	}

	// The document is combined with the address it was read from. Naming a
	// server would claim that some other component adds or removes part of the
	// address, which nothing here does.
	if len(schema.Servers) != 0 {
		t.Error("the served schema declares a server of its own")
	}

	for path := range schema.Paths {
		if !strings.HasPrefix(path, "/api/") {
			t.Errorf("the served schema names %q, which is not an address of this API", path)
		}

		if service.AtExactTarget(http.MethodGet, addressable(t, path)).Status == http.StatusNotFound {
			t.Errorf("the served schema names %s, which this build does not serve", path)
		}
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
			segments[index] = "6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0"
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

	for _, target := range []string{"/docs", "/docs/", "/docs/oauth2-redirect", "/openapi.json"} {
		service.AtExactTarget(http.MethodGet, target).ExpectStatus(http.StatusNotFound)
	}
}
