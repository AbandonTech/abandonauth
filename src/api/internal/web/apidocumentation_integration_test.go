//go:build integration

package web_test

import (
	"encoding/json"
	"net/http"
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

	// The page is loaded in a browser, so the address it fetches the schema from
	// has to be the one the browser can reach, not the one inside the deployment.
	// The address is written into a script, where the separators are escaped.
	unescaped := strings.ReplaceAll(string(page.Body), `\/`, "/")

	if !strings.Contains(unescaped, "/api/openapi.json") {
		t.Error("the page does not fetch the schema from the address a browser can reach")
	}
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
		Paths   map[string]json.RawMessage `json:"paths"`
	}

	served.DecodeInto(&schema)

	if schema.OpenAPI != "3.1.0" {
		t.Errorf("openapi version = %q, want 3.1.0", schema.OpenAPI)
	}

	if len(schema.Paths) == 0 {
		t.Error("the served schema documents nothing")
	}

	for path := range schema.Paths {
		if service.GET(path).Status == http.StatusNotFound {
			t.Errorf("the served schema names %s, which this build does not serve", path)
		}
	}
}

// One page documents this API, and it is at /docs. No other address serves
// documentation.
func TestOnlyOneAddressServesDocumentation(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/redoc").ExpectStatus(http.StatusNotFound)
	service.GET("/redoc/").ExpectStatus(http.StatusNotFound)
}
