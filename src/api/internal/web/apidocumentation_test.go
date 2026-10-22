package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// leakSentinel stands in for a credential pasted into a schema source. A refusal
// must not repeat it anywhere.
const leakSentinel = "AbandonAuthLeakSentinel7Qz4Vb9Kx2Lm"

// minimalOpenAPISource is the smallest source the renderer accepts, so a case
// built from it is refused for the one thing it adds.
const minimalOpenAPISource = `openapi: "3.1.0"
info:
  title: AbandonAuth
  version: "0.0.1"
paths: {}
components: {}
`

func decodeJSONValue(t *testing.T, document []byte) map[string]any {
	t.Helper()

	var value map[string]any
	if err := json.Unmarshal(document, &value); err != nil {
		t.Fatalf("the JSON representation is not JSON: %v", err)
	}

	return value
}

func decodeYAMLValue(t *testing.T, document []byte) map[string]any {
	t.Helper()

	var value map[string]any
	if err := yaml.Unmarshal(document, &value); err != nil {
		t.Fatalf("the YAML representation is not YAML: %v", err)
	}

	return value
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
	case int64:
		return float64(typed)
	case uint64:
		return float64(typed)
	default:
		return value
	}
}

func publishedRepresentations(t *testing.T) openAPIRepresentations {
	t.Helper()

	published, err := publishedOpenAPI()
	if err != nil {
		t.Fatalf("the embedded schema is not published: %v", err)
	}

	return published
}

func TestEmbeddedSchemaIsPublished(t *testing.T) {
	t.Parallel()

	published := publishedRepresentations(t)

	if !bytes.Equal(published.YAML, embeddedOpenAPISchema) {
		t.Error("the YAML representation is not the embedded source")
	}

	if !json.Valid(published.JSON) {
		t.Error("the JSON representation is not JSON")
	}
}

// One source, two representations: a reader of either gets the same document.
func TestSchemaRepresentationsMatch(t *testing.T) {
	t.Parallel()

	published := publishedRepresentations(t)

	fromYAML := decoderIndependent(decodeYAMLValue(t, published.YAML))
	fromJSON := decoderIndependent(decodeJSONValue(t, published.JSON))

	if !reflect.DeepEqual(fromYAML, fromJSON) {
		t.Error("the YAML and JSON representations describe different documents")
	}
}

func TestSchemaHandlersServeRepresentations(t *testing.T) {
	t.Parallel()

	published := publishedRepresentations(t)

	for name, served := range map[string]struct {
		handler     http.Handler
		contentType string
		body        []byte
	}{
		"YAML": {composed().openAPIYAML(), "application/yaml; charset=utf-8", published.YAML},
		"JSON": {composed().openAPIJSON(), response.ContentTypeJSON, published.JSON},
	} {
		recorder := httptest.NewRecorder()
		served.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, OpenAPIYAMLPath, nil))

		if recorder.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", name, recorder.Code)
		}

		if got := recorder.Header().Get("Content-Type"); got != served.contentType {
			t.Errorf("%s: Content-Type = %q, want %q", name, got, served.contentType)
		}

		if !bytes.Equal(recorder.Body.Bytes(), served.body) {
			t.Errorf("%s: the body is not the published representation", name)
		}
	}
}

// The page is loaded in a browser, so it names the YAML relative to its own
// address rather than to an origin guessed here.
func TestDocumentationPageReadsYAMLSchema(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	composed().documentation().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, APIRoot+"/docs/", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	page := strings.ReplaceAll(recorder.Body.String(), `\/`, "/")

	if !strings.Contains(page, `"../openapi.yaml"`) {
		t.Error("the page does not read the schema from ../openapi.yaml")
	}

	if strings.Contains(page, "openapi.json") {
		t.Error("the page names the JSON representation")
	}
}

// refusedSources are schema sources that must yield neither representation.
func refusedSources() map[string]string {
	return map[string]string{
		"empty":                 "",
		"malformed":             "openapi: \"3.1.0\"\ninfo: [" + leakSentinel + "\n",
		"two documents":         minimalOpenAPISource + "---\n" + minimalOpenAPISource,
		"a scalar root":         leakSentinel + "\n",
		"a list root":           "- " + leakSentinel + "\n",
		"a null root":           "~\n",
		"no openapi member":     strings.Replace(minimalOpenAPISource, `openapi: "3.1.0"`, "", 1),
		"a numeric openapi":     strings.Replace(minimalOpenAPISource, `openapi: "3.1.0"`, "openapi: 3.1", 1),
		"no info member":        strings.Replace(minimalOpenAPISource, "info:\n  title: AbandonAuth\n  version: \"0.0.1\"\n", "", 1),
		"a scalar info member":  strings.Replace(minimalOpenAPISource, "info:\n  title: AbandonAuth\n  version: \"0.0.1\"\n", "info: "+leakSentinel+"\n", 1),
		"a list paths member":   strings.Replace(minimalOpenAPISource, "paths: {}", "paths: []", 1),
		"no components member":  strings.Replace(minimalOpenAPISource, "components: {}\n", "", 1),
		"a duplicated member":   minimalOpenAPISource + "paths: {}\n",
		"a value JSON lacks":    strings.Replace(minimalOpenAPISource, "paths: {}", "paths:\n  /api/x:\n    summary: "+leakSentinel+"\n    x-weight: .nan", 1),
		"a schema default":      strings.Replace(minimalOpenAPISource, "components: {}", "components:\n  schemas:\n    Token:\n      type: string\n      default: "+leakSentinel, 1),
		"a parameter example":   strings.Replace(minimalOpenAPISource, "components: {}", "components:\n  parameters:\n    Code:\n      name: code\n      in: query\n      example: "+leakSentinel, 1),
		"a request example":     strings.Replace(minimalOpenAPISource, "paths: {}", "paths:\n  /api/x:\n    post:\n      requestBody:\n        content:\n          application/json:\n            example: "+leakSentinel, 1),
		"a response's examples": strings.Replace(minimalOpenAPISource, "paths: {}", "paths:\n  /api/x:\n    get:\n      responses:\n        \"200\":\n          content:\n            application/json:\n              examples:\n                token:\n                  value: "+leakSentinel, 1),
	}
}

// A source that fails any check is refused whole, with fixed words. The YAML
// library's own errors can quote the source, so none of them is passed on.
func TestMalformedSchemaIsNotPublished(t *testing.T) {
	t.Parallel()

	if _, err := renderOpenAPIRepresentations([]byte(minimalOpenAPISource)); err != nil {
		t.Fatalf("the minimal source is refused, so the cases below prove nothing: %v", err)
	}

	fixed := []error{errOpenAPIUnreadable, errOpenAPIIncomplete, errOpenAPIExample, errOpenAPIUnrenderable}

	for name, source := range refusedSources() {
		rendered, err := renderOpenAPIRepresentations([]byte(source))
		if err == nil {
			t.Errorf("%s: the source was published", name)

			continue
		}

		if rendered.YAML != nil || rendered.JSON != nil {
			t.Errorf("%s: a refused source still produced a representation", name)
		}

		recognised := false
		for _, known := range fixed {
			if errors.Is(err, known) {
				recognised = true
			}
		}

		if !recognised {
			t.Errorf("%s: refused with %q, which is not one of the fixed refusals", name, err)
		}

		if strings.Contains(err.Error(), leakSentinel) {
			t.Errorf("%s: the refusal repeats the source", name)
		}
	}

	for name, want := range map[string]error{
		"a schema default":      errOpenAPIExample,
		"a parameter example":   errOpenAPIExample,
		"a request example":     errOpenAPIExample,
		"a response's examples": errOpenAPIExample,
		"no components member":  errOpenAPIIncomplete,
		"two documents":         errOpenAPIUnreadable,
		"a value JSON lacks":    errOpenAPIUnrenderable,
	} {
		if _, err := renderOpenAPIRepresentations([]byte(refusedSources()[name])); !errors.Is(err, want) {
			t.Errorf("%s: refused with %v, want %v", name, err, want)
		}
	}
}

// A refused source is answered with the service's fixed failure, and neither the
// answer nor the log repeats anything from it.
func TestRefusedSchemaRevealsNothing(t *testing.T) {
	t.Parallel()

	for name, source := range refusedSources() {
		if !strings.Contains(source, leakSentinel) {
			continue
		}

		for _, contentType := range []string{contentTypeYAML, response.ContentTypeJSON} {
			var log bytes.Buffer

			server := composedWithLog(&log)

			var refusal error

			handler := server.serveOpenAPI(contentType, func() ([]byte, error) {
				rendered, err := renderOpenAPIRepresentations([]byte(source))
				refusal = err

				return rendered.YAML, err
			})

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, OpenAPIJSONPath, nil))

			if recorder.Code != http.StatusInternalServerError {
				t.Errorf("%s (%s): status = %d, want 500", name, contentType, recorder.Code)
			}

			if got := strings.TrimSpace(recorder.Body.String()); got != `{"detail":"Internal Server Error"}` {
				t.Errorf("%s (%s): body = %s, want the fixed failure", name, contentType, got)
			}

			if refusal == nil {
				t.Errorf("%s (%s): the source was not refused", name, contentType)
			} else if strings.Contains(refusal.Error(), leakSentinel) {
				t.Errorf("%s (%s): the refusal repeats the source", name, contentType)
			}

			if strings.Contains(recorder.Body.String(), leakSentinel) {
				t.Errorf("%s (%s): the response repeats the source", name, contentType)
			}

			if log.Len() == 0 {
				t.Errorf("%s (%s): the refusal was not logged", name, contentType)
			}

			if strings.Contains(log.String(), leakSentinel) {
				t.Errorf("%s (%s): the log repeats the source", name, contentType)
			}
		}
	}
}
