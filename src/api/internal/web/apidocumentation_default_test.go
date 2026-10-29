//go:build !devtools

package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A deployment documents the password operations so a reader of either build
// sees one contract, labelled so nobody mistakes them for something it serves.
// What keeps them unreachable is that this build neither declares nor binds them.
func TestDeploymentPublishesDevelopmentOperationsWithoutServingThem(t *testing.T) {
	t.Parallel()

	published := publishedRepresentations(t)

	for name, document := range map[string]map[string]any{
		"YAML": decodeYAMLValue(t, published.YAML),
		"JSON": decodeJSONValue(t, published.JSON),
	} {
		paths, _ := document["paths"].(map[string]any)

		for _, key := range developmentOperations {
			method, path, _ := strings.Cut(key, " ")

			methods, _ := paths[path].(map[string]any)

			operation, found := methods[strings.ToLower(method)].(map[string]any)
			if !found {
				t.Errorf("%s: the deployment document does not describe %s", name, key)

				continue
			}

			if label := operation["x-abandonauth-build"]; label != developmentBuildLabel {
				t.Errorf("%s: %s is labelled %v, want %q", name, key, label, developmentBuildLabel)
			}

			responses, _ := operation["responses"].(map[string]any)
			if _, documented := responses["404"]; !documented {
				t.Errorf("%s: %s does not document the 404 a deployment answers", name, key)
			}
		}
	}

	declared := make(map[string]bool)
	for _, route := range Routes() {
		declared[fmt.Sprintf("%s %s", route.Method, route.Path())] = true
	}

	handler := composed().Handler()

	for _, key := range developmentOperations {
		if declared[key] {
			t.Errorf("a deployment declares %s", key)
		}

		method, path, _ := strings.Cut(key, " ")

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))

		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s answered %d in a deployment, want 404", key, recorder.Code)
		}
	}
}
