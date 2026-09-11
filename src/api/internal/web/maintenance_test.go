package web_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/web"
)

func TestMaintenanceHandlerRefusesEveryRequest(t *testing.T) {
	t.Parallel()

	// Targets that would otherwise accept a credential, act on one, or describe
	// the service, alongside spellings the serving handler refuses outright.
	// None of them may behave differently from any other target: this handler
	// runs when nothing else does, so it answers before any of that is decided.
	paths := []string{
		"/",
		"/api",
		"/api/",
		"/api/me",
		"/api/login",
		"/api/burn-token",
		"/api/developer_application",
		"/api/developer_application/6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0",
		"/api/ui/",
		"/api/ui/discord-callback?code=placeholder&state=placeholder",
		"/api/ui/logout",
		"/api/google?code=placeholder&state=placeholder",
		"/api/docs",
		"/api/openapi.json",
		"/api/create_test_user",
		"/me",
		"/login",
		"/ui/discord-callback?code=placeholder&state=placeholder",
		"/api//me",
		"/api/../api/me",
		"/api%2fme",
		"/anything/else",
	}

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodPut,
		http.MethodHead,
		http.MethodOptions,
	}

	handler := web.MaintenanceHandler()

	for _, path := range paths {
		for _, method := range methods {
			request := httptest.NewRequest(method, path, nil)
			request.Header.Set("Authorization", "Bearer placeholder")
			request.Header.Set("Cookie", "abandonauth_session=placeholder")

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusServiceUnavailable {
				t.Errorf("%s %s: status = %d, want %d",
					method, path, recorder.Code, http.StatusServiceUnavailable)
			}

			retryAfter := recorder.Header().Get("Retry-After")
			if seconds, err := strconv.Atoi(retryAfter); err != nil || seconds <= 0 {
				t.Errorf("%s %s: Retry-After = %q, want a positive number of seconds",
					method, path, retryAfter)
			}
		}
	}
}

func TestMaintenanceHandlerDisclosesNothingAboutTheDeployment(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	recorder := httptest.NewRecorder()

	web.MaintenanceHandler().ServeHTTP(recorder, request)

	var body struct {
		Detail string `json:"detail"`
	}

	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not the expected shape: %v (%q)", err, recorder.Body.String())
	}

	if body.Detail != "AbandonAuth is temporarily unavailable." {
		t.Errorf("detail = %q", body.Detail)
	}

	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}
