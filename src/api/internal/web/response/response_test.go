package response_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

func TestJSONWritesTheStatusContentTypeAndBody(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()

	response.JSON(recorder, http.StatusOK, map[string]string{"username": "ada"})

	if recorder.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	if got := recorder.Header().Get("Content-Type"); got != response.ContentTypeJSON {
		t.Errorf("content type = %q, want %q", got, response.ContentTypeJSON)
	}

	if got := recorder.Body.String(); got != "{\"username\":\"ada\"}\n" {
		t.Errorf("body = %q", got)
	}
}

func TestEmptyWritesNoBody(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()

	response.Empty(recorder, http.StatusOK)

	if recorder.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	if recorder.Body.Len() != 0 {
		t.Errorf("body = %q, want no body", recorder.Body.String())
	}
}

func TestErrorWritesADetailMember(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()

	response.Error(recorder, http.StatusForbidden, "Invalid authentication credentials")

	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}

	var body struct {
		Detail string `json:"detail"`
	}

	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not the expected shape: %v (%q)", err, recorder.Body.String())
	}

	if body.Detail != "Invalid authentication credentials" {
		t.Errorf("detail = %q", body.Detail)
	}
}

func TestNotFoundAndMethodNotAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		write      func(http.ResponseWriter)
		wantStatus int
		wantDetail string
	}{
		{
			name:       "no route matched",
			write:      response.NotFound,
			wantStatus: http.StatusNotFound,
			wantDetail: "Not Found",
		},
		{
			name:       "wrong method for the route",
			write:      response.MethodNotAllowed,
			wantStatus: http.StatusMethodNotAllowed,
			wantDetail: "Method Not Allowed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			test.write(recorder)

			if recorder.Code != test.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, test.wantStatus)
			}

			var body struct {
				Detail string `json:"detail"`
			}

			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not the expected shape: %v", err)
			}

			if body.Detail != test.wantDetail {
				t.Errorf("detail = %q, want %q", body.Detail, test.wantDetail)
			}
		})
	}
}

func TestInvalidListsEveryRejectedInput(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()

	response.Invalid(recorder, []response.Failure{
		{Location: []any{"body", "name"}, Message: "Field required", Type: "missing"},
		{Location: []any{"path", "application_id"}, Message: "Input should be a valid UUID", Type: "uuid_parsing"},
	})

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusUnprocessableEntity)
	}

	var body struct {
		Detail []struct {
			Location []any  `json:"loc"`
			Message  string `json:"msg"`
			Type     string `json:"type"`
		} `json:"detail"`
	}

	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not the expected shape: %v (%q)", err, recorder.Body.String())
	}

	if len(body.Detail) != 2 {
		t.Fatalf("detail lists %d failures, want 2", len(body.Detail))
	}

	first := body.Detail[0]
	if len(first.Location) != 2 || first.Location[0] != "body" || first.Location[1] != "name" {
		t.Errorf("location = %v, want [body name]", first.Location)
	}

	if first.Message != "Field required" || first.Type != "missing" {
		t.Errorf("first failure = %+v", first)
	}
}

func TestInvalidWithNoFailuresStillWritesAnArray(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()

	response.Invalid(recorder, nil)

	if got := recorder.Body.String(); got != "{\"detail\":[]}\n" {
		t.Errorf("body = %q, want an empty array", got)
	}
}

func TestTooManyRequestsRoundsTheWaitUpAndSaysNothingAboutTheCaller(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		retryAfter time.Duration
		want       string
	}{
		{name: "whole seconds are kept", retryAfter: 30 * time.Second, want: "30"},
		{name: "a partial second rounds up", retryAfter: 1500 * time.Millisecond, want: "2"},
		{name: "an elapsed window still asks for a second", retryAfter: 0, want: "1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()

			response.TooManyRequests(recorder, test.retryAfter)

			if recorder.Code != http.StatusTooManyRequests {
				t.Errorf("status = %d, want %d", recorder.Code, http.StatusTooManyRequests)
			}

			if got := recorder.Header().Get("Retry-After"); got != test.want {
				t.Errorf("Retry-After = %q, want %q", got, test.want)
			}

			var body struct {
				Detail string `json:"detail"`
			}

			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not the expected shape: %v", err)
			}

			// The message must be the same for every caller: a different one
			// for a known account would answer whether the account exists.
			if body.Detail != "Too many requests. Try again later." {
				t.Errorf("detail = %q", body.Detail)
			}
		})
	}
}

func TestRedirectWritesTheLocationExactlyAsGiven(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()

	const location = "https://application.example.test/callback?tenant=one%20two&code=opaque"

	response.Redirect(recorder, http.StatusTemporaryRedirect, location)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusTemporaryRedirect)
	}

	if got := recorder.Header().Get("Location"); got != location {
		t.Errorf("Location = %q, want %q", got, location)
	}
}
