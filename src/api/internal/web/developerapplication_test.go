package web

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
)

// managedApplicationID is a well-formed identifier for the application a
// request names. It is a placeholder and names nothing.
const managedApplicationID = "8b1f4c66-9a2e-4d51-9d5e-2f8b0f1a7c34"

func applicationBodyRequest(path, body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
}

func applicationPathRequest(value string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/developer_application/"+value, nil)
	request.SetPathValue("application_id", value)

	return request
}

func callbackRequest(body string) *http.Request {
	return httptest.NewRequest(
		http.MethodPatch,
		"/developer_application/"+managedApplicationID+"/callback_uris",
		strings.NewReader(body),
	)
}

// An application is registered with a name, which is the only thing whoever
// registers it chooses.
func TestRegisteringAnApplicationReadsItsName(t *testing.T) {
	t.Parallel()

	given := inputs.New(applicationBodyRequest("/developer_application", `{"name":"an application"}`))

	if name := readApplicationName(given); name != "an application" {
		t.Errorf("name = %q", name)
	}

	if !given.OK() {
		t.Errorf("a valid request was refused: %v", refusals(given))
	}
}

func TestRegisteringAnApplicationRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "no body", want: []string{"body missing"}},
		{name: "no name", body: `{}`, want: []string{"body.name missing"}},
		{name: "a name that is not text", body: `{"name":42}`, want: []string{"body.name string_type"}},
		{name: "a body that is not an object", body: `"an application"`, want: []string{"body model_attributes_type"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			given := inputs.New(applicationBodyRequest("/developer_application", test.body))
			readApplicationName(given)

			if got := refusals(given); !slices.Equal(got, test.want) {
				t.Errorf("refusals = %v, want %v", got, test.want)
			}
		})
	}
}

// An application says which application it is and proves it in the same
// request, so neither member is optional.
func TestAnApplicationsCredentialsAreReadTogether(t *testing.T) {
	t.Parallel()

	given := inputs.New(applicationBodyRequest("/developer_application/login",
		`{"id":"`+managedApplicationID+`","refresh_token":"a-placeholder-credential"}`))
	presented := readApplicationCredentials(given)

	if !given.OK() {
		t.Fatalf("a valid set of credentials was refused: %v", refusals(given))
	}

	if presented.applicationID.String() != managedApplicationID {
		t.Errorf("id = %q, want %q", presented.applicationID, managedApplicationID)
	}

	if presented.refreshToken != "a-placeholder-credential" {
		t.Error("the credential in the body did not reach the handler")
	}
}

func TestAnApplicationsCredentialsRefuseWhatTheyCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "no body", want: []string{"body missing"}},
		{name: "neither member", body: `{}`, want: []string{"body.id missing", "body.refresh_token missing"}},
		{
			name: "an application that is not an identifier",
			body: `{"id":"not-an-identifier","refresh_token":"a-placeholder-credential"}`,
			want: []string{"body.id uuid_parsing"},
		},
		{
			name: "a credential that is not text",
			body: `{"id":"` + managedApplicationID + `","refresh_token":42}`,
			want: []string{"body.refresh_token string_type"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			given := inputs.New(applicationBodyRequest("/developer_application/login", test.body))
			readApplicationCredentials(given)

			if got := refusals(given); !slices.Equal(got, test.want) {
				t.Errorf("refusals = %v, want %v", got, test.want)
			}
		})
	}
}

// The application a path names is read the same way for every route that names
// one, so reading it and refusing it are one rule rather than four.
func TestAnApplicationInThePathIsAnIdentifier(t *testing.T) {
	t.Parallel()

	given := inputs.New(applicationPathRequest(managedApplicationID))

	if identifier := readApplicationIdentifier(given); identifier.String() != managedApplicationID {
		t.Errorf("application_id = %q, want %q", identifier, managedApplicationID)
	}

	if !given.OK() {
		t.Errorf("a valid path value was refused: %v", refusals(given))
	}

	for _, value := range []string{"", "not-an-identifier", managedApplicationID + "x"} {
		refused := inputs.New(applicationPathRequest(value))
		readApplicationIdentifier(refused)

		if got := refusals(refused); !slices.Equal(got, []string{"path.application_id uuid_parsing"}) {
			t.Errorf("refusals = %v, want the path value to be refused", got)
		}
	}
}

// The submitted body is the complete set of callbacks, and an empty list is how
// an application says it has none.
func TestTheSubmittedCallbacksAreTheWholeBody(t *testing.T) {
	t.Parallel()

	given := inputs.New(callbackRequest(
		`["https://one.example.test/return","https://two.example.test/return"]`))
	uris := readSubmittedCallbackURIs(given)

	if !given.OK() {
		t.Fatalf("a valid list was refused: %v", refusals(given))
	}

	want := []string{"https://one.example.test/return", "https://two.example.test/return"}
	if !slices.Equal(uris, want) {
		t.Errorf("callback URIs = %v, want %v", uris, want)
	}

	cleared := inputs.New(callbackRequest(`[]`))

	if uris := readSubmittedCallbackURIs(cleared); len(uris) != 0 {
		t.Errorf("callback URIs = %v, want none", uris)
	}

	if !cleared.OK() {
		t.Errorf("an empty list was refused: %v", refusals(cleared))
	}
}

func TestTheSubmittedCallbacksRefuseWhatIsNotAList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "no body", want: []string{"body missing"}},
		{name: "an object", body: `{"callback_uris":[]}`, want: []string{"body list_type"}},
		{
			name: "an entry that is not text",
			body: `["https://one.example.test/return",7]`,
			want: []string{"body.1 string_type"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			given := inputs.New(callbackRequest(test.body))
			readSubmittedCallbackURIs(given)

			if got := refusals(given); !slices.Equal(got, test.want) {
				t.Errorf("refusals = %v, want %v", got, test.want)
			}
		})
	}
}
