package web

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
)

// managedApplicationID is a well-formed identifier for the application a
// request names. It is a placeholder and names nothing.
const managedApplicationID = "00000000-0000-0000-0000-000000000001"

func applicationBodyRequest(path, body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
}

func applicationPathRequest(value string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, APIRoot+"/developer_application/"+value, nil)
	request.SetPathValue("application_id", value)

	return request
}

func callbackRequest(body string) *http.Request {
	return httptest.NewRequest(
		http.MethodPatch,
		APIRoot+"/developer_application/"+managedApplicationID+"/callback_uris",
		strings.NewReader(body),
	)
}

// An application is registered with a name and, optionally, its client type; a
// registration that names no type is confidential, as every registration was
// before public clients could be named.
func TestRegisteringApplicationReadsNameAndClientType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want applications.ClientType
	}{
		{name: "no client type", body: `{"name":"an application"}`, want: applications.Confidential},
		{name: "an explicit null", body: `{"name":"an application","client_type":null}`, want: applications.Confidential},
		{name: "confidential", body: `{"name":"an application","client_type":"confidential"}`, want: applications.Confidential},
		{name: "public", body: `{"name":"an application","client_type":"public"}`, want: applications.Public},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			given := inputs.New(applicationBodyRequest(APIRoot+"/developer_application", test.body))
			registration := readApplicationRegistration(given)

			if !given.OK() {
				t.Fatalf("a valid request was refused: %v", refusals(given))
			}

			if registration.name != "an application" || registration.clientType != test.want {
				t.Errorf("registration = %q %q, want %q %q",
					registration.name, registration.clientType, "an application", test.want)
			}
		})
	}
}

func TestRegisteringApplicationRefusesWhatItCannotRead(t *testing.T) {
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
		{
			name: "a client type that is not text",
			body: `{"name":"an application","client_type":1}`,
			want: []string{"body.client_type string_type"},
		},
		{
			name: "an unknown client type",
			body: `{"name":"an application","client_type":"native"}`,
			want: []string{"body.client_type enum"},
		},
		{
			name: "a client type in another letter case",
			body: `{"name":"an application","client_type":"Public"}`,
			want: []string{"body.client_type enum"},
		},
		{
			name: "an empty client type",
			body: `{"name":"an application","client_type":""}`,
			want: []string{"body.client_type enum"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			given := inputs.New(applicationBodyRequest(APIRoot+"/developer_application", test.body))
			readApplicationRegistration(given)

			if got := refusals(given); !slices.Equal(got, test.want) {
				t.Errorf("refusals = %v, want %v", got, test.want)
			}
		})
	}
}

// An application says which application it is and proves it in the same
// request, so neither member is optional.
func TestApplicationsCredentialsAreReadTogether(t *testing.T) {
	t.Parallel()

	given := inputs.New(applicationBodyRequest(APIRoot+"/developer_application/login",
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

func TestApplicationsCredentialsRefuseWhatTheyCannotRead(t *testing.T) {
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

			given := inputs.New(applicationBodyRequest(APIRoot+"/developer_application/login", test.body))
			readApplicationCredentials(given)

			if got := refusals(given); !slices.Equal(got, test.want) {
				t.Errorf("refusals = %v, want %v", got, test.want)
			}
		})
	}
}

// The application a path names is read the same way for every route that names
// one, so reading it and refusing it are one rule rather than four.
func TestApplicationInPathIsIdentifier(t *testing.T) {
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
func TestSubmittedCallbacksAreWholeBody(t *testing.T) {
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

func TestSubmittedCallbacksRefuseWhatIsNotList(t *testing.T) {
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
