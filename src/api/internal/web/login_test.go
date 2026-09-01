package web

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
)

// collectingApplicationID is a well-formed identifier for the application
// spending a code. It is a placeholder and names nothing.
const collectingApplicationID = "6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0"

func spendRequest(code, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))

	if code != "" {
		request.Header.Set(ExchangeTokenHeader, code)
	}

	return request
}

// An application relying on its own access token sends the code and nothing
// else, so the body remains optional.
func TestSpendingACodeReadsTheCodeWithoutABody(t *testing.T) {
	t.Parallel()

	given := inputs.New(spendRequest("an-opaque-code", ""))
	presented := readLoginInputs(given)

	if !given.OK() {
		t.Fatalf("a request carrying only the code was refused: %v", refusals(given))
	}

	if presented.code != "an-opaque-code" {
		t.Error("the code in the header did not reach the handler")
	}

	if presented.credentialsGiven {
		t.Error("a request with no body was read as carrying credentials")
	}
}

// A client that sends null is saying it has nothing to send, which is the same
// as sending nothing at all.
func TestSpendingACodeTreatsANullBodyAsAbsent(t *testing.T) {
	t.Parallel()

	given := inputs.New(spendRequest("an-opaque-code", "null"))
	presented := readLoginInputs(given)

	if !given.OK() {
		t.Fatalf("a null body was refused: %v", refusals(given))
	}

	if presented.credentialsGiven {
		t.Error("a null body was read as carrying credentials")
	}
}

// A body is a claim about which application is collecting the token, so both
// members of it are required once one arrives.
func TestSpendingACodeWithCredentialsReadsBothOfThem(t *testing.T) {
	t.Parallel()

	given := inputs.New(spendRequest("an-opaque-code",
		`{"id":"`+collectingApplicationID+`","refresh_token":"a-placeholder-credential"}`))
	presented := readLoginInputs(given)

	if !given.OK() {
		t.Fatalf("a valid set of credentials was refused: %v", refusals(given))
	}

	if !presented.credentialsGiven {
		t.Fatal("a body carrying credentials was read as absent")
	}

	if presented.applicationID.String() != collectingApplicationID {
		t.Errorf("id = %q, want %q", presented.applicationID, collectingApplicationID)
	}

	if presented.refreshToken != "a-placeholder-credential" {
		t.Error("the credential in the body did not reach the handler")
	}
}

// An application that sends members this service does not know keeps working,
// which is what lets a client be upgraded before the service is.
func TestSpendingACodeIgnoresMembersItDoesNotKnow(t *testing.T) {
	t.Parallel()

	given := inputs.New(spendRequest("an-opaque-code",
		`{"id":"`+collectingApplicationID+`","refresh_token":"a-placeholder-credential","scopes":["identify"]}`))

	if readLoginInputs(given); !given.OK() {
		t.Errorf("a member this service does not read was refused: %v", refusals(given))
	}
}

func TestSpendingACodeRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code string
		body string
		want []string
	}{
		{
			name: "no code",
			want: []string{"header.exchange-token missing"},
		},
		{
			name: "credentials naming no application",
			code: "an-opaque-code",
			body: `{"refresh_token":"a-placeholder-credential"}`,
			want: []string{"body.id missing"},
		},
		{
			name: "credentials carrying no credential",
			code: "an-opaque-code",
			body: `{"id":"` + collectingApplicationID + `"}`,
			want: []string{"body.refresh_token missing"},
		},
		{
			name: "an application that is not an identifier",
			code: "an-opaque-code",
			body: `{"id":"not-an-identifier","refresh_token":"a-placeholder-credential"}`,
			want: []string{"body.id uuid_parsing"},
		},
		{
			name: "a credential that is not text",
			code: "an-opaque-code",
			body: `{"id":"` + collectingApplicationID + `","refresh_token":42}`,
			want: []string{"body.refresh_token string_type"},
		},
		{
			name: "a body that is not an object",
			code: "an-opaque-code",
			body: `["a"]`,
			want: []string{"body model_attributes_type"},
		},
		{
			name: "a body that is present and malformed",
			code: "an-opaque-code",
			body: `{`,
			want: []string{"body json_invalid"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			given := inputs.New(spendRequest(test.code, test.body))
			readLoginInputs(given)

			if got := refusals(given); !slices.Equal(got, test.want) {
				t.Errorf("refusals = %v, want %v", got, test.want)
			}
		})
	}
}
