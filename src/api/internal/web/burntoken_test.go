package web

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
)

func withdrawRequest(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, APIRoot+"/burn-token", strings.NewReader(body))
}

// Whatever a caller is holding is withdrawn as it was sent: the endpoint reads
// text and does not decide here what kind of credential it is.
func TestWithdrawingReadsTheCredentialAsGiven(t *testing.T) {
	t.Parallel()

	given := inputs.New(withdrawRequest(`{"token":"a-placeholder-credential"}`))
	presented := readWithdrawnCredential(given)

	if !given.OK() {
		t.Fatalf("a valid request was refused: %v", refusals(given))
	}

	if presented != "a-placeholder-credential" {
		t.Error("the credential in the body did not reach the handler")
	}
}

func TestWithdrawingRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "no body", want: []string{"body missing"}},
		{name: "nothing to withdraw", body: `{}`, want: []string{"body.token missing"}},
		{name: "a credential sent as null", body: `{"token":null}`, want: []string{"body.token missing"}},
		{name: "a credential that is not text", body: `{"token":42}`, want: []string{"body.token string_type"}},
		{name: "a body that is not an object", body: `["a"]`, want: []string{"body model_attributes_type"}},
		{name: "a body that is not JSON", body: `{`, want: []string{"body json_invalid"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			given := inputs.New(withdrawRequest(test.body))
			readWithdrawnCredential(given)

			if got := refusals(given); !slices.Equal(got, test.want) {
				t.Errorf("refusals = %v, want %v", got, test.want)
			}
		})
	}
}
