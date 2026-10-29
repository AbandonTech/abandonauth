package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
)

// signingInToApplicationID is a well-formed identifier for the application a
// person is signing in to. It is a placeholder and names nothing.
const signingInToApplicationID = "00000000-0000-0000-0000-000000000001"

const registeredCallbackURI = "https://relying.example.test/return"

func authorizeRequest(provider string, query url.Values) *http.Request {
	request := httptest.NewRequest(
		http.MethodGet, APIRoot+"/ui/"+provider+"/authorize?"+query.Encode(), nil,
	)
	request.SetPathValue("provider", provider)

	return request
}

func authorizeQuery(applicationID, callback string) url.Values {
	return url.Values{"application_id": {applicationID}, "callback_uri": {callback}}
}

// Every provider this service offers can be named, and the application and the
// exact callback are read alongside it.
func TestStartingLoginReadsProviderApplicationAndCallback(t *testing.T) {
	t.Parallel()

	for _, provider := range oauth.Providers {
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()

			given := inputs.New(authorizeRequest(
				string(provider), authorizeQuery(signingInToApplicationID, registeredCallbackURI),
			))
			wanted := readProviderLoginInputs(given)

			if !given.OK() {
				t.Fatalf("a valid request was refused: %v", refusals(given))
			}

			if wanted.provider != provider {
				t.Errorf("provider = %q, want %q", wanted.provider, provider)
			}

			if wanted.applicationID.String() != signingInToApplicationID {
				t.Errorf("application_id = %q, want %q", wanted.applicationID, signingInToApplicationID)
			}

			if wanted.callbackURI != registeredCallbackURI {
				t.Errorf("callback_uri = %q, want %q", wanted.callbackURI, registeredCallbackURI)
			}
		})
	}
}

// A callback that is present but empty is still present. It reaches the handler,
// which refuses it because no application registered it, rather than being
// reported as an input that was never sent.
func TestStartingLoginReadsEmptyCallbackAsGiven(t *testing.T) {
	t.Parallel()

	given := inputs.New(authorizeRequest("discord", authorizeQuery(signingInToApplicationID, "")))
	wanted := readProviderLoginInputs(given)

	if !given.OK() {
		t.Fatalf("an empty callback was refused as an input: %v", refusals(given))
	}

	if wanted.callbackURI != "" {
		t.Errorf("callback_uri = %q, want empty", wanted.callbackURI)
	}
}

// The refusal lists the providers offered and never repeats the value given.
func TestStartingLoginNamesOfferedProvidersWhenRefusingOne(t *testing.T) {
	t.Parallel()

	const unoffered = "placeholder-unoffered-provider"

	given := inputs.New(authorizeRequest(unoffered, authorizeQuery(signingInToApplicationID, registeredCallbackURI)))
	readProviderLoginInputs(given)

	failures := given.Failures()
	if len(failures) != 1 {
		t.Fatalf("refusals = %v, want exactly one", refusals(given))
	}

	if failures[0].Message != "Input must be discord, github, or google" {
		t.Errorf("msg = %q", failures[0].Message)
	}

	if strings.Contains(failures[0].Message, unoffered) {
		t.Error("the refusal repeats the provider that was named")
	}
}

func TestStartingLoginRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider string
		query    url.Values
		want     []string
	}{
		{
			name:     "a provider this service does not offer",
			provider: "somewhere-else",
			query:    authorizeQuery(signingInToApplicationID, registeredCallbackURI),
			want:     []string{"path.provider enum"},
		},
		{
			name:     "neither an application nor a callback",
			provider: "discord",
			query:    url.Values{},
			want:     []string{"query.application_id missing", "query.callback_uri missing"},
		},
		{
			name:     "an application that is not an identifier",
			provider: "discord",
			query:    authorizeQuery("not-an-identifier", registeredCallbackURI),
			want:     []string{"query.application_id uuid_parsing"},
		},
		{
			name:     "an unknown provider and an unreadable application",
			provider: "somewhere-else",
			query:    authorizeQuery("not-an-identifier", registeredCallbackURI),
			want:     []string{"path.provider enum", "query.application_id uuid_parsing"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			given := inputs.New(authorizeRequest(test.provider, test.query))
			readProviderLoginInputs(given)

			if got := refusals(given); !slices.Equal(got, test.want) {
				t.Errorf("refusals = %v, want %v", got, test.want)
			}
		})
	}
}
