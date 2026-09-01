package request_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

const applicationID = "6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0"

func post(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
}

func failureSummaries(failures []response.Failure) []string {
	summaries := make([]string, 0, len(failures))

	for _, failure := range failures {
		location := make([]string, 0, len(failure.Location))

		for _, part := range failure.Location {
			location = append(location, fmt.Sprintf("%v", part))
		}

		summaries = append(summaries, strings.Join(location, ".")+" "+failure.Type)
	}

	return summaries
}

func TestAnObjectBodyIsReadMemberByMember(t *testing.T) {
	t.Parallel()

	inputs := request.New(post(`{"id":"` + applicationID + `","refresh_token":"placeholder-refresh-token"}`))
	inputs.DecodeObjectBody()

	id := inputs.BodyUUID("id")
	token := inputs.BodyString("refresh_token")

	if !inputs.OK() {
		t.Fatalf("a valid body was refused: %v", inputs.Failures())
	}

	if id.String() != applicationID {
		t.Errorf("id = %q, want %q", id, applicationID)
	}

	if token != "placeholder-refresh-token" {
		t.Errorf("refresh_token = %q", token)
	}
}

// An application that sends fields this service does not know keeps working,
// which is what lets a client be upgraded before the service is.
func TestUnknownMembersAreIgnored(t *testing.T) {
	t.Parallel()

	inputs := request.New(post(`{"name":"an application","scopes":["identify"],"nested":{"a":1}}`))
	inputs.DecodeObjectBody()

	if name := inputs.BodyString("name"); name != "an application" {
		t.Errorf("name = %q", name)
	}

	if !inputs.OK() {
		t.Errorf("unknown members were refused: %v", inputs.Failures())
	}
}

func TestEveryRefusedInputIsReported(t *testing.T) {
	t.Parallel()

	inputs := request.New(post(`{"refresh_token":42}`))
	inputs.DecodeObjectBody()

	inputs.BodyUUID("id")
	inputs.BodyString("refresh_token")

	got := failureSummaries(inputs.Failures())
	want := []string{"body.id missing", "body.refresh_token string_type"}

	if !slices.Equal(got, want) {
		t.Errorf("failures = %v, want %v", got, want)
	}
}

func TestBodyFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "no body at all", body: "", want: []string{"body missing"}},
		{name: "not JSON", body: "not json", want: []string{"body json_invalid"}},
		{name: "truncated JSON", body: `{"id":`, want: []string{"body json_invalid"}},
		{name: "a second document after the first", body: `{"id":"a"} {"id":"b"}`, want: []string{"body json_invalid"}},
		{name: "an array where an object is expected", body: `["a"]`, want: []string{"body model_attributes_type"}},
		{name: "a number where an object is expected", body: `7`, want: []string{"body model_attributes_type"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			inputs := request.New(post(test.body))
			inputs.DecodeObjectBody()

			if got := failureSummaries(inputs.Failures()); !slices.Equal(got, test.want) {
				t.Errorf("failures = %v, want %v", got, test.want)
			}
		})
	}
}

// A member sent as null is the same as a member that was not sent: the service
// has no field it accepts an explicit null for.
func TestANullMemberIsTreatedAsAbsent(t *testing.T) {
	t.Parallel()

	inputs := request.New(post(`{"name":null}`))
	inputs.DecodeObjectBody()
	inputs.BodyString("name")

	if got := failureSummaries(inputs.Failures()); !slices.Equal(got, []string{"body.name missing"}) {
		t.Errorf("failures = %v", got)
	}
}

// Reading a member of a body that never arrived must not add a refusal for the
// member as well: the body itself is the thing that was wrong.
func TestAMissingBodyIsRefusedOnlyOnce(t *testing.T) {
	t.Parallel()

	inputs := request.New(post(""))
	inputs.DecodeObjectBody()
	inputs.BodyUUID("id")
	inputs.BodyString("refresh_token")

	if got := failureSummaries(inputs.Failures()); !slices.Equal(got, []string{"body missing"}) {
		t.Errorf("failures = %v", got)
	}
}

func TestAnOptionalBodyMayBeAbsent(t *testing.T) {
	t.Parallel()

	inputs := request.New(post(""))

	if inputs.DecodeOptionalObjectBody() {
		t.Error("an absent optional body was reported as present")
	}

	if !inputs.OK() {
		t.Errorf("an absent optional body was refused: %v", inputs.Failures())
	}
}

// A client that sends null is saying it has nothing to send, which is the same
// as sending nothing.
func TestAnOptionalBodyThatIsNullIsAbsent(t *testing.T) {
	t.Parallel()

	inputs := request.New(post("null"))

	if inputs.DecodeOptionalObjectBody() {
		t.Error("a null optional body was reported as present")
	}

	if !inputs.OK() {
		t.Errorf("a null optional body was refused: %v", inputs.Failures())
	}
}

// Optional does not mean unchecked. A body that is present and malformed is
// refused rather than silently treated as absent, which would let a caller skip
// credential checks by sending broken JSON.
func TestAnOptionalBodyThatIsPresentIsStillChecked(t *testing.T) {
	t.Parallel()

	inputs := request.New(post("{"))

	if inputs.DecodeOptionalObjectBody() {
		t.Error("a malformed optional body was reported as present")
	}

	if inputs.OK() {
		t.Error("a malformed optional body was accepted")
	}
}

func TestAStringArrayBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		body  string
		want  []string
		fails []string
	}{
		{
			name: "a list of URIs",
			body: `["https://one.example.test/cb","https://two.example.test/cb"]`,
			want: []string{"https://one.example.test/cb", "https://two.example.test/cb"},
		},
		{name: "an empty list", body: `[]`, want: []string{}},
		{name: "no body", body: ``, fails: []string{"body missing"}},
		{name: "an object", body: `{"uris":[]}`, fails: []string{"body list_type"}},
		{name: "an element of the wrong type", body: `["https://one.example.test/cb",7]`, fails: []string{"body.1 string_type"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			inputs := request.New(post(test.body))
			got := inputs.DecodeStringArrayBody()

			if len(test.fails) > 0 {
				if summaries := failureSummaries(inputs.Failures()); !slices.Equal(summaries, test.fails) {
					t.Errorf("failures = %v, want %v", summaries, test.fails)
				}

				return
			}

			if !inputs.OK() {
				t.Fatalf("a valid list was refused: %v", inputs.Failures())
			}

			if !slices.Equal(got, test.want) {
				t.Errorf("values = %v, want %v", got, test.want)
			}
		})
	}
}

func TestABodyLargerThanTheLimitIsRefusedWithoutBeingBuffered(t *testing.T) {
	t.Parallel()

	oversized := `{"name":"` + strings.Repeat("a", int(request.MaxBodyBytes)+1) + `"}`

	inputs := request.New(post(oversized))
	inputs.DecodeObjectBody()

	if got := failureSummaries(inputs.Failures()); !slices.Equal(got, []string{"body too_long"}) {
		t.Errorf("failures = %v", got)
	}
}

func TestPathUUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantID  string
		refused bool
	}{
		{name: "a UUID", value: applicationID, wantID: applicationID},
		{name: "not a UUID", value: "abc", refused: true},
		{name: "empty", value: "", refused: true},
		{name: "a UUID with trailing text", value: applicationID + "x", refused: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			httpRequest := httptest.NewRequest(http.MethodGet, "/developer_application/"+test.value, nil)
			httpRequest.SetPathValue("application_id", test.value)

			inputs := request.New(httpRequest)
			got := inputs.PathUUID("application_id")

			if test.refused {
				if summaries := failureSummaries(inputs.Failures()); !slices.Equal(summaries, []string{"path.application_id uuid_parsing"}) {
					t.Errorf("failures = %v", summaries)
				}

				if got != uuid.Nil {
					t.Errorf("a refused path value still produced %v", got)
				}

				return
			}

			if !inputs.OK() {
				t.Fatalf("a valid path value was refused: %v", inputs.Failures())
			}

			if got.String() != test.wantID {
				t.Errorf("application_id = %q, want %q", got, test.wantID)
			}
		})
	}
}

func TestARequiredHeader(t *testing.T) {
	t.Parallel()

	httpRequest := post("")
	httpRequest.Header.Set("exchange-token", "opaque-placeholder")

	inputs := request.New(httpRequest)

	if got := inputs.Header("exchange-token"); got != "opaque-placeholder" {
		t.Errorf("exchange-token = %q", got)
	}

	if !inputs.OK() {
		t.Errorf("a present header was refused: %v", inputs.Failures())
	}

	missing := request.New(post(""))
	missing.Header("exchange-token")

	if got := failureSummaries(missing.Failures()); !slices.Equal(got, []string{"header.exchange-token missing"}) {
		t.Errorf("failures = %v", got)
	}
}

func TestARequiredQueryParameter(t *testing.T) {
	t.Parallel()

	present := request.New(httptest.NewRequest(http.MethodGet, "/google?code=opaque-placeholder", nil))

	if got := present.Query("code"); got != "opaque-placeholder" {
		t.Errorf("code = %q", got)
	}

	if !present.OK() {
		t.Errorf("a present query parameter was refused: %v", present.Failures())
	}

	missing := request.New(httptest.NewRequest(http.MethodGet, "/google", nil))
	missing.Query("code")

	if got := failureSummaries(missing.Failures()); !slices.Equal(got, []string{"query.code missing"}) {
		t.Errorf("failures = %v", got)
	}
}

// A parameter that is present but empty is still present. An empty state value
// must reach the handler, which refuses it for its own reasons, rather than
// being reported as absent here.
func TestAnEmptyQueryParameterIsPresent(t *testing.T) {
	t.Parallel()

	inputs := request.New(httptest.NewRequest(http.MethodGet, "/google?code=", nil))

	if got := inputs.Query("code"); got != "" {
		t.Errorf("code = %q, want empty", got)
	}

	if !inputs.OK() {
		t.Errorf("an empty but present query parameter was refused: %v", inputs.Failures())
	}
}

func TestOptionalInputsAreNeverRefused(t *testing.T) {
	t.Parallel()

	inputs := request.New(httptest.NewRequest(http.MethodGet, "/ui/", nil))

	if got := inputs.OptionalQuery("code"); got != "" {
		t.Errorf("code = %q, want empty", got)
	}

	if got := inputs.OptionalHeader("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty", got)
	}

	if !inputs.OK() {
		t.Errorf("absent optional inputs were refused: %v", inputs.Failures())
	}
}

// The refusal is written to the client and may be logged, so it must describe
// the input without repeating it.
func TestARefusalNeverRepeatsTheValue(t *testing.T) {
	t.Parallel()

	const secretish = "bearer-looking-value-that-must-not-be-echoed"

	inputs := request.New(post(`{"id":"` + secretish + `","refresh_token":` + `"` + secretish + `"}`))
	inputs.DecodeObjectBody()
	inputs.BodyUUID("id")

	for _, failure := range inputs.Failures() {
		if strings.Contains(failure.Message, secretish) {
			t.Errorf("a refusal repeats the rejected value: %+v", failure)
		}

		for _, part := range failure.Location {
			if text, isText := part.(string); isText && strings.Contains(text, secretish) {
				t.Errorf("a refusal location repeats the rejected value: %+v", failure)
			}
		}
	}
}
