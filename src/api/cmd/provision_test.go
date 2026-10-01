package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/siteapplication"
)

const placeholderSiteOrigin = "https://auth.example.test"

// provisionRun is what one run of the provision command did and said.
type provisionRun struct {
	perform *recorder
	// output is standard output, which carries only the result.
	output string
	// prompts is standard error, where questions and the outcome are written.
	prompts string
	// asked reports whether anything was read from standard input.
	asked bool
	err   error
}

// readRecorder answers from a script and records that it was read.
type readRecorder struct {
	answers *strings.Reader
	read    bool
}

func (r *readRecorder) Read(buffer []byte) (int, error) {
	r.read = true

	return r.answers.Read(buffer)
}

func runProvision(t *testing.T, perform *recorder, input string, arguments ...string) provisionRun {
	t.Helper()

	var output, prompts strings.Builder

	answers := &readRecorder{answers: strings.NewReader(input)}

	root := newCommand(perform)
	root.Reader = answers
	root.Writer = &output
	root.ErrWriter = &prompts

	err := root.Run(t.Context(), append([]string{"abandonauth", "provision"}, arguments...))

	return provisionRun{
		perform: perform,
		output:  output.String(),
		prompts: prompts.String(),
		asked:   answers.read,
		err:     err,
	}
}

// databaseOnly is the one setting provisioning reads from the environment.
func databaseOnly(t *testing.T) {
	t.Helper()

	t.Setenv(environmentDatabaseURL, placeholderDatabaseURL)
	t.Setenv("DEBUG", "false")
}

func flags(applicationID, siteOrigin string) []string {
	return []string{"--" + flagProvisionApplicationID, applicationID, "--" + flagProvisionSiteURL, siteOrigin}
}

// requireRefusedBeforeDatabase asserts a run failed without provisioning and
// without repeating the value it refused.
func requireRefusedBeforeDatabase(t *testing.T, run provisionRun, refused string) {
	t.Helper()

	if run.err == nil {
		t.Fatal("provisioning accepted the input")
	}

	if run.perform.provisioned {
		t.Error("provisioning reached the database despite refusing its input")
	}

	if run.output != "" {
		t.Errorf("a refused run wrote a result: %q", run.output)
	}

	if strings.TrimSpace(refused) == "" {
		return
	}

	for name, text := range map[string]string{"error": run.err.Error(), "output": run.output, "prompts": run.prompts} {
		if strings.Contains(text, refused) {
			t.Errorf("the %s repeats the refused value", name)
		}
	}
}

func TestBareProvisionAsksForIdentifierAndOrigin(t *testing.T) {
	databaseOnly(t)

	run := runProvision(t, &recorder{}, placeholderApplicationID+"\n"+placeholderSiteOrigin+"\n")
	if run.err != nil {
		t.Fatalf("provisioning failed: %v", run.err)
	}

	if !run.perform.provisioned {
		t.Fatal("provisioning did not run")
	}

	if run.perform.applicationID.String() != placeholderApplicationID {
		t.Errorf("application id = %s, want the one answered", run.perform.applicationID)
	}

	if run.perform.callback != placeholderSiteOrigin+"/api/ui" {
		t.Errorf("callback = %q", run.perform.callback)
	}

	if strings.Count(run.prompts, "Application UUID") != 1 || strings.Count(run.prompts, "Site origin") != 1 {
		t.Errorf("each input was not asked for exactly once:\n%s", run.prompts)
	}

	if run.perform.databaseURL.Reveal() != placeholderDatabaseURL {
		t.Error("DATABASE_URL did not reach provisioning")
	}
}

// A deployment's settings never stand in for an answer: bare provisioning asks
// even where the site's settings are in the environment.
func TestBareProvisionIgnoresDeploymentSettings(t *testing.T) {
	applyEnvironment(t, placeholderEnvironment())
	t.Setenv("DEBUG", "false")

	const answered = "0b0e5a3c-6a52-4e57-9d5c-6c1bd5ab0a8e"

	run := runProvision(t, &recorder{}, answered+"\nhttps://answered.example.test\n")
	if run.err != nil {
		t.Fatalf("provisioning failed: %v", run.err)
	}

	if run.perform.applicationID.String() != answered {
		t.Errorf("application id = %s, want the answered one", run.perform.applicationID)
	}

	if run.perform.callback != "https://answered.example.test/api/ui" {
		t.Errorf("callback = %q, want one built from the answered origin", run.perform.callback)
	}
}

func TestProvisionWithBothFlagsAsksNothing(t *testing.T) {
	databaseOnly(t)

	run := runProvision(t, &recorder{}, "", flags(placeholderApplicationID, placeholderSiteOrigin)...)
	if run.err != nil {
		t.Fatalf("provisioning failed: %v", run.err)
	}

	if run.asked {
		t.Error("provisioning read standard input although both flags were given")
	}

	if !run.perform.provisioned || run.perform.applicationID.String() != placeholderApplicationID {
		t.Error("provisioning did not run with the given identifier")
	}
}

func TestProvisionWithOneFlagFailsWithoutAsking(t *testing.T) {
	databaseOnly(t)

	for _, arguments := range [][]string{
		{"--" + flagProvisionApplicationID, placeholderApplicationID},
		{"--" + flagProvisionSiteURL, placeholderSiteOrigin},
	} {
		t.Run(arguments[0], func(t *testing.T) {
			run := runProvision(t, &recorder{}, placeholderApplicationID+"\n"+placeholderSiteOrigin+"\n", arguments...)

			requireRefusedBeforeDatabase(t, run, "")

			if run.asked {
				t.Error("provisioning asked for the missing input")
			}
		})
	}
}

// Success reports the identifier as the setting it belongs in, and nothing
// else: neither the database address nor any credential.
func TestProvisionPrintsOnlyIdentifierAssignment(t *testing.T) {
	for name, outcome := range map[string]siteapplication.Outcome{
		"created":         siteapplication.Created,
		"already present": siteapplication.AlreadyPresent,
	} {
		t.Run(name, func(t *testing.T) {
			databaseOnly(t)

			run := runProvision(t, &recorder{outcomeToReturn: outcome}, "",
				flags(placeholderApplicationID, placeholderSiteOrigin)...)
			if run.err != nil {
				t.Fatalf("provisioning failed: %v", run.err)
			}

			if want := "ABANDON_AUTH_DEVELOPER_APP_ID=" + placeholderApplicationID + "\n"; run.output != want {
				t.Errorf("output = %q, want %q", run.output, want)
			}

			if strings.Contains(run.output+run.prompts, placeholderDatabaseURL) ||
				strings.Contains(run.output+run.prompts, "abandonauth:abandonauth@") {
				t.Error("the run printed the database address")
			}
		})
	}
}

func TestProvisionReportsOperationFailure(t *testing.T) {
	databaseOnly(t)

	run := runProvision(t, &recorder{errorToReturnOnCall: errors.New("the database did not answer")}, "",
		flags(placeholderApplicationID, placeholderSiteOrigin)...)
	if run.err == nil {
		t.Fatal("a failed provisioning reported success")
	}

	if run.output != "" {
		t.Errorf("a failed provisioning wrote a result: %q", run.output)
	}
}

func TestProvisionWithoutDatabaseFailsBeforeAsking(t *testing.T) {
	t.Setenv(environmentDatabaseURL, "")

	run := runProvision(t, &recorder{}, placeholderApplicationID+"\n"+placeholderSiteOrigin+"\n")

	requireRefusedBeforeDatabase(t, run, "")

	if !strings.Contains(run.err.Error(), environmentDatabaseURL) {
		t.Errorf("the failure does not name %s: %v", environmentDatabaseURL, run.err)
	}

	if run.asked {
		t.Error("provisioning asked for inputs it could not use")
	}
}

func TestProvisionRefusesUnusableAnswers(t *testing.T) {
	cases := map[string]struct {
		input   string
		refused string
	}{
		"no answers":           {"", ""},
		"blank answers":        {"\n\n", ""},
		"identifier only":      {placeholderApplicationID + "\n", ""},
		"malformed identifier": {"not-a-uuid-placeholder\n" + placeholderSiteOrigin + "\n", "not-a-uuid-placeholder"},
		"nil identifier":       {"00000000-0000-0000-0000-000000000000\n" + placeholderSiteOrigin + "\n", ""},
		"plain http elsewhere": {placeholderApplicationID + "\nhttp://plain.example.test\n", "plain.example.test"},
		"origin with a path":   {placeholderApplicationID + "\nhttps://auth.example.test/pathed\n", "/pathed"},
		"origin with a query":  {placeholderApplicationID + "\nhttps://auth.example.test/?q=queried\n", "queried"},
		"origin with a fragment": {
			placeholderApplicationID + "\nhttps://auth.example.test/#fragmented\n", "fragmented",
		},
		"origin carrying a credential": {
			placeholderApplicationID + "\nhttps://operator:placeholder-credential@auth.example.test\n",
			"placeholder-credential",
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			databaseOnly(t)

			requireRefusedBeforeDatabase(t, runProvision(t, &recorder{}, testCase.input), testCase.refused)
		})
	}
}

func TestProvisionRefusesUnusableFlags(t *testing.T) {
	cases := map[string]struct {
		arguments []string
		refused   string
	}{
		"malformed identifier": {flags("not-a-uuid-placeholder", placeholderSiteOrigin), "not-a-uuid-placeholder"},
		"nil identifier":       {flags("00000000-0000-0000-0000-000000000000", placeholderSiteOrigin), ""},
		"empty origin":         {flags(placeholderApplicationID, ""), ""},
		"two trailing slashes": {flags(placeholderApplicationID, "https://auth.example.test//"), ""},
		"positional argument": {
			append(flags(placeholderApplicationID, placeholderSiteOrigin), "stray-positional-placeholder"),
			"stray-positional-placeholder",
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			databaseOnly(t)

			requireRefusedBeforeDatabase(t, runProvision(t, &recorder{}, "", testCase.arguments...), testCase.refused)
		})
	}
}

// The callback keeps the origin's spelling and drops only its one optional
// trailing slash, which is the address the site builds from the same setting.
func TestProvisionDerivesOneCallbackPerOrigin(t *testing.T) {
	cases := map[string]string{
		"https://auth.example.test":      "https://auth.example.test/api/ui",
		"https://auth.example.test/":     "https://auth.example.test/api/ui",
		"HTTPS://Auth.Example.TEST/":     "HTTPS://Auth.Example.TEST/api/ui",
		"https://auth.example.test:443":  "https://auth.example.test:443/api/ui",
		"https://auth.example.test:8443": "https://auth.example.test:8443/api/ui",
	}

	for origin, want := range cases {
		t.Run(origin, func(t *testing.T) {
			databaseOnly(t)

			run := runProvision(t, &recorder{}, "", flags(placeholderApplicationID, origin)...)
			if run.err != nil {
				t.Fatalf("provisioning failed: %v", run.err)
			}

			if run.perform.callback != want {
				t.Errorf("callback = %q, want %q", run.perform.callback, want)
			}
		})
	}
}

// The origin is judged as serving judges it: a deployment build refuses debug
// mode and plain HTTP outright, and a development build accepts loopback HTTP
// only in debug mode.
func TestProvisionTransportFollowsBuild(t *testing.T) {
	const loopback = "http://localhost:3000"

	type attempt struct {
		debug  string
		origin string
		accept bool
	}

	attempts := map[string]attempt{
		"https without debug":    {"false", placeholderSiteOrigin, true},
		"loopback without debug": {"false", loopback, false},
		"https with debug":       {"true", placeholderSiteOrigin, buildServesDevelopmentRoutes},
		"loopback with debug":    {"true", loopback, buildServesDevelopmentRoutes},
	}

	for name, attempt := range attempts {
		t.Run(name, func(t *testing.T) {
			databaseOnly(t)
			t.Setenv("DEBUG", attempt.debug)

			run := runProvision(t, &recorder{}, "", flags(placeholderApplicationID, attempt.origin)...)

			if !attempt.accept {
				requireRefusedBeforeDatabase(t, run, "")

				return
			}

			if run.err != nil {
				t.Fatalf("provisioning failed: %v", run.err)
			}

			if run.perform.callback != attempt.origin+"/api/ui" {
				t.Errorf("callback = %q", run.perform.callback)
			}
		})
	}
}
