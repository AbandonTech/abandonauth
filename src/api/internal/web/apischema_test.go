package web

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// developmentOperations are the password sign-in operations. Every build
// documents them, labelled development-only; only a devtools build declares
// them.
var developmentOperations = []string{"POST /api/create_test_user", "POST /api/login_test_user"}

// developmentBuildLabel is the value of x-abandonauth-build on an operation a
// deployment build does not serve.
const developmentBuildLabel = "development"

// openAPIDocument is the part of the OpenAPI document this service commits to.
// Unknown members are refused when it is decoded, so a misspelt member fails a
// test instead of being silently ignored by every reader.
type openAPIDocument struct {
	OpenAPI string `yaml:"openapi"`
	Info    struct {
		Title       string `yaml:"title"`
		Version     string `yaml:"version"`
		Description string `yaml:"description"`
	} `yaml:"info"`
	// Servers is read so that its absence can be asserted. A published path is
	// the whole address, combined by a reader with the origin the document came
	// from; naming a server would claim something else supplies part of it.
	Servers []any `yaml:"servers"`
	Tags    []struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"tags"`
	Paths      map[string]map[string]openAPIOperation `yaml:"paths"`
	Components struct {
		SecuritySchemes map[string]openAPISecurityScheme `yaml:"securitySchemes"`
		Parameters      map[string]openAPIParameter      `yaml:"parameters"`
		Headers         map[string]openAPIHeader         `yaml:"headers"`
		Schemas         map[string]openAPISchema         `yaml:"schemas"`
		Responses       map[string]openAPIResponse       `yaml:"responses"`
	} `yaml:"components"`
}

type openAPISecurityScheme struct {
	Type         string `yaml:"type"`
	Scheme       string `yaml:"scheme"`
	BearerFormat string `yaml:"bearerFormat"`
	In           string `yaml:"in"`
	Name         string `yaml:"name"`
	Description  string `yaml:"description"`
}

type openAPIOperation struct {
	Tags        []string                   `yaml:"tags"`
	Summary     string                     `yaml:"summary"`
	Description string                     `yaml:"description"`
	Build       string                     `yaml:"x-abandonauth-build"`
	Security    *[]map[string][]string     `yaml:"security"`
	Parameters  []openAPIParameter         `yaml:"parameters"`
	RequestBody *openAPIRequestBody        `yaml:"requestBody"`
	Responses   map[string]openAPIResponse `yaml:"responses"`
}

type openAPIParameter struct {
	Ref         string        `yaml:"$ref"`
	Name        string        `yaml:"name"`
	In          string        `yaml:"in"`
	Required    bool          `yaml:"required"`
	Description string        `yaml:"description"`
	Schema      openAPISchema `yaml:"schema"`
}

type openAPIRequestBody struct {
	Required    bool                        `yaml:"required"`
	Description string                      `yaml:"description"`
	Content     map[string]openAPIMediaType `yaml:"content"`
}

type openAPIMediaType struct {
	Schema openAPISchema `yaml:"schema"`
}

type openAPIResponse struct {
	Ref         string                      `yaml:"$ref"`
	Description string                      `yaml:"description"`
	Headers     map[string]openAPIHeader    `yaml:"headers"`
	Content     map[string]openAPIMediaType `yaml:"content"`
}

type openAPIHeader struct {
	Ref         string        `yaml:"$ref"`
	Description string        `yaml:"description"`
	Schema      openAPISchema `yaml:"schema"`
}

type openAPISchema struct {
	Ref         string                   `yaml:"$ref"`
	Type        string                   `yaml:"type"`
	Format      string                   `yaml:"format"`
	Description string                   `yaml:"description"`
	Required    []string                 `yaml:"required"`
	Properties  map[string]openAPISchema `yaml:"properties"`
	Items       *openAPISchema           `yaml:"items"`
	AnyOf       []openAPISchema          `yaml:"anyOf"`
	Enum        []string                 `yaml:"enum"`
	Minimum     *int                     `yaml:"minimum"`
}

func canonicalOpenAPI(t *testing.T) openAPIDocument {
	t.Helper()

	decoder := yaml.NewDecoder(bytes.NewReader(embeddedOpenAPISchema))
	decoder.KnownFields(true)

	var document openAPIDocument
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("openapi.yaml is not the expected shape: %v", err)
	}

	return document
}

func canonicalOpenAPIValue(t *testing.T) map[string]any {
	t.Helper()

	var document map[string]any
	if err := yaml.Unmarshal(embeddedOpenAPISchema, &document); err != nil {
		t.Fatalf("openapi.yaml is not YAML: %v", err)
	}

	return document
}

// operations returns every operation keyed "METHOD /path".
func (d openAPIDocument) operations() map[string]openAPIOperation {
	keyed := make(map[string]openAPIOperation)

	for path, methods := range d.Paths {
		for method, operation := range methods {
			keyed[fmt.Sprintf("%s %s", strings.ToUpper(method), path)] = operation
		}
	}

	return keyed
}

func (d openAPIDocument) operation(t *testing.T, key string) openAPIOperation {
	t.Helper()

	operation, found := d.operations()[key]
	if !found {
		t.Fatalf("the schema documents no %s", key)
	}

	return operation
}

func componentName(t *testing.T, ref, kind string) string {
	t.Helper()

	name, local := strings.CutPrefix(ref, "#/components/"+kind+"/")
	if !local {
		t.Fatalf("%q is not a reference to a local %s component", ref, kind)
	}

	return name
}

func (d openAPIDocument) response(t *testing.T, response openAPIResponse) openAPIResponse {
	t.Helper()

	if response.Ref == "" {
		return response
	}

	resolved, found := d.Components.Responses[componentName(t, response.Ref, "responses")]
	if !found {
		t.Fatalf("response reference %q resolves to nothing", response.Ref)
	}

	return resolved
}

func (d openAPIDocument) parameter(t *testing.T, parameter openAPIParameter) openAPIParameter {
	t.Helper()

	if parameter.Ref == "" {
		return parameter
	}

	resolved, found := d.Components.Parameters[componentName(t, parameter.Ref, "parameters")]
	if !found {
		t.Fatalf("parameter reference %q resolves to nothing", parameter.Ref)
	}

	return resolved
}

func (d openAPIDocument) schema(t *testing.T, schema openAPISchema) openAPISchema {
	t.Helper()

	if schema.Ref == "" {
		return schema
	}

	resolved, found := d.Components.Schemas[componentName(t, schema.Ref, "schemas")]
	if !found {
		t.Fatalf("schema reference %q resolves to nothing", schema.Ref)
	}

	return resolved
}

func (d openAPIDocument) header(t *testing.T, header openAPIHeader) openAPIHeader {
	t.Helper()

	if header.Ref == "" {
		return header
	}

	resolved, found := d.Components.Headers[componentName(t, header.Ref, "headers")]
	if !found {
		t.Fatalf("header reference %q resolves to nothing", header.Ref)
	}

	return resolved
}

// headerParameter returns an operation's resolved header parameter by name.
func (d openAPIDocument) headerParameter(
	t *testing.T, operation openAPIOperation, name string,
) (openAPIParameter, bool) {
	t.Helper()

	for _, parameter := range operation.Parameters {
		resolved := d.parameter(t, parameter)
		if resolved.In == "header" && strings.EqualFold(resolved.Name, name) {
			return resolved, true
		}
	}

	return openAPIParameter{}, false
}

// securityAlternatives describes an operation's security declaration as one
// entry per alternative, each the sorted scheme names that alternative needs.
func securityAlternatives(t *testing.T, key string, operation openAPIOperation) []string {
	t.Helper()

	if operation.Security == nil {
		t.Fatalf("%s declares no security, so it inherits whatever a reader assumes", key)
	}

	alternatives := make([]string, 0, len(*operation.Security))

	for _, requirement := range *operation.Security {
		schemes := make([]string, 0, len(requirement))

		for scheme, scopes := range requirement {
			if len(scopes) != 0 {
				t.Errorf("%s lists scopes %v for %s, which a bearer or cookie scheme cannot carry", key, scopes, scheme)
			}

			schemes = append(schemes, scheme)
		}

		slices.Sort(schemes)
		alternatives = append(alternatives, strings.Join(schemes, "+"))
	}

	return alternatives
}

// prose collapses a description's whitespace, so a statement is found however
// the source wraps it.
func prose(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

func documentedRoutes(routes []Route) []string {
	keys := make([]string, 0, len(routes))

	for _, route := range routes {
		if route.Documented {
			keys = append(keys, fmt.Sprintf("%s %s", route.Method, route.Path()))
		}
	}

	slices.Sort(keys)

	return keys
}

func TestAPISchemaIsOpenAPIDocument(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	if document.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q, want 3.1.0", document.OpenAPI)
	}

	if document.Info.Title != "AbandonAuth" || document.Info.Version != "0.0.1" {
		t.Errorf("info = %q %q, want AbandonAuth 0.0.1", document.Info.Title, document.Info.Version)
	}

	if len(document.Paths) == 0 {
		t.Error("the schema documents no paths")
	}

	if len(document.Components.SecuritySchemes) == 0 || len(document.Components.Schemas) == 0 ||
		len(document.Components.Responses) == 0 {
		t.Error("the schema's components are missing")
	}

	tags := make([]string, 0, len(document.Tags))
	for _, tag := range document.Tags {
		tags = append(tags, tag.Name)
	}

	want := []string{"Users", "Authentication", "Developer Applications", "Provider Callbacks", "Development Sign-In"}
	if !slices.Equal(tags, want) {
		t.Errorf("tags = %v, want %v", tags, want)
	}
}

// A reader combines a published address with the origin the document came from,
// so every address has to be the whole one this service answers at, and nothing
// in the document may claim that something else adds or removes part of it.
func TestAPISchemaNamesWholeAddressesAndNoServer(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	if len(document.Servers) != 0 {
		t.Error("the schema declares a server, so it claims something else supplies part of an address")
	}

	if _, present := canonicalOpenAPIValue(t)["servers"]; present {
		t.Error("the schema carries a servers member")
	}

	for path := range document.Paths {
		if !strings.HasPrefix(path, APIRoot+"/") {
			t.Errorf("%q is not an address of this API", path)
		}
	}
}

// The schema and the route table are written separately, so nothing but this
// comparison keeps the document describing what the running build serves. The
// one permitted difference is the labelled development operations, which a
// deployment documents and does not declare.
func TestAPISchemaDocumentsDeclaredRoutes(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	operations := document.operations()

	seen := make(map[string]bool)

	for path, methods := range document.Paths {
		for method := range methods {
			key := fmt.Sprintf("%s %s", strings.ToUpper(method), path)
			if seen[key] {
				t.Errorf("%s is documented twice", key)
			}

			seen[key] = true
		}
	}

	declared := documentedRoutes(Routes())

	for _, key := range declared {
		if _, documented := operations[key]; !documented {
			t.Errorf("%s is a documented route the schema does not describe", key)
		}
	}

	for key, operation := range operations {
		if slices.Contains(declared, key) {
			continue
		}

		if !slices.Contains(developmentOperations, key) {
			t.Errorf("the schema describes %s, which this build does not declare", key)

			continue
		}

		if DevtoolsBuild {
			t.Errorf("%s is development-only, and this development build does not declare it", key)
		}

		if operation.Build != developmentBuildLabel {
			t.Errorf("%s is documented without a route and is not labelled development-only", key)
		}
	}
}

func TestAPISchemaMarksDevelopmentOperations(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	for key, operation := range document.operations() {
		development := slices.Contains(developmentOperations, key)

		if !development {
			if operation.Build != "" {
				t.Errorf("%s carries x-abandonauth-build %q, but every build serves it", key, operation.Build)
			}

			continue
		}

		if operation.Build != developmentBuildLabel {
			t.Errorf("%s: x-abandonauth-build = %q, want %q", key, operation.Build, developmentBuildLabel)
		}

		if !slices.Equal(operation.Tags, []string{"Development Sign-In"}) {
			t.Errorf("%s: tags = %v, want the development sign-in tag alone", key, operation.Tags)
		}

		for _, condition := range []string{
			"Development-only.",
			"development build compiled with the `devtools` tag",
			"debug mode on",
			"loopback-only",
			"A deployment build contains neither the route nor the handler",
			"answers 404",
		} {
			if !strings.Contains(prose(operation.Description), condition) {
				t.Errorf("%s does not say %q", key, condition)
			}
		}

		unavailable, documented := operation.Responses["404"]
		if !documented {
			t.Errorf("%s does not document the 404 it answers when unavailable", key)

			continue
		}

		if unavailable.Ref != "#/components/responses/DevelopmentOperationUnavailable" {
			t.Errorf("%s documents 404 as %q", key, unavailable.Ref)
		}
	}
}

// A document that names an endpoint but says nothing about it is not
// documentation, and a reader would have to try the endpoint to find out.
func TestEveryOperationIsDescribed(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	declaredTags := make(map[string]bool)
	for _, tag := range document.Tags {
		declaredTags[tag.Name] = true
	}

	for key, operation := range document.operations() {
		if strings.TrimSpace(operation.Summary) == "" {
			t.Errorf("%s has no summary", key)
		}

		if strings.TrimSpace(operation.Description) == "" {
			t.Errorf("%s has no description", key)
		}

		if len(operation.Tags) == 0 {
			t.Errorf("%s has no tag", key)
		}

		for _, tag := range operation.Tags {
			if !declaredTags[tag] {
				t.Errorf("%s carries the undeclared tag %q", key, tag)
			}
		}

		if operation.Security == nil {
			t.Errorf("%s declares no security; a public operation says so with security: []", key)
		}

		if len(operation.Responses) == 0 {
			t.Errorf("%s documents no responses", key)
		}

		for status, response := range operation.Responses {
			if strings.TrimSpace(document.response(t, response).Description) == "" {
				t.Errorf("%s: response %s has no description", key, status)
			}
		}
	}
}

// Each operation's security is the exact set of credential classes its handler
// accepts. A user token where an application token belongs, or the reverse, would
// send a caller's credential somewhere it is refused or overexposed.
func TestAPISchemaAuthenticationBoundaries(t *testing.T) {
	t.Parallel()

	const (
		user        = "UserAccessToken"
		application = "DeveloperApplicationAccessToken"
		browser     = "BrowserSession"
	)

	public := []string{}
	userOrBrowser := []string{user, browser}

	want := map[string][]string{
		"GET /api/me":                                                     userOrBrowser,
		"GET /api/user/applications":                                      userOrBrowser,
		"POST /api/login":                                                 {application},
		"POST /api/burn-token":                                            public,
		"POST /api/developer_application":                                 userOrBrowser,
		"POST /api/developer_application/login":                           public,
		"GET /api/developer_application/me":                               {application},
		"GET /api/developer_application/{application_id}":                 userOrBrowser,
		"DELETE /api/developer_application/{application_id}":              userOrBrowser,
		"PATCH /api/developer_application/{application_id}/reset_token":   userOrBrowser,
		"PATCH /api/developer_application/{application_id}/callback_uris": userOrBrowser,
		"GET /api/ui/{provider}/authorize":                                public,
		"GET /api/ui/discord-callback":                                    public,
		"GET /api/ui/github-callback":                                     public,
		"GET /api/google":                                                 public,
		"GET /api/ui/steam-callback":                                      public,
		"POST /api/ui/logout":                                             {browser},
		"POST /api/create_test_user":                                      public,
		"POST /api/login_test_user":                                       public,
	}

	document := canonicalOpenAPI(t)
	operations := document.operations()

	if len(operations) != len(want) {
		t.Errorf("the schema documents %d operations, and %d have a stated boundary", len(operations), len(want))
	}

	for key, alternatives := range want {
		operation, found := operations[key]
		if !found {
			t.Errorf("the schema documents no %s", key)

			continue
		}

		if got := securityAlternatives(t, key, operation); !slices.Equal(got, alternatives) {
			t.Errorf("%s: security = %v, want %v", key, got, alternatives)
		}
	}

	for _, key := range []string{
		"GET /api/user/applications",
		"POST /api/developer_application",
		"GET /api/developer_application/{application_id}",
		"DELETE /api/developer_application/{application_id}",
		"PATCH /api/developer_application/{application_id}/reset_token",
		"PATCH /api/developer_application/{application_id}/callback_uris",
	} {
		description := prose(operations[key].Description)
		for _, statement := range []string{"AbandonAuth site itself", "`abandonauth` scope", "`BrowserSession`"} {
			if !strings.Contains(description, statement) {
				t.Errorf("%s does not state %q", key, statement)
			}
		}
	}

	me := prose(operations["GET /api/me"].Description)
	for _, statement := range []string{"`identify` scope", "still registered", "`BrowserSession`"} {
		if !strings.Contains(me, statement) {
			t.Errorf("GET /api/me does not state %q", statement)
		}
	}

	applicationOnly := prose(operations["GET /api/developer_application/me"].Description)
	if !strings.Contains(applicationOnly, "a user access token and a browser session are refused") {
		t.Error("GET /api/developer_application/me does not say a user token and a session are refused")
	}
}

func TestAPISchemaSecuritySchemes(t *testing.T) {
	t.Parallel()

	schemes := canonicalOpenAPI(t).Components.SecuritySchemes

	if len(schemes) != 3 {
		t.Errorf("the schema declares %d security schemes, want 3", len(schemes))
	}

	for name, class := range map[string]string{
		"UserAccessToken":                 "`user_access`",
		"DeveloperApplicationAccessToken": "`developer_application_access`",
	} {
		scheme := schemes[name]

		if scheme.Type != "http" || scheme.Scheme != "bearer" || scheme.BearerFormat != "JWT" {
			t.Errorf("%s = %s %s %s, want an http bearer JWT", name, scheme.Type, scheme.Scheme, scheme.BearerFormat)
		}

		for _, statement := range []string{class, "fifteen minutes", "never accepted"} {
			if !strings.Contains(prose(scheme.Description), statement) {
				t.Errorf("%s does not state %q", name, statement)
			}
		}
	}

	userToken := prose(schemes["UserAccessToken"].Description)
	for _, statement := range []string{
		"never accepted where a `DeveloperApplicationAccessToken` is required",
		"`identify`",
		"`abandonauth`",
		"withdrawn",
	} {
		if !strings.Contains(userToken, statement) {
			t.Errorf("UserAccessToken does not state %q", statement)
		}
	}

	applicationToken := prose(schemes["DeveloperApplicationAccessToken"].Description)
	for _, statement := range []string{
		"never accepted where a `UserAccessToken` is required",
		"its subject is the application",
		"its audience is the AbandonAuth site",
		"exactly the `abandonauth` and `identify` scopes",
		"credential version",
	} {
		if !strings.Contains(applicationToken, statement) {
			t.Errorf("DeveloperApplicationAccessToken does not state %q", statement)
		}
	}

	session := schemes["BrowserSession"]
	if session.Type != "apiKey" || session.In != "cookie" || session.Name != "__Host-abandonauth_session" {
		t.Errorf("BrowserSession = %s in %s named %q, want the secure session cookie", session.Type, session.In, session.Name)
	}
}

// The session cookie's protections are what make a cookie-authenticated change
// safe, and a reader who sends that cookie has to know every one of them.
func TestAPISchemaBrowserSessionContract(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	session := strings.Join(strings.Fields(document.Components.SecuritySchemes["BrowserSession"].Description), " ")

	for _, statement := range []string{
		"stores only its digest",
		"Expiry is absolute",
		"Logout deletes the session on the server",
		"`HttpOnly`",
		"`Secure`",
		"`SameSite=Lax`",
		"`Path=/`",
		"no `Domain`",
		"readable `__Host-abandonauth_csrf` cookie, with the same attributes except `HttpOnly`",
		"loopback address without TLS",
		"`abandonauth_session` and `abandonauth_csrf`, without the `__Host-` prefix or `Secure`",
		"requires the exact site `Origin`",
		"a non-empty `X-CSRF-Token`",
		"equality between that header and the readable CSRF cookie",
		"a match to the CSRF digest bound to the server-side session",
		"needs neither `Origin` nor `X-CSRF-Token`",
	} {
		if !strings.Contains(session, statement) {
			t.Errorf("BrowserSession does not state %q", statement)
		}
	}

	for key, operation := range document.operations() {
		alternatives := securityAlternatives(t, key, operation)
		origin, hasOrigin := document.headerParameter(t, operation, "Origin")
		csrf, hasCSRF := document.headerParameter(t, operation, "X-CSRF-Token")
		method, _, _ := strings.Cut(key, " ")
		description := strings.Join(strings.Fields(operation.Description), " ")

		switch {
		case slices.Equal(alternatives, []string{"BrowserSession"}):
			if !hasOrigin || !origin.Required || !hasCSRF || !csrf.Required {
				t.Errorf("%s accepts only a session, so Origin and X-CSRF-Token must both be required", key)
			}

			if !strings.Contains(description, "exact site `Origin`") ||
				!strings.Contains(description, "bound to the server-side session") {
				t.Errorf("%s does not describe its Origin and CSRF checks", key)
			}
		case slices.Contains(alternatives, "BrowserSession") && changesState(method):
			if !hasOrigin || !hasCSRF {
				t.Errorf("%s accepts a session for a change and documents no Origin or X-CSRF-Token", key)

				continue
			}

			if origin.Required || csrf.Required {
				t.Errorf("%s accepts a token too, so Origin and X-CSRF-Token cannot be unconditionally required", key)
			}

			for _, parameter := range []openAPIParameter{origin, csrf} {
				if !strings.Contains(parameter.Description, "`BrowserSession`") {
					t.Errorf("%s: %s does not say it applies to a browser session", key, parameter.Name)
				}
			}

			for _, statement := range []string{
				"exact site `Origin`",
				"`X-CSRF-Token` equal to the readable CSRF cookie and bound to the server-side session",
				"needs neither header",
			} {
				if !strings.Contains(description, statement) {
					t.Errorf("%s does not state %q", key, statement)
				}
			}
		default:
			if (hasOrigin && origin.Required) || (hasCSRF && csrf.Required) {
				t.Errorf("%s requires Origin or X-CSRF-Token without being a session-only change", key)
			}
		}
	}
}

// Spending a code needs proof of the collecting application, and OpenAPI can
// express only the header half of that proof. The rest has to be in words.
func TestAPISchemaLoginContract(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	login := document.operation(t, "POST /api/login")

	if got := securityAlternatives(t, "POST /api/login", login); !slices.Equal(got, []string{"DeveloperApplicationAccessToken"}) {
		t.Errorf("security = %v, want exactly DeveloperApplicationAccessToken with no alternative", got)
	}

	exchange, found := document.headerParameter(t, login, ExchangeTokenHeader)
	if !found || !exchange.Required {
		t.Error("the exchange-token header is not a required parameter")
	}

	if login.RequestBody == nil {
		t.Fatal("POST /api/login documents no body for its credential alternative")
	}

	if login.RequestBody.Required {
		t.Error("the body is required, but a caller proving itself by header sends none")
	}

	media, found := login.RequestBody.Content["application/json"]
	if !found {
		t.Fatal("the body is not JSON")
	}

	credentials := document.schema(t, media.Schema)
	if !slices.Equal(credentials.Required, []string{"id", "refresh_token"}) {
		t.Errorf("the credential body requires %v, want both id and refresh_token", credentials.Required)
	}

	description := strings.Join(strings.Fields(login.Description), " ")
	for _, statement := range []string{
		"Application proof is mandatory.",
		"`DeveloperApplicationAccessToken` in the `Authorization` header",
		"when no `Authorization` header is sent, with its `DeveloperApplicationCredentials` in the body",
		"A present `Authorization` header takes precedence",
		"never falls back to the body credentials",
		"must carry both `id` and `refresh_token`",
		"one atomic delete",
		"spent at most once",
		"replayed code",
	} {
		if !strings.Contains(description, statement) {
			t.Errorf("POST /api/login does not state %q", statement)
		}
	}
}

// The protocol bindings of a provider sign-in are this service's own checks.
// The document must name every one, so a reader never assumes a weaker flow,
// and must not claim a check this service does not make.
func TestAPISchemaProviderSignInContract(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	stateBinding := []string{
		"opaque",
		"unpredictable",
		"single-use",
		"`S256`",
	}

	authorize := strings.Join(strings.Fields(document.operation(t, "GET /api/ui/{provider}/authorize").Description), " ")
	for _, statement := range append(slices.Clone(stateBinding),
		"expiring after five minutes",
		"bound to the initiating browser",
		"to the provider, the application and the exact registered callback",
		"must exactly match one of the URIs the application registered",
		"PKCE with the `S256` challenge method is used for every OAuth provider, Discord, GitHub and Google",
		"Steam signs in through OpenID 2.0, which has no PKCE",
		"`https://steamcommunity.com/openid/login`",
		"`openid.mode` `checkid_setup`",
		"identifier selection for both `openid.claimed_id` and `openid.identity`",
		"`openid.realm` the AbandonAuth site's origin followed by `/`",
		"`openid.return_to` that origin followed by `/api/ui/steam-callback`, with the opaque state appended",
		"No access token or session token is ever put in a redirect query string.",
	) {
		if !strings.Contains(authorize, statement) {
			t.Errorf("GET /api/ui/{provider}/authorize does not state %q", statement)
		}
	}

	// Steam's sign-in has no PKCE, so wording that claims it for every
	// provider describes a check this service does not make.
	for _, overstatement := range []string{"used for every provider", "every provider uses PKCE"} {
		if strings.Contains(authorize, overstatement) {
			t.Errorf("GET /api/ui/{provider}/authorize claims %q", overstatement)
		}
	}

	callbacks := map[string]string{
		"GET /api/ui/discord-callback": "`code`",
		"GET /api/ui/github-callback":  "`code`",
		"GET /api/google":              "`authentication`",
	}

	for key, responseKey := range callbacks {
		description := strings.Join(strings.Fields(document.operation(t, key).Description), " ")

		for _, statement := range append(slices.Clone(stateBinding),
			"expiring",
			"presented by the same browser that started the sign-in",
			"consumed by one atomic delete",
			"belongs to another browser or was started with another provider",
			"returned to the exact registered callback spelling",
			"appends only one parameter, the one-time code under the "+responseKey+" query key",
			"No access token or session token is ever put in a redirect query string.",
		) {
			if !strings.Contains(description, statement) {
				t.Errorf("%s does not state %q", key, statement)
			}
		}
	}

	google := strings.Join(strings.Fields(document.operation(t, "GET /api/google").Description), " ")
	for _, statement := range []string{
		"algorithm must be RS256 and nothing else",
		"signature must verify against Google's published keys",
		"issuer must be exactly `https://accounts.google.com`",
		"audience must contain this service's client identifier",
		"When the token names more than one audience, a non-empty `azp` equal to the client identifier is required.",
		"Any other non-empty `azp` must equal the client identifier.",
		"`exp` and `iat` claims are mandatory and checked within the bounded clock skew",
		"`nbf` is enforced whenever it is present.",
		"nonce is mandatory and must match the nonce issued for this sign-in",
		"A non-empty `at_hash` must match the provider access token returned with it.",
	} {
		if !strings.Contains(google, statement) {
			t.Errorf("GET /api/google does not state %q", statement)
		}
	}

	// Empty and null values decode as absent, and nbf is optional, so wording
	// that claims otherwise describes a check this service does not make.
	for _, overstatement := range []string{
		"`nbf` is required",
		"`nbf` is mandatory",
		"`nbf` claims are mandatory",
		"`azp` is required",
		"`azp` is mandatory",
		"`at_hash` is required",
		"`at_hash` is mandatory",
		"null `azp`",
		"null `at_hash`",
		"empty or null",
	} {
		if strings.Contains(google, overstatement) {
			t.Errorf("GET /api/google claims %q", overstatement)
		}
	}

	expectSteamSignInBindings(t, document)

	for key, operation := range document.operations() {
		description := strings.ToLower(operation.Description)
		for _, claim := range []string{"openapi enforces", "enforced by openapi", "this document enforces"} {
			if strings.Contains(description, claim) {
				t.Errorf("%s claims the document itself enforces a guarantee", key)
			}
		}
	}
}

// expectSteamSignInBindings requires the Steam callback to state what binds an
// assertion to one sign-in, and never to claim PKCE.
func expectSteamSignInBindings(t *testing.T, document openAPIDocument) {
	t.Helper()

	const key = "GET /api/ui/steam-callback"

	steam := prose(document.operation(t, key).Description)

	for _, statement := range []string{
		"OpenID 2.0, not OAuth: it uses no PKCE verifier and no authorization code",
		"signed over `op_endpoint`, `claimed_id`, `identity`, `return_to` and `response_nonce`",
		"an assertion Steam returned for one sign-in cannot finish another",
		"refused with the 403 below before the state is consumed, so it spends no sign-in and Steam is not contacted",
		"opaque, unpredictable, expiring, single-use",
		"presented by the same browser that started the sign-in",
		"consumed by one atomic delete",
		"`openid.mode` set to `check_authentication`",
		"only if Steam answers `is_valid:true`",
		"username is `steam:` followed by that Steam ID",
		"returned to the exact registered callback spelling",
		"appends only one parameter, the one-time code under the `code` query key",
		"No access token or session token is ever put in a redirect query string.",
	} {
		if !strings.Contains(steam, statement) {
			t.Errorf("%s does not state %q", key, statement)
		}
	}

	for _, overstatement := range []string{"`S256`", "PKCE verifier held", "is exchanged with the PKCE", "nonce issued"} {
		if strings.Contains(steam, overstatement) {
			t.Errorf("%s claims %q", key, overstatement)
		}
	}
}

// The guarantees beside each handler are what a caller relies on, so the
// document states each of them rather than leaving it to be discovered.
func TestAPISchemaStatesSecurityGuarantees(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	statements := map[string][]string{
		"POST /api/burn-token": {
			"same empty 200 whether the value was withdrawn, was already gone, or was never issued",
			"cannot be used to discover which credentials are outstanding",
		},
		"POST /api/developer_application/login": {
			"refused with the same 401",
		},
		"GET /api/developer_application/{application_id}": {
			"answered 404, exactly as one that does not exist",
		},
		"DELETE /api/developer_application/{application_id}": {
			"answered 404, exactly as one that does not exist",
		},
		"PATCH /api/developer_application/{application_id}/reset_token": {
			"stops authenticating the application at once",
			"every developer application access token issued against it is refused",
			"answered 404, exactly as one that does not exist",
		},
		"PATCH /api/developer_application/{application_id}/callback_uris": {
			"replaced atomically, whole or not at all",
			"never a mixture",
			"answered 404, exactly as one that does not exist",
		},
		"POST /api/ui/logout": {
			"deleted on the server before the session and CSRF cookies are cleared",
		},
	}

	for key, wanted := range statements {
		description := strings.Join(strings.Fields(document.operation(t, key).Description), " ")
		for _, statement := range wanted {
			if !strings.Contains(description, statement) {
				t.Errorf("%s does not state %q", key, statement)
			}
		}
	}

	limited := []string{
		"POST /api/developer_application",
		"DELETE /api/developer_application/{application_id}",
		"PATCH /api/developer_application/{application_id}/reset_token",
		"PATCH /api/developer_application/{application_id}/callback_uris",
	}

	for key, operation := range document.operations() {
		_, documents429 := operation.Responses["429"]

		if !slices.Contains(limited, key) {
			if documents429 {
				t.Errorf("%s documents 429, but no budget applies to it", key)
			}

			continue
		}

		if !documents429 {
			t.Errorf("%s spends a budget and does not document 429", key)
		}

		description := strings.Join(strings.Fields(operation.Description), " ")
		if !strings.Contains(description, "one budget of 20 per minute") {
			t.Errorf("%s does not state the budget it spends", key)
		}
	}
}

// Every refusal has the body the service writes, a spent budget says when to
// return, and a response the service writes without a body declares none.
func TestAPISchemaResponseConventions(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	emptySuccess := []string{"POST /api/burn-token", "POST /api/ui/logout"}

	for key, operation := range document.operations() {
		for status, declared := range operation.Responses {
			response := document.response(t, declared)
			media, hasJSON := response.Content["application/json"]

			switch {
			case strings.HasPrefix(status, "3"):
				if len(response.Content) != 0 {
					t.Errorf("%s: redirect %s declares a body", key, status)
				}

				location, found := response.Headers["Location"]
				if !found || document.header(t, location).Schema.Type != "string" {
					t.Errorf("%s: redirect %s declares no Location", key, status)
				}
			case status == "200" && slices.Contains(emptySuccess, key):
				if len(response.Content) != 0 {
					t.Errorf("%s: its empty 200 declares a body", key)
				}
			case status == "200":
				if !hasJSON {
					t.Errorf("%s: 200 declares no JSON body", key)
				}
			case status == "422":
				if !hasJSON || media.Schema.Ref != "#/components/schemas/Invalidated" {
					t.Errorf("%s: 422 is not the Invalidated body", key)
				}
			default:
				if !hasJSON || media.Schema.Ref != "#/components/schemas/Failure" {
					t.Errorf("%s: %s is not the Failure body", key, status)
				}
			}

			if status == "429" {
				retry, found := response.Headers["Retry-After"]
				if !found || document.header(t, retry).Schema.Type != "integer" {
					t.Errorf("%s: 429 declares no Retry-After", key)
				}
			}
		}
	}

	invalidated := document.Components.Schemas["Invalidated"]
	if items := invalidated.Properties["detail"].Items; items == nil || items.Ref != "#/components/schemas/InputFailure" {
		t.Error("Invalidated does not list InputFailure entries")
	}

	if failure := document.Components.Schemas["Failure"]; !slices.Equal(failure.Required, []string{"detail"}) {
		t.Errorf("Failure requires %v, want detail", failure.Required)
	}
}

// Refusal text is for people, so the document says clients classify a refusal
// by status, `loc` and `type`, and states each refusal equivalence class a
// client could otherwise mistake for a difference worth probing.
func TestAPISchemaStatesRefusalContract(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	schemas := document.Components.Schemas
	responses := document.Components.Responses

	statements := map[string]struct {
		description string
		wanted      []string
	}{
		"the Failure schema": {schemas["Failure"].Description, []string{
			"human-readable detail",
			"never repeats a request value",
			"not a stable machine-readable code and may change",
			"classify a refusal by its HTTP status",
		}},
		"the InputFailure schema": {schemas["InputFailure"].Description, []string{
			"`loc` and `type` identify the refusal",
			"`msg` is human-readable, is not a stable machine-readable code and may change",
		}},
		"the Forbidden response": {responses["Forbidden"].Description, []string{
			"An expired access token is reported separately",
			"every other access token refusal, including a withdrawn token, a stale auth epoch and a " +
				"principal that no longer exists, receives the same response",
			"No response reveals whether an account or application exists",
		}},
		"the Unauthorized response": {responses["Unauthorized"].Description, []string{
			"An unknown principal and a wrong credential receive the same response",
			"an unknown, spent, expired and misdirected exchange code",
		}},
		"POST /api/login": {document.operation(t, "POST /api/login").Description, []string{
			"refused with the same 403 for an unknown application and a wrong refresh token",
		}},
		"PATCH /api/developer_application/{application_id}/callback_uris": {
			document.operation(t, "PATCH /api/developer_application/{application_id}/callback_uris").Description,
			[]string{"names only the zero-based index of the first refused URI", "never the URI or the rule it broke"},
		},
		"GET /api/ui/{provider}/authorize": {document.operation(t, "GET /api/ui/{provider}/authorize").Description, []string{
			"with the same response whether the application or the callback is unknown",
		}},
	}

	for _, key := range []string{
		"GET /api/ui/discord-callback", "GET /api/ui/github-callback", "GET /api/google", "GET /api/ui/steam-callback",
	} {
		statements[key] = struct {
			description string
			wanted      []string
		}{document.operation(t, key).Description, []string{
			"Every failure after the state is consumed is refused with that same 403 response",
			"a provider that does not authenticate the user",
			"a provider identity that is incomplete or cannot be stored",
			"a stored callback that no longer passes the callback URI policy",
			"carries no redirect and issues no session or one-time code",
		}}
	}

	for where, stated := range statements {
		description := prose(stated.description)
		for _, statement := range stated.wanted {
			if !strings.Contains(description, statement) {
				t.Errorf("%s does not state %q", where, statement)
			}
		}
	}
}

// A token is a set of verified claims, not a party to the exchange. Wording
// that personifies one blurs which principal is authenticated.
func TestAPISchemaDescribesTokensWithoutPersonification(t *testing.T) {
	t.Parallel()

	source := strings.ToLower(prose(string(embeddedOpenAPISchema)))

	for _, metaphor := range []string{"speaks for", "speak for", "dressed as", "token says", "token said"} {
		if strings.Contains(source, metaphor) {
			t.Errorf("the schema describes a token as something that %q", metaphor)
		}
	}
}

// A reference to a component that does not exist leaves a reader with half a
// contract, so every one has to resolve within the document.
func TestAPISchemaReferencesResolve(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPIValue(t)
	references := 0

	var walk func(location string, value any)
	walk = func(location string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, member := range typed {
				if key == "$ref" {
					references++

					resolveLocalReference(t, document, location, member)

					continue
				}

				walk(location+"/"+key, member)
			}
		case []any:
			for index, element := range typed {
				walk(fmt.Sprintf("%s/%d", location, index), element)
			}
		}
	}

	walk("#", document)

	if references == 0 {
		t.Error("the schema holds no references, so this proves nothing")
	}
}

func resolveLocalReference(t *testing.T, document map[string]any, location string, reference any) {
	t.Helper()

	target, isString := reference.(string)
	if !isString || !strings.HasPrefix(target, "#/components/") {
		t.Errorf("%s refers to %v, which is not a local component", location, reference)

		return
	}

	var current any = document

	for _, segment := range strings.Split(strings.TrimPrefix(target, "#/"), "/") {
		members, isMapping := current.(map[string]any)
		if !isMapping {
			t.Errorf("%s refers to %s, which resolves to nothing", location, target)

			return
		}

		next, found := members[segment]
		if !found {
			t.Errorf("%s refers to %s, which resolves to nothing", location, target)

			return
		}

		current = next
	}
}

// credentialPatterns describe values that would be a credential if they
// appeared in a published document.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`\$2[aby]\$\d{2}\$`),
	regexp.MustCompile(`(?i)client_secret\s*[=:]\s*\S`),
	regexp.MustCompile(`(?i)\bset-cookie\b`),
}

// findForbiddenMembers lists every location of an example or default member.
func findForbiddenMembers(location string, value any) []string {
	var found []string

	switch typed := value.(type) {
	case map[string]any:
		for key, member := range typed {
			if slices.Contains(forbiddenOpenAPIMembers, key) {
				found = append(found, location+"/"+key)
			}

			found = append(found, findForbiddenMembers(location+"/"+key, member)...)
		}
	case []any:
		for index, element := range typed {
			found = append(found, findForbiddenMembers(fmt.Sprintf("%s/%d", location, index), element)...)
		}
	}

	return found
}

// The schema is committed and served to every browser that opens the page, so a
// credential pasted into it would be published. Nothing in it may look like one,
// and it carries no example or default value a credential could hide in.
func TestAPISchemaHoldsNoCredentials(t *testing.T) {
	t.Parallel()

	samples := []string{
		"Bearer " + strings.Repeat("a1", 6),
		"eyJ" + strings.Repeat("b", 10) + "." + strings.Repeat("c", 10),
		"$2b$" + "12$",
		"client_secret" + "=x",
		"Set-" + "Cookie",
	}

	for index, pattern := range credentialPatterns {
		if !pattern.MatchString(samples[index]) {
			t.Fatalf("pattern %s matches nothing it is meant to, so this proves nothing", pattern)
		}
	}

	published, err := publishedOpenAPI()
	if err != nil {
		t.Fatalf("the embedded schema is not published: %v", err)
	}

	for name, document := range map[string][]byte{"openapi.yaml": published.YAML, "openapi.json": published.JSON} {
		for _, pattern := range credentialPatterns {
			if pattern.Match(document) {
				t.Errorf("%s matches forbidden pattern %s", name, pattern)
			}
		}
	}

	if found := findForbiddenMembers("#", canonicalOpenAPIValue(t)); len(found) != 0 {
		t.Errorf("the schema carries example or default members at %v", found)
	}

	if found := findForbiddenMembers("#", decodeJSONValue(t, published.JSON)); len(found) != 0 {
		t.Errorf("the JSON representation carries example or default members at %v", found)
	}
}

// Undocumented routes are deliberate: browser redirects and the documentation
// UI are not part of the published API. Listing them here keeps that decision
// visible and stops a route from becoming undocumented by accident.
func TestUndocumentedRoutesAreExpected(t *testing.T) {
	t.Parallel()

	want := []string{
		"GET /api",
		"GET /api/",
		"GET /api/ui",
		"GET /api/ui/",
		"GET /api/docs",
		"GET /api/docs/",
		"GET /api/docs/oauth2-redirect",
		"GET /api/openapi.json",
		"GET /api/openapi.yaml",
	}

	slices.Sort(want)

	got := make([]string, 0, len(Routes()))

	for _, route := range Routes() {
		if route.Documented {
			continue
		}

		got = append(got, fmt.Sprintf("%s %s", route.Method, route.Path()))
	}

	slices.Sort(got)

	if !slices.Equal(got, want) {
		t.Errorf("undocumented routes\n got: %v\nwant: %v", got, want)
	}
}

// Routes must be unique and use patterns the router can register.
func TestRoutesAreUniqueAndAnchored(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, len(Routes()))

	for _, route := range Routes() {
		key := fmt.Sprintf("%s %s", route.Method, route.Pattern)
		if seen[key] {
			t.Errorf("duplicate route %s", key)
		}

		seen[key] = true

		if route.Method != strings.ToUpper(route.Method) || route.Method == "" {
			t.Errorf("route %s has a non-canonical method", key)
		}

		if !strings.HasPrefix(route.Pattern, "/") {
			t.Errorf("route %s pattern is not absolute", key)
		}

		if strings.Contains(route.Pattern, "//") {
			t.Errorf("route %s pattern has an empty segment", key)
		}
	}
}

// The route root belongs to this API. A route written without it would be an
// address no caller could reach through a deployment, and one written with a
// second root would be a second contract.
func TestEveryRouteIsUnderAPIsRouteRoot(t *testing.T) {
	t.Parallel()

	for _, route := range Routes() {
		if route.Path() != APIRoot && !strings.HasPrefix(route.Path(), APIRoot+"/") {
			t.Errorf("route %s %s is not under %s", route.Method, route.Path(), APIRoot)
		}
	}
}
