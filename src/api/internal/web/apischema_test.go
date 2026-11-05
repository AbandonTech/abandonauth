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
	Served      *bool                      `yaml:"x-abandonauth-served"`
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
	Ref                  string                   `yaml:"$ref"`
	Type                 string                   `yaml:"type"`
	Format               string                   `yaml:"format"`
	Description          string                   `yaml:"description"`
	Required             []string                 `yaml:"required"`
	Properties           map[string]openAPISchema `yaml:"properties"`
	AdditionalProperties *bool                    `yaml:"additionalProperties"`
	Items                *openAPISchema           `yaml:"items"`
	AnyOf                []openAPISchema          `yaml:"anyOf"`
	Enum                 []any                    `yaml:"enum"`
	Pattern              string                   `yaml:"pattern"`
	Minimum              *int                     `yaml:"minimum"`
	Maximum              *int                     `yaml:"maximum"`
	MaxLength            *int                     `yaml:"maxLength"`
	MinItems             *int                     `yaml:"minItems"`
	MaxItems             *int                     `yaml:"maxItems"`
	UniqueItems          bool                     `yaml:"uniqueItems"`
}

// unserved reports whether the contract describes an operation before any build
// declares its route. Only the exact value false says so.
func (o openAPIOperation) unserved() bool {
	return o.Served != nil && !*o.Served
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

	want := []string{
		"Users", "Authentication", "Developer Applications", "Provider Callbacks",
		"OpenID Connect", "Authorization Page", "Development Sign-In",
	}
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
// permitted differences are the labelled development operations, which a
// deployment documents and does not declare, and an operation whose contract is
// written before its route exists, which says so with x-abandonauth-served
// exactly false. That value on a declared route is a contradiction.
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
		if operation.Served != nil && *operation.Served {
			t.Errorf("%s carries x-abandonauth-served true; a served operation carries no marker", key)
		}

		if slices.Contains(declared, key) {
			if operation.Served != nil {
				t.Errorf("%s is declared and still carries x-abandonauth-served", key)
			}

			continue
		}

		if operation.unserved() {
			if operation.Build != "" || slices.Contains(developmentOperations, key) {
				t.Errorf("%s is marked unserved and development-only at once", key)
			}

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
		oidcAccess  = "OIDCAccessToken"
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
		"GET /api/.well-known/openid-configuration":                       public,
		"GET /api/oidc/jwks":                                              public,
		"GET /api/oauth/access-jwks":                                      public,
		"GET /api/oauth/authorize":                                        public,
		"GET /api/oauth/authorization/{request}":                          public,
		"POST /api/oauth/authorization/{request}/{provider}":              public,
		"GET /api/oauth/consent/{consent}":                                public,
		"POST /api/oauth/consent/{consent}/allow":                         public,
		"POST /api/oauth/consent/{consent}/cancel":                        public,
		"POST /api/oauth/token":                                           public,
		"GET /api/oauth/userinfo":                                         {oidcAccess},
		"POST /api/oauth/revoke":                                          public,
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

	if len(schemes) != 4 {
		t.Errorf("the schema declares %d security schemes, want 4", len(schemes))
	}

	for name, class := range map[string]string{
		"UserAccessToken":                 "`user_access`",
		"DeveloperApplicationAccessToken": "`developer_application_access`",
		"OIDCAccessToken":                 "RFC 9068 access token",
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

	for _, name := range []string{"UserAccessToken", "DeveloperApplicationAccessToken"} {
		if !strings.Contains(prose(schemes[name].Description), "Nor is an `OIDCAccessToken`.") {
			t.Errorf("%s does not say an OIDC access token is refused in its place", name)
		}
	}

	oidcToken := prose(schemes["OIDCAccessToken"].Description)
	for _, statement := range []string{
		"`typ` `at+jwt`, `alg` `RS256`",
		"published only at `GET /api/oauth/access-jwks`",
		"its subject the AbandonAuth user's canonical UUID",
		"its audience the client identifier as one string",
		"never a username or a `user_id` claim",
		"exactly fifteen minutes after it is issued",
		"refuses it at once after revocation",
		"accepts a correctly signed token until it expires",
		"Validators allow no clock tolerance",
		"never accepted where a `UserAccessToken` or a `DeveloperApplicationAccessToken` is required",
	} {
		if !strings.Contains(oidcToken, statement) {
			t.Errorf("OIDCAccessToken does not state %q", statement)
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
		case slices.Contains(authorizationPageSubmissions, key):
			if !hasOrigin || !origin.Required || hasCSRF {
				t.Errorf("%s must require the exact site Origin and no CSRF token", key)
			}

			binding, bound := document.cookieParameter(t, operation, nativeBindingCookie)
			if !bound || !binding.Required {
				t.Errorf("%s does not require the native binding cookie", key)
			}

			for _, statement := range []string{
				"exact site `Origin`",
				"`NativeAuthorizationBinding` cookie",
				"consumed atomically",
				"exactly one succeeds",
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

// authorizationPageSubmissions spend a public client's pending authorization.
// The page submits them as forms, so the exact Origin and the binding cookie
// stand where a session-authenticated change would need a CSRF token.
var authorizationPageSubmissions = []string{
	"POST /api/oauth/authorization/{request}/{provider}",
	"POST /api/oauth/consent/{consent}/allow",
	"POST /api/oauth/consent/{consent}/cancel",
}

// nativeBindingCookie is the published name of the cookie binding a public
// client's authorization to the browser that began it.
const nativeBindingCookie = "__Host-abandonauth_native_oauth"

// cookieParameter returns an operation's resolved cookie parameter by name.
func (d openAPIDocument) cookieParameter(
	t *testing.T, operation openAPIOperation, name string,
) (openAPIParameter, bool) {
	t.Helper()

	for _, parameter := range operation.Parameters {
		resolved := d.parameter(t, parameter)
		if resolved.In == "cookie" && resolved.Name == name {
			return resolved, true
		}
	}

	return openAPIParameter{}, false
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
	emptySuccess := []string{"POST /api/burn-token", "POST /api/ui/logout", "POST /api/oauth/revoke"}

	for key, operation := range document.operations() {
		for status, declared := range operation.Responses {
			response := document.response(t, declared)
			media, hasJSON := response.Content["application/json"]

			if slices.Contains(oauthOperations, key) && !strings.HasPrefix(status, "2") &&
				!strings.HasPrefix(status, "3") {
				expectOAuthRefusal(t, document, key, status, response)

				continue
			}

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

// oauthOperations answer a refusal with an OAuth error body rather than this
// service's detail or input-failure bodies.
var oauthOperations = []string{
	"GET /api/oauth/authorize",
	"POST /api/oauth/token",
	"GET /api/oauth/userinfo",
	"POST /api/oauth/revoke",
}

// expectOAuthRefusal requires an OAuth refusal to be exactly one `error` member
// drawn from fixed codes, never a description, and never cacheable.
func expectOAuthRefusal(t *testing.T, document openAPIDocument, key, status string, response openAPIResponse) {
	t.Helper()

	if status == "422" {
		t.Errorf("%s documents the 422 input-failure body, which an OAuth endpoint never sends", key)
	}

	media, hasJSON := response.Content["application/json"]
	if !hasJSON || len(response.Content) != 1 {
		t.Errorf("%s: %s is not a JSON OAuth error", key, status)

		return
	}

	if !strings.HasPrefix(media.Schema.Ref, "#/components/schemas/OAuthError") {
		t.Errorf("%s: %s is %q, not an OAuth error body", key, status, media.Schema.Ref)

		return
	}

	body := document.schema(t, media.Schema)
	if body.AdditionalProperties == nil || *body.AdditionalProperties ||
		!slices.Equal(body.Required, []string{"error"}) || len(body.Properties) != 1 {
		t.Errorf("%s: %s is not exactly one error member", key, status)
	}

	if codes := body.Properties["error"].Enum; len(codes) == 0 {
		t.Errorf("%s: %s names no fixed error code", key, status)
	}

	for header, value := range map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache"} {
		declared, found := response.Headers[header]
		if !found || !slices.Equal(document.header(t, declared).Schema.Enum, []any{value}) {
			t.Errorf("%s: %s does not carry %s: %s", key, status, header, value)
		}
	}
}

// Every OAuth refusal names one fixed code per status, and nothing the caller
// sent: no description, no rejected value.
func TestAPISchemaOAuthErrorCodes(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	want := map[string]map[string][]any{
		"GET /api/oauth/authorize": {
			"400": {"invalid_request"},
			"500": {"server_error"},
			"503": {"temporarily_unavailable"},
		},
		"POST /api/oauth/token": {
			"400": {"invalid_request", "unsupported_grant_type", "invalid_client", "invalid_grant", "invalid_scope"},
			"500": {"server_error"},
			"503": {"temporarily_unavailable"},
		},
		"GET /api/oauth/userinfo": {
			"401": {"invalid_token"},
			"403": {"insufficient_scope"},
			"500": {"server_error"},
			"503": {"temporarily_unavailable"},
		},
		"POST /api/oauth/revoke": {
			"400": {"invalid_request"},
			"500": {"server_error"},
			"503": {"temporarily_unavailable"},
		},
	}

	for key, statuses := range want {
		operation := document.operation(t, key)

		for status, codes := range statuses {
			declared, found := operation.Responses[status]
			if !found {
				t.Errorf("%s does not document %s", key, status)

				continue
			}

			body := document.schema(t, document.response(t, declared).Content["application/json"].Schema)
			if got := body.Properties["error"].Enum; !slices.Equal(got, codes) {
				t.Errorf("%s %s: codes = %v, want %v", key, status, got, codes)
			}
		}

		for status := range operation.Responses {
			if _, stated := statuses[status]; !stated && !strings.HasPrefix(status, "2") && !strings.HasPrefix(status, "3") {
				t.Errorf("%s documents %s, which has no stated code", key, status)
			}
		}
	}

	for _, challenge := range []struct{ status, header, value string }{
		{"401", "InvalidTokenChallenge", `Bearer error="invalid_token"`},
		{"403", "InsufficientScopeChallenge", `Bearer error="insufficient_scope", scope="openid"`},
	} {
		response := document.response(t, document.operation(t, "GET /api/oauth/userinfo").Responses[challenge.status])

		declared, found := response.Headers["WWW-Authenticate"]
		if !found || declared.Ref != "#/components/headers/"+challenge.header {
			t.Errorf("UserInfo %s does not carry the fixed challenge", challenge.status)

			continue
		}

		if got := document.header(t, declared).Schema.Enum; !slices.Equal(got, []any{challenge.value}) {
			t.Errorf("UserInfo %s challenge = %v, want exactly %q", challenge.status, got, challenge.value)
		}
	}

	for name, schema := range document.Components.Schemas {
		if strings.HasPrefix(name, "OAuthError") {
			if _, described := schema.Properties["error_description"]; described {
				t.Errorf("%s carries error_description", name)
			}
		}
	}

	token := document.operation(t, "POST /api/oauth/token")
	if _, challenged := document.response(t, token.Responses["400"]).Headers["WWW-Authenticate"]; challenged {
		t.Error("the token endpoint's invalid_client carries WWW-Authenticate")
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
			"For a confidential application's sign-in, every failure after the state is consumed is refused " +
				"with that same 403 response",
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

// expectStatements fails for every statement a description does not make.
func expectStatements(t *testing.T, where, description string, statements ...string) {
	t.Helper()

	text := prose(description)

	for _, statement := range statements {
		if !strings.Contains(text, statement) {
			t.Errorf("%s does not state %q", where, statement)
		}
	}
}

// propertyNames lists a schema's members, sorted.
func propertyNames(schema openAPISchema) []string {
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}

	slices.Sort(names)

	return names
}

// expectExactObject requires a schema to be a closed object with exactly the
// named members, of which exactly the named ones are required.
func expectExactObject(t *testing.T, name string, schema openAPISchema, members, required []string) {
	t.Helper()

	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Errorf("%s does not refuse members it does not name", name)
	}

	sortedMembers := slices.Sorted(slices.Values(members))
	if got := propertyNames(schema); !slices.Equal(got, sortedMembers) {
		t.Errorf("%s members = %v, want %v", name, got, sortedMembers)
	}

	sortedRequired := slices.Sorted(slices.Values(required))
	if got := slices.Sorted(slices.Values(schema.Required)); !slices.Equal(got, sortedRequired) {
		t.Errorf("%s requires %v, want %v", name, got, sortedRequired)
	}
}

func intValue(value *int) int {
	if value == nil {
		return -1
	}

	return *value
}

// Each public-client operation documents exactly the statuses its handler
// answers, and the headers that keep its answers out of caches and frames.
func TestAPISchemaOpenIDConnectStatuses(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	want := map[string][]string{
		"GET /api/.well-known/openid-configuration":          {"200", "500"},
		"GET /api/oidc/jwks":                                 {"200", "500"},
		"GET /api/oauth/access-jwks":                         {"200", "500"},
		"GET /api/oauth/authorize":                           {"303", "400", "500", "503"},
		"GET /api/oauth/authorization/{request}":             {"200", "404", "500", "503"},
		"POST /api/oauth/authorization/{request}/{provider}": {"303", "403", "404", "500", "503"},
		"GET /api/oauth/consent/{consent}":                   {"200", "404", "500", "503"},
		"POST /api/oauth/consent/{consent}/allow":            {"303", "403", "404", "500", "503"},
		"POST /api/oauth/consent/{consent}/cancel":           {"303", "403", "404", "500", "503"},
		"POST /api/oauth/token":                              {"200", "400", "500", "503"},
		"GET /api/oauth/userinfo":                            {"200", "401", "403", "500", "503"},
		"POST /api/oauth/revoke":                             {"200", "400", "500", "503"},
	}

	for key, statuses := range want {
		operation := document.operation(t, key)

		got := make([]string, 0, len(operation.Responses))
		for status := range operation.Responses {
			got = append(got, status)
		}

		slices.Sort(got)

		if !slices.Equal(got, statuses) {
			t.Errorf("%s documents %v, want %v", key, got, statuses)
		}
	}

	expectHeader := func(key, status, header string, value any) {
		t.Helper()

		response := document.response(t, document.operation(t, key).Responses[status])

		declared, found := response.Headers[header]
		if !found || !slices.Equal(document.header(t, declared).Schema.Enum, []any{value}) {
			t.Errorf("%s %s does not carry %s: %v", key, status, header, value)
		}
	}

	for _, key := range []string{
		"GET /api/.well-known/openid-configuration", "GET /api/oidc/jwks", "GET /api/oauth/access-jwks",
	} {
		expectHeader(key, "200", "Cache-Control", "public, max-age=300")
	}

	for _, key := range []string{"POST /api/oauth/token", "GET /api/oauth/userinfo", "POST /api/oauth/revoke"} {
		expectHeader(key, "200", "Cache-Control", "no-store")
		expectHeader(key, "200", "Pragma", "no-cache")
	}

	pageHeaders := map[string]string{
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
	}

	for key, statuses := range map[string][]string{
		"GET /api/oauth/authorize":                           {"303"},
		"GET /api/oauth/authorization/{request}":             {"200", "404"},
		"POST /api/oauth/authorization/{request}/{provider}": {"303", "403", "404"},
		"GET /api/oauth/consent/{consent}":                   {"200", "404"},
		"POST /api/oauth/consent/{consent}/allow":            {"303", "403", "404"},
		"POST /api/oauth/consent/{consent}/cancel":           {"303", "403", "404"},
		"GET /api/ui/discord-callback":                       {"303"},
		"GET /api/ui/github-callback":                        {"303"},
		"GET /api/google":                                    {"303"},
		"GET /api/ui/steam-callback":                         {"303"},
	} {
		for _, status := range statuses {
			for header, value := range pageHeaders {
				expectHeader(key, status, header, value)
			}
		}

		if strings.Contains(key, "/api/oauth/") {
			expectStatements(t, key, document.operation(t, key).Description,
				"Every answer carries `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, "+
					"`X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.")
		}
	}

	for key, operation := range document.operations() {
		if !strings.Contains(key, "/api/oauth/") && !strings.Contains(key, "/api/.well-known/") &&
			!strings.Contains(key, "/api/oidc/") {
			continue
		}

		if slices.ContainsFunc(operation.Tags, func(tag string) bool {
			return tag == "OpenID Connect" || tag == "Authorization Page"
		}) {
			continue
		}

		t.Errorf("%s is a public-client operation outside its tags", key)
	}
}

// Discovery advertises exactly the implemented profile, and each key set
// publishes exactly the public members of one purpose's keys.
func TestAPISchemaOpenIDDiscoveryDocument(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	schemas := document.Components.Schemas

	metadata := schemas["OpenIDProviderMetadata"]
	members := []string{
		"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "revocation_endpoint",
		"jwks_uri", "access_token_jwks_uri", "response_types_supported", "response_modes_supported",
		"grant_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported",
		"scopes_supported", "token_endpoint_auth_methods_supported",
		"revocation_endpoint_auth_methods_supported", "code_challenge_methods_supported",
		"authorization_response_iss_parameter_supported",
	}
	expectExactObject(t, "OpenIDProviderMetadata", metadata, members, members)

	for member, values := range map[string][]any{
		"response_types_supported":                   {"code"},
		"response_modes_supported":                   {"query"},
		"grant_types_supported":                      {"authorization_code", "refresh_token"},
		"subject_types_supported":                    {"public"},
		"id_token_signing_alg_values_supported":      {"RS256"},
		"scopes_supported":                           {"openid", "profile", "offline_access"},
		"token_endpoint_auth_methods_supported":      {"none"},
		"revocation_endpoint_auth_methods_supported": {"none"},
		"code_challenge_methods_supported":           {"S256"},
	} {
		array := metadata.Properties[member]
		if array.Type != "array" || array.Items == nil || !slices.Equal(array.Items.Enum, values) ||
			intValue(array.MinItems) != len(values) || intValue(array.MaxItems) != len(values) {
			t.Errorf("%s does not advertise exactly %v", member, values)
		}
	}

	if issuer := metadata.Properties["authorization_response_iss_parameter_supported"]; !slices.Equal(issuer.Enum, []any{true}) {
		t.Error("discovery does not advertise RFC 9207 issuer identification as exactly true")
	}

	for member, path := range map[string]string{
		"authorization_endpoint": "`/oauth/authorize`",
		"token_endpoint":         "`/oauth/token`",
		"userinfo_endpoint":      "`/oauth/userinfo`",
		"revocation_endpoint":    "`/oauth/revoke`",
		"jwks_uri":               "`/oidc/jwks`",
		"access_token_jwks_uri":  "`/oauth/access-jwks`",
	} {
		expectStatements(t, member, metadata.Properties[member].Description, "The issuer followed by "+path)
	}

	expectStatements(t, "the issuer", metadata.Properties["issuer"].Description,
		"`ABANDON_AUTH_URL` followed by `/api`", "no trailing slash")

	expectStatements(t, "GET /api/.well-known/openid-configuration",
		document.operation(t, "GET /api/.well-known/openid-configuration").Description,
		"requires its `issuer` to equal the expected issuer byte for byte",
		"Standard `jwks_uri` names only the ID token key set.",
		"`access_token_jwks_uri` names only the access token key set",
		"never tries a key from one set against the other class",
		"publishes no dynamic registration, introspection, DPoP, device authorization or logout capability",
	)

	keySet := schemas["JSONWebKeySet"]
	expectExactObject(t, "JSONWebKeySet", keySet, []string{"keys"}, []string{"keys"})

	if keys := keySet.Properties["keys"]; intValue(keys.MinItems) != 1 || intValue(keys.MaxItems) != 1 ||
		keys.Items == nil || keys.Items.Ref != "#/components/schemas/RSAPublicJSONWebKey" {
		t.Error("a key set does not hold exactly one public RSA key")
	}

	key := schemas["RSAPublicJSONWebKey"]
	keyMembers := []string{"kid", "kty", "use", "alg", "n", "e"}
	expectExactObject(t, "RSAPublicJSONWebKey", key, keyMembers, keyMembers)

	for member, value := range map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256"} {
		if !slices.Equal(key.Properties[member].Enum, []any{value}) {
			t.Errorf("a published key's %s is not exactly %s", member, value)
		}
	}

	if key.Properties["kid"].Pattern != "^[A-Za-z0-9_-]{43}$" {
		t.Error("a key identifier is not a 43-character thumbprint")
	}

	for _, operation := range []string{"GET /api/oidc/jwks", "GET /api/oauth/access-jwks"} {
		expectStatements(t, operation, document.operation(t, operation).Description,
			"RFC 7638 thumbprint", "no private member", "no `kid` appears in both key sets", "exactly one key",
			"removes the replaced key from this set at once",
			"it refuses tokens the new key signs and can keep trusting the replaced key")
	}
}

// The authorization request's bounds are exact protocol constants, and every
// one is written where a client reads it.
func TestAPISchemaAuthorizationRequestBounds(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	authorize := document.operation(t, "GET /api/oauth/authorize")

	type bound struct {
		in       string
		required bool
		pattern  string
		enum     []any
		maximum  int
	}

	canonicalUUID := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	clientValue := "^[A-Za-z0-9_-]{43,128}$"

	want := map[string]bound{
		"response_type":                   {in: "query", required: true, enum: []any{"code"}, maximum: -1},
		"client_id":                       {in: "query", required: true, pattern: canonicalUUID, maximum: -1},
		"redirect_uri":                    {in: "query", required: true, maximum: -1},
		"scope":                           {in: "query", required: true, maximum: 64},
		"state":                           {in: "query", required: true, pattern: clientValue, maximum: -1},
		"nonce":                           {in: "query", required: true, pattern: clientValue, maximum: -1},
		"code_challenge":                  {in: "query", required: true, pattern: "^[A-Za-z0-9_-]{43}$", maximum: -1},
		"code_challenge_method":           {in: "query", required: true, enum: []any{"S256"}, maximum: -1},
		"response_mode":                   {in: "query", required: false, enum: []any{"query"}, maximum: -1},
		"__Host-abandonauth_native_oauth": {in: "cookie", required: false, maximum: -1},
	}

	got := make(map[string]bound)

	for _, declared := range authorize.Parameters {
		parameter := document.parameter(t, declared)
		got[parameter.Name] = bound{
			in:       parameter.In,
			required: parameter.Required,
			pattern:  parameter.Schema.Pattern,
			enum:     parameter.Schema.Enum,
			maximum:  intValue(parameter.Schema.MaxLength),
		}
	}

	if len(got) != len(want) {
		t.Errorf("the authorization request documents %d parameters, want %d", len(got), len(want))
	}

	for name, expected := range want {
		actual, found := got[name]
		if !found {
			t.Errorf("the authorization request does not document %s", name)

			continue
		}

		if actual.in != expected.in || actual.required != expected.required || actual.pattern != expected.pattern ||
			!slices.Equal(actual.enum, expected.enum) || actual.maximum != expected.maximum {
			t.Errorf("%s = %+v, want %+v", name, actual, expected)
		}
	}

	parameters := document.Components.Parameters
	expectStatements(t, "redirect_uri", parameters["AuthorizationRedirectURI"].Description,
		"exactly one numeric port from 1 through 65535", "at most 2,048 UTF-8 bytes", "byte for byte")
	expectStatements(t, "scope", parameters["AuthorizationScope"].Description,
		"single spaces", "none repeated", "at most 64 bytes", "`openid profile offline_access`")
	expectStatements(t, "code_challenge_method", parameters["AuthorizationCodeChallengeMethod"].Description,
		"`plain` and an omitted method are refused")

	for name, pattern := range map[string]string{
		"AuthorizationRequestHandle": "^[A-Za-z0-9_-]{43}$",
		"ConsentHandle":              "^[A-Za-z0-9_-]{43}$",
		"NativeAuthorizationBinding": "^[A-Za-z0-9_-]{43}$",
	} {
		if parameters[name].Schema.Pattern != pattern {
			t.Errorf("%s is not exactly 43 unpadded base64url characters", name)
		}
	}

	binding := parameters["NativeAuthorizationBinding"]
	if binding.In != "cookie" || binding.Name != nativeBindingCookie || !binding.Required {
		t.Errorf("the native binding cookie is %s %q", binding.In, binding.Name)
	}

	expectStatements(t, "the native binding cookie", binding.Description,
		"`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` and no `Domain`",
		"expires five minutes after it was last set",
		"separate from the cookie a confidential sign-in uses",
		"Only in a development build running in debug mode with the site on a loopback address without TLS",
		"`abandonauth_native_oauth`, without the `__Host-` prefix or `Secure`",
	)

	expectStatements(t, "GET /api/oauth/authorize", authorize.Description,
		"Each parameter must appear exactly once",
		"Unknown parameters are ignored.",
		"at most 8,192 bytes and 32 fields, unknown fields included",
		"every parameter name at most 64 bytes",
		"is refused whole, and no part of it is used",
		"validated before the redirect is used for anything",
		"the port is the only difference accepted",
		"direct 400 `invalid_request` and no `Location`",
		"`unsupported_response_type`",
		"`invalid_scope`",
		"ten thousand authorizations already in progress across the whole service with `temporarily_unavailable`",
		"`state` when exactly one syntactically valid state was supplied, and `iss`",
		"No refusal carries `error_description`.",
		"expires five minutes after creation and nothing that happens to it later extends it",
		"an empty 303 to the AbandonAuth site's origin followed by `/authorize#request=`",
		"The handle travels only in the fragment",
		"Nothing is approved silently.",
		"at most 64 public-protocol requests at once",
	)
}

// Provider selection and consent each read a sanitized model and nothing that
// would let the page or anything it loads complete the authorization itself.
func TestAPISchemaProviderSelectionAndConsentDisclosure(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	selection := document.Components.Schemas["ProviderSelection"]
	consent := document.Components.Schemas["PendingConsent"]

	selectionMembers := []string{"application_name", "expires_at", "providers"}
	expectExactObject(t, "ProviderSelection", selection, selectionMembers, selectionMembers)

	consentMembers := []string{"application_name", "scopes", "expires_at"}
	expectExactObject(t, "PendingConsent", consent, consentMembers, consentMembers)

	if scopes := consent.Properties["scopes"]; scopes.Items == nil ||
		!slices.Equal(scopes.Items.Enum, []any{"openid", "profile", "offline_access"}) {
		t.Error("the requested scopes are not the canonical three")
	}

	if providers := selection.Properties["providers"]; providers.Items == nil ||
		!slices.Equal(providers.Items.Enum, []any{"discord", "github", "google", "steam"}) ||
		intValue(providers.MinItems) != 4 || intValue(providers.MaxItems) != 4 {
		t.Error("the providers are not exactly the four, in order")
	}

	for name, model := range map[string]openAPISchema{"ProviderSelection": selection, "PendingConsent": consent} {
		if expiry := model.Properties["expires_at"]; expiry.Pattern !=
			"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$" {
			t.Errorf("%s's expiry is not whole-second UTC with a trailing Z", name)
		}
	}

	expectStatements(t, "PendingConsent", consent.Description,
		"the same at every application",
		"up to 90 days")

	expectStatements(t, "GET /api/oauth/authorization/{request}",
		document.operation(t, "GET /api/oauth/authorization/{request}").Description,
		"never carries the requested scopes, the redirect URI, the client's state, nonce or challenge, a user identifier or anything a provider returned",
		"Reading consumes nothing and extends nothing.",
		"same 404 `Authorization request unavailable`")

	expectStatements(t, "GET /api/oauth/consent/{consent}",
		document.operation(t, "GET /api/oauth/consent/{consent}").Description,
		"never carries a user identifier, a username, the redirect URI, the client's state, nonce or challenge, or anything a provider returned",
		"Reading consumes nothing and extends nothing.",
		"same 404 `Authorization request unavailable`")

	allow := document.operation(t, "POST /api/oauth/consent/{consent}/allow")
	expectStatements(t, "POST /api/oauth/consent/{consent}/allow", allow.Description,
		"the only operation that creates its authorization code",
		"before the handle is read",
		"does not say which won",
		"at most 120 seconds and never beyond the authorization's five-minute deadline",
		"Approval is never remembered.")

	cancel := document.operation(t, "POST /api/oauth/consent/{consent}/cancel")
	expectStatements(t, "POST /api/oauth/consent/{consent}/cancel", cancel.Description,
		"`error` `access_denied`",
		"no code, token, refresh family or relationship",
		"account the provider sign-in resolved or created stays")

	for key, operation := range map[string]openAPIOperation{
		"POST /api/oauth/consent/{consent}/allow": allow, "POST /api/oauth/consent/{consent}/cancel": cancel,
	} {
		if operation.Responses["303"].Ref != "#/components/responses/RedirectToPublicClient" {
			t.Errorf("%s does not document the 303 to the public client", key)
		}
	}

	responses := document.Components.Responses
	for name, detail := range map[string]string{
		"AuthorizationRequestUnavailable": "`Authorization request unavailable`",
		"AuthorizationRequestForbidden":   "`Authorization request forbidden`",
		"ServiceTemporarilyUnavailable":   "`Service temporarily unavailable`",
		"PublicClientHasNoCredential":     "`Public client has no credential`",
	} {
		expectStatements(t, name, responses[name].Description, detail)
	}
}

// The token and revocation contracts state every bound, binding and lifetime a
// public client depends on, and the claims of each token class exactly.
func TestAPISchemaTokenContract(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	schemas := document.Components.Schemas

	for _, key := range []string{"POST /api/oauth/token", "POST /api/oauth/revoke"} {
		operation := document.operation(t, key)
		if operation.RequestBody == nil || !operation.RequestBody.Required || len(operation.RequestBody.Content) != 1 {
			t.Errorf("%s does not require one form body", key)

			continue
		}

		if _, form := operation.RequestBody.Content["application/x-www-form-urlencoded"]; !form {
			t.Errorf("%s does not take application/x-www-form-urlencoded", key)
		}
	}

	grants := document.operation(t, "POST /api/oauth/token").RequestBody.Content["application/x-www-form-urlencoded"].Schema
	if len(grants.AnyOf) != 2 || grants.AnyOf[0].Ref != "#/components/schemas/AuthorizationCodeGrant" ||
		grants.AnyOf[1].Ref != "#/components/schemas/RefreshTokenGrant" {
		t.Error("the token request is not one of the two grants")
	}

	code := schemas["AuthorizationCodeGrant"]
	if want := []string{"grant_type", "client_id", "code", "redirect_uri", "code_verifier"}; !slices.Equal(code.Required, want) {
		t.Errorf("a code grant requires %v, want %v", code.Required, want)
	}

	if code.Properties["code_verifier"].Pattern != "^[A-Za-z0-9._~-]{43,128}$" ||
		code.Properties["code"].Pattern != "^[A-Za-z0-9_-]{43}$" {
		t.Error("a code grant does not bound its code and verifier")
	}

	refresh := schemas["RefreshTokenGrant"]
	if want := []string{"grant_type", "client_id", "refresh_token"}; !slices.Equal(refresh.Required, want) {
		t.Errorf("a refresh grant requires %v, want %v", refresh.Required, want)
	}

	if intValue(refresh.Properties["scope"].MaxLength) != 64 ||
		refresh.Properties["refresh_token"].Pattern != "^[A-Za-z0-9_-]{43}$" {
		t.Error("a refresh grant does not bound its scope and token")
	}

	revocation := schemas["TokenRevocation"]
	if !slices.Equal(revocation.Required, []string{"client_id", "token"}) ||
		intValue(revocation.Properties["token"].MaxLength) != 8192 {
		t.Error("a revocation does not require a bounded token and a client")
	}

	tokens := schemas["TokenSet"]
	expectExactObject(t, "TokenSet", tokens,
		[]string{"access_token", "token_type", "expires_in", "id_token", "scope", "refresh_token", "refresh_token_expires_in"},
		[]string{"access_token", "token_type", "expires_in", "id_token", "scope"})

	if !slices.Equal(tokens.Properties["token_type"].Enum, []any{"Bearer"}) ||
		!slices.Equal(tokens.Properties["expires_in"].Enum, []any{900}) {
		t.Error("a token set is not exactly a Bearer token for 900 seconds")
	}

	if lifetime := tokens.Properties["refresh_token_expires_in"]; intValue(lifetime.Minimum) != 1 ||
		intValue(lifetime.Maximum) != 2592000 {
		t.Error("a refresh token's remaining lifetime is not bounded by thirty days")
	}

	expectExactObject(t, "IDTokenClaims", schemas["IDTokenClaims"],
		[]string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "preferred_username"},
		[]string{"iss", "sub", "aud", "exp", "iat", "auth_time"})
	expectExactObject(t, "AccessTokenClaims", schemas["AccessTokenClaims"],
		[]string{"iss", "sub", "aud", "client_id", "scope", "jti", "auth_epoch", "iat", "nbf", "exp"},
		[]string{"iss", "sub", "aud", "client_id", "scope", "jti", "auth_epoch", "iat", "nbf", "exp"})
	expectExactObject(t, "UserInfo", schemas["UserInfo"], []string{"sub", "preferred_username"}, []string{"sub"})

	for _, name := range []string{"IDTokenClaims", "AccessTokenClaims", "UserInfo"} {
		if ref := schemas[name].Properties["sub"].Ref; ref != "#/components/schemas/UserSubject" {
			t.Errorf("%s sub is %q, want the user subject", name, ref)
		}
	}

	if subject := schemas["UserSubject"]; subject.Type != "string" || subject.Format != "uuid" || subject.Pattern !=
		"^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" {
		t.Error("a user subject is not exactly a canonical lower-case non-nil UUID")
	}

	expectStatements(t, "UserSubject", schemas["UserSubject"].Description,
		"The AbandonAuth user identifier", "canonical lower-case hyphenated UUID", "never the nil UUID",
		"the same for one user at every application and in every token class",
		"including the `sub` of a `UserAccessToken`", "correlate it across applications",
		"there is no `user_id` claim", "refuses an upper-case, braced, compact, nil or otherwise non-canonical spelling")
	expectStatements(t, "IDTokenClaims", schemas["IDTokenClaims"].Description,
		"`alg` `RS256`", "ID token key set", "exactly five minutes", "canonical non-nil UUID",
		"rejects `typ` `at+jwt`", "naming any member twice")
	expectStatements(t, "AccessTokenClaims", schemas["AccessTokenClaims"].Description,
		"`typ` `at+jwt`", "access token key set", "exactly 900 seconds later", "no clock tolerance",
		"`sub` to be a canonical lower-case non-nil UUID", "naming any member twice",
		"does not compare `auth_epoch` with the current authority")

	if strings.Contains(strings.ToLower(string(embeddedOpenAPISchema)), "pairwise") {
		t.Error("the contract still describes pairwise subjects")
	}

	expectStatements(t, "POST /api/oauth/token", document.operation(t, "POST /api/oauth/token").Description,
		"Client authentication is `none`",
		"an `Authorization` header, a `client_secret` member or any other attempt to authenticate the client is refused",
		"at most 16,384 bytes and 16 fields, unknown fields included",
		"every field name at most 64 bytes",
		"Parameters in the query are never read.",
		"one atomic delete",
		"a wrong verifier, client or redirect does not consume the code",
		"exactly one succeeds",
		"revokes its whole family",
		"serialize refreshes and store the replacement before discarding the token it presented",
		"A refresh never adds scope.",
		"30 days after it is issued",
		"90 days after the code was redeemed",
		"at most 10,000 tokens",
		"at most ten active families",
		"revokes the least recently created one",
		"accepts it until it expires fifteen minutes after issue",
		"`Cache-Control: no-store` and `Pragma: no-cache`",
		"400 `invalid_client`, without `WWW-Authenticate`",
	)

	expectStatements(t, "POST /api/oauth/revoke", document.operation(t, "POST /api/oauth/revoke").Description,
		"`token_type_hint` is accepted and completely ignored",
		"Both supported token classes are always checked.",
		"same empty 200",
		"at most 1,000 revoked access tokens",
		"is not recorded as revoked",
		"accepts it until it expires fifteen minutes after issue",
	)

	expectStatements(t, "GET /api/oauth/userinfo", document.operation(t, "GET /api/oauth/userinfo").Description,
		"`preferred_username` only when `profile` was granted",
		"No other claim is ever returned.",
		"the AbandonAuth user's canonical UUID, under `openid` alone",
		"`sub` is the same at every application the user signs in to",
		"canonical non-nil UUID `sub`",
		"that client's relationship with the user",
		"An ID token, a `UserAccessToken` and a `DeveloperApplicationAccessToken` are refused.",
		"Neither challenge quotes the token or a claim.",
	)
}

// An application's client type decides which credential and which callbacks it
// can ever have, so every application shape states it and none can change it.
func TestAPISchemaApplicationClientType(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)
	schemas := document.Components.Schemas

	if !slices.Equal(schemas["ClientType"].Enum, []any{"confidential", "public"}) {
		t.Errorf("client types = %v, want exactly confidential and public", schemas["ClientType"].Enum)
	}

	for _, name := range []string{
		"DeveloperApplication", "DeveloperApplicationWithCallbackURIs",
		"DeveloperApplicationWithCredential", "RegisteredDeveloperApplication",
	} {
		if !slices.Contains(schemas[name].Required, "client_type") {
			t.Errorf("%s does not always state client_type", name)
		}
	}

	if credential := schemas["DeveloperApplicationWithCredential"]; !slices.Equal(
		credential.Properties["client_type"].Enum, []any{"confidential"},
	) {
		t.Error("a credential is returned for an application that is not confidential")
	}

	if slices.Contains(schemas["RegisteredDeveloperApplication"].Required, "token") {
		t.Error("registration always returns a token, but a public client has none")
	}

	registration := schemas["DeveloperApplicationRegistration"]
	if slices.Contains(registration.Required, "client_type") ||
		!slices.Equal(registration.Properties["client_type"].Enum, []any{"confidential", "public"}) {
		t.Error("registration does not take an optional client_type of the two values")
	}

	create := document.operation(t, "POST /api/developer_application")
	if create.RequestBody.Content["application/json"].Schema.Ref != "#/components/schemas/DeveloperApplicationRegistration" ||
		document.response(t, create.Responses["200"]).Content["application/json"].Schema.Ref !=
			"#/components/schemas/RegisteredDeveloperApplication" {
		t.Error("registration does not use the client-type shapes")
	}

	expectStatements(t, "POST /api/developer_application", create.Description,
		"can never be changed", "an omitted `client_type` registers a `confidential` application",
		"receives no credential, and its answer carries no `token`")

	reset := document.operation(t, "PATCH /api/developer_application/{application_id}/reset_token")
	if reset.Responses["409"].Ref != "#/components/responses/PublicClientHasNoCredential" {
		t.Error("resetting a public client's credential documents no fixed 409")
	}

	expectStatements(t, "reset_token", reset.Description, "answered 409 and changes nothing")

	expectStatements(t, "callback_uris",
		document.operation(t, "PATCH /api/developer_application/{application_id}/callback_uris").Description,
		"Which URIs are accepted depends on the application's `client_type`.",
		"A public client's callback is a portless loopback template",
		"an IPv4 literal in `127.0.0.0/8` or the IPv6 literal `[::1]`, no port",
		"none of the query keys `code`, `state`, `error`, `error_description` or `iss` in any letter case or encoding",
		"A host name such as `localhost` is refused.")

	expectStatements(t, "GET /api/ui/{provider}/authorize", document.operation(t, "GET /api/ui/{provider}/authorize").Description,
		"A public client is refused with that same 403 before anything is stored")
	expectStatements(t, "POST /api/developer_application/login",
		document.operation(t, "POST /api/developer_application/login").Description,
		"A public client has no refresh token, and its identifier is refused with that same 401")
	expectStatements(t, "POST /api/login", document.operation(t, "POST /api/login").Description,
		"Only a confidential application spends a code here.")
}

// A provider callback continuing a public client's authorization hands the
// browser to consent, never with a session, a confidential code or the client's
// code, and a saturated worker leaves the callback retryable.
func TestAPISchemaProviderCallbacksContinuePublicAuthorization(t *testing.T) {
	t.Parallel()

	document := canonicalOpenAPI(t)

	for _, key := range []string{
		"GET /api/ui/discord-callback", "GET /api/ui/github-callback", "GET /api/google", "GET /api/ui/steam-callback",
	} {
		operation := document.operation(t, key)

		if operation.Responses["303"].Ref != "#/components/responses/PublicClientSignInContinued" {
			t.Errorf("%s does not document the 303 continuing a public client's sign-in", key)
		}

		if operation.Responses["503"].Ref != "#/components/responses/ServiceTemporarilyUnavailable" {
			t.Errorf("%s does not document the retryable 503", key)
		}

		expectStatements(t, key, operation.Description,
			"never ends in a browser session or in a one-time code for `POST /api/login`",
			"it creates no authorization code",
			"Every provider check above applies unchanged.",
			"A state that cannot be trusted is refused with the same 403.",
			"an empty 303 to the AbandonAuth site's origin followed by `/consent#request=`",
			"The handle travels only in the fragment",
			"the client receives nothing unless the person allows it",
			"`error` `access_denied`",
			"`error` `server_error`",
			"answered 503 before its parameters are read or its state is consumed",
			"the provider is not contacted",
		)
	}

	expectStatements(t, "PublicClientSignInContinued", document.Components.Responses["PublicClientSignInContinued"].Description,
		"`/consent#request=`", "No code or token is ever put in this address.")
	expectStatements(t, "RedirectToPublicClient", document.Components.Responses["RedirectToPublicClient"].Description,
		"rebuilt from its exact stored spelling with no existing byte rewritten", "No token is ever put in this address.")
}
