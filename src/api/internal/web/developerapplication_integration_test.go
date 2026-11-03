//go:build integration && !devtools

package web_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// Applications belong to the person who registered them, and one person's list
// says nothing about anyone else's.
func TestApplicationsAreListedForTheirOwnerOnly(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))
	first := service.RegisterApplication("the first")
	second := service.RegisterApplication("the second")

	if names := listedApplications(t, service); len(names) != 2 {
		t.Fatalf("the owner sees %v, want both applications", names)
	}

	service.SignIn(service.Providers.Someone(oauth.Discord, "somebody else"))

	if names := listedApplications(t, service); len(names) != 0 {
		t.Errorf("somebody else sees %v", names)
	}

	for _, application := range []servertest.Application{first, second} {
		service.GET("/developer_application/" + application.ID.String()).
			ExpectStatus(http.StatusNotFound).
			ExpectDetail("Not Found")
	}
}

// Reading an application somebody else owns is refused in the same words as
// reading one that does not exist.
func TestApplicationNobodyOwnsAndOneSomebodyElseOwnsAreSameAnswer(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))
	owned := service.RegisterApplication("someone else's application")

	service.SignIn(service.Providers.Someone(oauth.Discord, "a stranger"))

	stranger := service.GET("/developer_application/" + owned.ID.String()).
		ExpectStatus(http.StatusNotFound)
	absent := service.GET("/developer_application/" + uuid.New().String()).
		ExpectStatus(http.StatusNotFound)

	if string(stranger.Body) != string(absent.Body) {
		t.Errorf("an application somebody owns answers %s and one nobody owns answers %s", stranger.Body, absent.Body)
	}
}

// The set of callbacks an application may be returned to is exactly what was
// last submitted, and a URI submitted twice is registered once.
func TestReplacingCallbacksLeavesExactlyWhatWasSubmitted(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	service.PATCHJSON(
		"/developer_application/"+application.ID.String()+"/callback_uris",
		[]string{externalCallbackURI, externalCallbackURI, "https://relying.example.test/other"},
		service.Protected,
	).ExpectStatus(http.StatusOK)

	registered := registeredCallbacks(t, service, application)
	if len(registered) != 2 {
		t.Errorf("registered callbacks = %v, want the two distinct URIs", registered)
	}

	service.PATCHJSON(
		"/developer_application/"+application.ID.String()+"/callback_uris",
		[]string{externalCallbackURI},
		service.Protected,
	).ExpectStatus(http.StatusOK)

	if registered := registeredCallbacks(t, service, application); len(registered) != 1 {
		t.Errorf("registered callbacks = %v, want only the one that was submitted", registered)
	}
}

// callbackReplacement builds a request replacing an application's callbacks
// as the signed-in browser, for the tests that send several at once.
func callbackReplacement(
	t *testing.T, service *servertest.Service, application servertest.Application, uris []string,
) *http.Request {
	t.Helper()

	body, err := json.Marshal(uris)
	if err != nil {
		t.Fatalf("encoding the callbacks: %v", err)
	}

	request, err := http.NewRequestWithContext(
		t.Context(), http.MethodPatch,
		service.EndpointURL("/developer_application/"+application.ID.String()+"/callback_uris"),
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	request.Header.Set("Content-Type", "application/json")

	for _, name := range []string{service.SessionCookieName(), service.CSRFCookieName()} {
		request.AddCookie(&http.Cookie{Name: name, Value: service.CookieValue(name)})
	}

	service.Protected(request)

	return request
}

// holdApplicationRow takes the application's row lock in a transaction of the
// test's own, so a replacement arriving meanwhile has to wait.
func holdApplicationRow(t *testing.T, service *servertest.Service, application servertest.Application) pgx.Tx {
	t.Helper()

	holder, err := service.Pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("beginning the holding transaction: %v", err)
	}

	if _, err := holder.Exec(t.Context(),
		`SELECT "id" FROM "DeveloperApplication" WHERE "id" = $1 FOR UPDATE`, application.ID,
	); err != nil {
		t.Fatalf("holding the application's row: %v", err)
	}

	return holder
}

// Two replacements of one application's callbacks arriving together leave it
// with one of the two sets, whole. Never the set it had, never both, never a
// mixture: the replacements run one after the other.
func TestReplacementsArrivingTogetherLeaveExactlyOneSubmittedSet(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application", externalCallbackURI)

	first := []string{"https://first.example.test/return", "https://first.example.test/other"}
	second := []string{"https://second.example.test/return"}

	// Both requests are held at the row lock until the test has seen them both
	// waiting there, so they contend for the application rather than one
	// finishing before the other arrives.
	holder := holdApplicationRow(t, service, application)

	released := make(chan struct{})

	go func() {
		defer close(released)

		if err := testdatabase.AwaitLockWaiters(t.Context(), service.Pool, 2); err != nil {
			t.Errorf("waiting for both replacements to block: %v", err)
		}

		if err := holder.Rollback(t.Context()); err != nil {
			t.Errorf("releasing the application's row: %v", err)
		}
	}()

	answers := concurrently(t,
		callbackReplacement(t, service, application, first),
		callbackReplacement(t, service, application, second),
	)

	<-released

	for _, answer := range answers {
		if answer.status != http.StatusOK {
			t.Errorf("a replacement answered %d (body: %s)", answer.status, answer.body)
		}
	}

	registered := registeredCallbacks(t, service, application)
	slices.Sort(registered)

	sortedFirst := slices.Clone(first)
	slices.Sort(sortedFirst)

	if !slices.Equal(registered, sortedFirst) && !slices.Equal(registered, second) {
		t.Errorf("registered callbacks = %v, want exactly %v or exactly %v", registered, first, second)
	}
}

// An application that is deleted while a replacement of its callbacks waits
// for its row is answered as an application that does not exist, and nothing
// is registered for it.
func TestReplacementThatOutlivesItsApplicationFindsNothing(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application", externalCallbackURI)

	holder := holdApplicationRow(t, service, application)

	deleted := make(chan struct{})

	go func() {
		defer close(deleted)

		if err := testdatabase.AwaitLockWaiters(t.Context(), service.Pool, 1); err != nil {
			t.Errorf("waiting for the replacement to block: %v", err)
		}

		if _, err := holder.Exec(t.Context(),
			`DELETE FROM "DeveloperApplication" WHERE "id" = $1`, application.ID,
		); err != nil {
			t.Errorf("deleting the application while a replacement waits: %v", err)
		}

		if err := holder.Commit(t.Context()); err != nil {
			t.Errorf("committing the deletion: %v", err)
		}
	}()

	answers := concurrently(t,
		callbackReplacement(t, service, application, []string{"https://late.example.test/return"}),
	)

	<-deleted

	if answers[0].status != http.StatusNotFound {
		t.Errorf("the replacement answered %d, want %d", answers[0].status, http.StatusNotFound)
	}

	absent := service.GET("/developer_application/" + uuid.New().String()).
		ExpectStatus(http.StatusNotFound)

	if string(answers[0].body) != string(absent.Body) {
		t.Errorf("the replacement answered %s, want the ordinary %s", answers[0].body, absent.Body)
	}

	var registered int
	if err := service.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM "CallbackUri" WHERE "developer_application_id" = $1`, application.ID,
	).Scan(&registered); err != nil {
		t.Fatalf("reading what the replacement left: %v", err)
	}

	if registered != 0 {
		t.Errorf("%d callbacks were registered for an application that no longer exists", registered)
	}
}

// An application may have no callbacks at all. Submitting an empty set is how
// it says so, and no login can be started for it afterwards.
func TestApplicationCanClearItsCallbacks(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application", externalCallbackURI)

	service.GET(authorizePath(application.ID, externalCallbackURI)).
		ExpectStatus(http.StatusTemporaryRedirect)

	service.PATCHJSON(
		"/developer_application/"+application.ID.String()+"/callback_uris",
		[]string{},
		service.Protected,
	).ExpectStatus(http.StatusOK)

	if registered := registeredCallbacks(t, service, application); len(registered) != 0 {
		t.Errorf("registered callbacks = %v, want none", registered)
	}

	service.GET(authorizePath(application.ID, externalCallbackURI)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid application ID or callback URI")
}

// Changing an application is the owner's to do. Somebody else is told exactly
// what they would be told about an application nobody registered, and the
// owner's application is left as it was.
func TestChangingApplicationNeedsToOwnIt(t *testing.T) {
	t.Parallel()

	attempts := map[string]func(*servertest.Service, string) *servertest.Response{
		"deleting it": func(service *servertest.Service, id string) *servertest.Response {
			return service.DELETE("/developer_application/"+id, service.Protected)
		},
		"replacing its credential": func(service *servertest.Service, id string) *servertest.Response {
			return service.PATCHJSON("/developer_application/"+id+"/reset_token", nil, service.Protected)
		},
		"replacing its callbacks": func(service *servertest.Service, id string) *servertest.Response {
			return service.PATCHJSON(
				"/developer_application/"+id+"/callback_uris",
				[]string{"https://elsewhere.example.test/return"},
				service.Protected,
			)
		},
	}

	for name, attempt := range attempts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)

			owner := service.Providers.Someone(oauth.Discord, "the owner")
			service.SignIn(owner)

			application := service.RegisterApplication("an application", externalCallbackURI)

			service.SignIn(service.Providers.Someone(oauth.Discord, "a stranger"))

			stranger := attempt(service, application.ID.String()).ExpectStatus(http.StatusNotFound)
			absent := attempt(service, uuid.New().String()).ExpectStatus(http.StatusNotFound)

			if string(stranger.Body) != string(absent.Body) {
				t.Errorf(
					"an application somebody owns answers %s and one nobody owns answers %s",
					stranger.Body, absent.Body,
				)
			}

			service.SignIn(owner)

			registered := registeredCallbacks(t, service, application)
			if len(registered) != 1 || registered[0] != externalCallbackURI {
				t.Errorf("registered callbacks = %v, want the set the owner registered", registered)
			}

			token := applicationAccessToken(t, service, application.ID, application.RefreshToken)
			service.GET("/developer_application/me", servertest.Bearer(token)).ExpectStatus(http.StatusOK)
		})
	}
}

// Ownership is settled before a submitted body is read, so a stranger sending
// something this service would refuse still only learns that it found nothing.
func TestStrangersUnusableCallbacksAreStillNothingFound(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	owner := service.Providers.Someone(oauth.Discord, "the owner")
	service.SignIn(owner)

	application := service.RegisterApplication("an application", externalCallbackURI)
	path := "/developer_application/" + application.ID.String() + "/callback_uris"

	service.SignIn(service.Providers.Someone(oauth.Discord, "a stranger"))

	service.PATCHJSON(path, []string{"javascript:alert(1)"}, service.Protected).
		ExpectStatus(http.StatusNotFound).
		ExpectDetail("Not Found")

	service.PATCHJSON(path, map[string][]string{"callback_uris": {}}, service.Protected).
		ExpectStatus(http.StatusNotFound).
		ExpectDetail("Not Found")

	service.SignIn(owner)

	registered := registeredCallbacks(t, service, application)
	if len(registered) != 1 || registered[0] != externalCallbackURI {
		t.Errorf("registered callbacks = %v, want the set the owner registered", registered)
	}
}

// A credential is required before anything a request carries is read, so a
// request without one is refused for the credential rather than told which of
// its inputs this service could not read.
func TestManagingApplicationsChecksCredentialBeforeInput(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/developer_application", map[string]string{}).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Authentication required")

	service.GET("/developer_application/not-an-identifier").
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Authentication required")

	service.DELETE("/developer_application/not-an-identifier").
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Authentication required")

	service.PATCHJSON("/developer_application/not-an-identifier/callback_uris",
		map[string][]string{"callback_uris": {}}).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Authentication required")
}

// A submitted list is taken whole or not at all: one URI this service would not
// return a browser to leaves the application with what it had. The refusal
// names the URI's zero-based index and neither the URI nor the rule it broke.
func TestOneUnusableCallbackLeavesRegisteredSetAlone(t *testing.T) {
	t.Parallel()

	unusable := map[string]string{
		"plain HTTP on a host that is not this machine": "http://relying.example.test/return",
		"a scheme that is not the web":                  "javascript:alert(1)",
		"a fragment":                                    "https://relying.example.test/return#fragment",
		"credentials in the address":                    "https://someone:secret@relying.example.test/return",
		"a relative address":                            "/return",
		"a reserved response key":                       "https://relying.example.test/return?code=x",
	}

	for name, uri := range unusable {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t)
			service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

			application := service.RegisterApplication("an application", externalCallbackURI)

			refused := service.PATCHJSON(
				"/developer_application/"+application.ID.String()+"/callback_uris",
				[]string{externalCallbackURI, uri},
				service.Protected,
			).ExpectStatus(http.StatusBadRequest).
				ExpectDetail("Callback URI at index 1 is invalid")

			if strings.Contains(string(refused.Body), uri) {
				t.Error("the refusal repeats the URI that was submitted")
			}

			registered := registeredCallbacks(t, service, application)
			if len(registered) != 1 || registered[0] != externalCallbackURI {
				t.Errorf("registered callbacks = %v, want the set the application already had", registered)
			}
		})
	}
}

// A callback matches by equality. Something that only looks like a registered
// URI is not one.
func TestCallbackIsMatchedExactly(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application", externalCallbackURI)

	nearly := []string{
		externalCallbackURI + "/",
		externalCallbackURI + "?",
		"HTTPS://relying.example.test/return",
		"https://relying.example.test:443/return",
	}

	for _, callback := range nearly {
		service.GET(authorizePath(application.ID, callback)).
			ExpectStatus(http.StatusForbidden).
			ExpectDetail("Invalid application ID or callback URI")
	}
}

// The credential an application is given is the one it can authenticate with,
// exactly as it was handed over.
func TestApplicationAuthenticatesWithCredentialItWasGiven(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	var granted struct {
		Token string `json:"token"`
	}

	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}).ExpectStatus(http.StatusOK).DecodeInto(&granted)

	var described struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	service.GET("/developer_application/me", servertest.Bearer(granted.Token)).
		ExpectStatus(http.StatusOK).
		DecodeInto(&described)

	if described.ID != application.ID.String() || described.Name != application.Name {
		t.Errorf("the token identifies %+v, want %s", described, application.ID)
	}
}

// A credential that is not the application's is refused, whether the
// application exists or not, and in the same words. That holds for the one
// value that does match the comparison an unknown application is checked
// against: it is published, and it grants nothing.
func TestApplicationsCredentialIsNotGuessable(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	// The session that registered the application must not be what a later
	// answer is measured against.
	service.Forget(service.SessionCookieName())
	service.Forget(service.CSRFCookieName())

	presented := map[string]string{
		"a valid credential":    application.RefreshToken,
		"the published input":   applications.UnknownApplicationComparisonInput,
		"an empty credential":   "",
		"a credential too long": strings.Repeat("x", credentials.MaxSecretBytes+1),
	}

	for name, credential := range presented {
		t.Run(name, func(t *testing.T) {
			wrong := service.POSTJSON("/developer_application/login", map[string]string{
				"id":            application.ID.String(),
				"refresh_token": "not-the-credential",
			}).ExpectStatus(http.StatusUnauthorized).
				ExpectDetail("Invalid application credentials")

			absent := service.POSTJSON("/developer_application/login", map[string]string{
				"id":            uuid.New().String(),
				"refresh_token": credential,
			}).ExpectStatus(http.StatusUnauthorized)

			if string(wrong.Body) != string(absent.Body) {
				t.Errorf("a wrong credential answers %s and an unknown application answers %s", wrong.Body, absent.Body)
			}

			if len(absent.Cookies) != 0 || len(wrong.Cookies) != 0 {
				t.Errorf("an unknown application presenting %s was given cookies", name)
			}

			var granted struct {
				Token string `json:"token"`
			}

			absent.DecodeInto(&granted)

			if granted.Token != "" {
				t.Errorf("an unknown application presenting %s was granted a token", name)
			}

			if service.CookieValue(service.SessionCookieName()) != "" {
				t.Errorf("an unknown application presenting %s left the browser holding a session", name)
			}
		})
	}
}

// A credential bcrypt could not have made a hash from is refused in the same
// words for an application that exists as for one that does not.
func TestUnusableCredentialIsRefusedSameForEveryApplication(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	service.Forget(service.SessionCookieName())
	service.Forget(service.CSRFCookieName())

	unusable := map[string]string{
		"empty":    "",
		"too long": strings.Repeat("x", credentials.MaxSecretBytes+1),
	}

	for name, credential := range unusable {
		t.Run(name, func(t *testing.T) {
			known := service.POSTJSON("/developer_application/login", map[string]string{
				"id":            application.ID.String(),
				"refresh_token": credential,
			}).ExpectStatus(http.StatusUnauthorized)

			absent := service.POSTJSON("/developer_application/login", map[string]string{
				"id":            uuid.New().String(),
				"refresh_token": credential,
			}).ExpectStatus(http.StatusUnauthorized)

			if string(known.Body) != string(absent.Body) {
				t.Errorf("a known application answers %s and an unknown one answers %s", known.Body, absent.Body)
			}
		})
	}
}

// Replacing the credential takes effect at once: every token issued against the
// one it replaces stops working, and the replaced credential no longer signs
// the application in.
func TestReplacingCredentialRefusesWhatWentBefore(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")
	before := applicationAccessToken(t, service, application.ID, application.RefreshToken)

	service.GET("/developer_application/me", servertest.Bearer(before)).ExpectStatus(http.StatusOK)

	var replaced struct {
		Token string `json:"token"`
	}

	service.PATCHJSON(
		"/developer_application/"+application.ID.String()+"/reset_token", nil, service.Protected,
	).ExpectStatus(http.StatusOK).DecodeInto(&replaced)

	if replaced.Token == application.RefreshToken {
		t.Fatal("the credential was not replaced")
	}

	service.GET("/developer_application/me", servertest.Bearer(before)).
		ExpectStatus(http.StatusForbidden)

	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}).ExpectStatus(http.StatusUnauthorized)

	after := applicationAccessToken(t, service, application.ID, replaced.Token)
	service.GET("/developer_application/me", servertest.Bearer(after)).ExpectStatus(http.StatusOK)
}

// Deleting an application takes everything that referred to it: nobody can read
// it, and no login can be started for it.
func TestDeletingApplicationTakesWhatReferredToIt(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application", externalCallbackURI)

	service.DELETE("/developer_application/"+application.ID.String(), service.Protected).
		ExpectStatus(http.StatusOK)

	service.GET("/developer_application/" + application.ID.String()).
		ExpectStatus(http.StatusNotFound)

	if names := listedApplications(t, service); len(names) != 0 {
		t.Errorf("a deleted application is still listed: %v", names)
	}

	service.GET(authorizePath(application.ID, externalCallbackURI)).
		ExpectStatus(http.StatusForbidden)

	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": application.RefreshToken,
	}).ExpectStatus(http.StatusUnauthorized)
}

// Managing applications is something only the site's own sign-in can do. A
// token an application was given to identify its user is not it.
func TestApplicationsTokenCannotManageItsUsersApplications(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	var granted struct {
		Token string `json:"token"`
	}

	service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusOK).DecodeInto(&granted)

	service.GET("/me", servertest.Bearer(granted.Token)).ExpectStatus(http.StatusOK)

	service.GET("/user/applications", servertest.Bearer(granted.Token)).
		ExpectStatus(http.StatusForbidden)

	service.POSTJSON("/developer_application", map[string]string{"name": "not allowed"},
		servertest.Bearer(granted.Token)).
		ExpectStatus(http.StatusForbidden)
}

// Without a credential nothing about applications is readable, and the refusal
// does not say what exists.
func TestManagingApplicationsNeedsCredential(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/user/applications").
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Authentication required")

	service.GET("/developer_application/" + uuid.New().String()).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Authentication required")

	service.POSTJSON("/developer_application", map[string]string{"name": "unauthorised"}).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Authentication required")
}

func TestApplicationIsRegisteredWithName(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	service.POSTJSON("/developer_application", map[string]string{}, service.Protected).
		ExpectRejectedInput("body", "name")

	service.GET("/developer_application/not-an-identifier").
		ExpectRejectedInput("path", "application_id")
}

// authorizePath is where a browser starts a Discord login for an application.
func authorizePath(applicationID uuid.UUID, callback string) string {
	return "/ui/discord/authorize?" + url.Values{
		"application_id": {applicationID.String()},
		"callback_uri":   {callback},
	}.Encode()
}

func listedApplications(t *testing.T, service *servertest.Service) []string {
	t.Helper()

	var listed []struct {
		Name string `json:"name"`
	}

	service.GET("/user/applications").ExpectStatus(http.StatusOK).DecodeInto(&listed)

	names := make([]string, 0, len(listed))
	for _, application := range listed {
		names = append(names, application.Name)
	}

	return names
}

func registeredCallbacks(t *testing.T, service *servertest.Service, application servertest.Application) []string {
	t.Helper()

	var described struct {
		CallbackUris []string `json:"callback_uris"`
	}

	service.GET("/developer_application/" + application.ID.String()).
		ExpectStatus(http.StatusOK).
		DecodeInto(&described)

	return described.CallbackUris
}

func applicationAccessToken(t *testing.T, service *servertest.Service, id uuid.UUID, refreshToken string) string {
	t.Helper()

	var granted struct {
		Token string `json:"token"`
	}

	service.POSTJSON("/developer_application/login", map[string]string{
		"id":            id.String(),
		"refresh_token": refreshToken,
	}).ExpectStatus(http.StatusOK).DecodeInto(&granted)

	return granted.Token
}

// A public client is registered with no credential at all: none is returned,
// none is stored, none can be reset, and nothing it presents authenticates it.
// Every management shape states its client type.
func TestPublicClientIsRegisteredWithoutCredential(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	var registered map[string]json.RawMessage

	service.POSTJSON("/developer_application", map[string]string{"name": "an installed application", "client_type": "public"},
		service.Protected).ExpectStatus(http.StatusOK).DecodeInto(&registered)

	members := make([]string, 0, len(registered))
	for member := range registered {
		members = append(members, member)
	}

	slices.Sort(members)

	if !slices.Equal(members, []string{"client_type", "id", "name", "owner_id"}) {
		t.Errorf("a public client's registration answered %v", members)
	}

	var identifier string
	if err := json.Unmarshal(registered["id"], &identifier); err != nil {
		t.Fatalf("the registration named no identifier: %v", err)
	}

	var stored int
	if err := service.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM "DeveloperApplication" WHERE "id" = $1 AND "refresh_token" IS NULL`, identifier,
	).Scan(&stored); err != nil || stored != 1 {
		t.Errorf("a public client's credential column is not empty: %d %v", stored, err)
	}

	service.PATCHJSON("/developer_application/"+identifier+"/reset_token", nil, service.Protected).
		ExpectStatus(http.StatusConflict).
		ExpectDetail("Public client has no credential")

	for _, presented := range []string{applications.UnknownApplicationComparisonInput, strings.Repeat("A", 43), "x"} {
		service.POSTJSON("/developer_application/login", map[string]string{"id": identifier, "refresh_token": presented}).
			ExpectStatus(http.StatusUnauthorized)
	}

	var described struct {
		ClientType string `json:"client_type"`
	}

	service.GET("/developer_application/" + identifier).ExpectStatus(http.StatusOK).DecodeInto(&described)

	if described.ClientType != "public" {
		t.Errorf("the application is described as %q", described.ClientType)
	}

	var listed []struct {
		ID         string `json:"id"`
		ClientType string `json:"client_type"`
	}

	service.GET("/user/applications").ExpectStatus(http.StatusOK).DecodeInto(&listed)

	if len(listed) != 1 || listed[0].ClientType != "public" {
		t.Errorf("the list describes %+v", listed)
	}
}

// Registration that names no client type is confidential and carries its
// credential exactly as before, and an unknown type is refused as an input.
func TestOmittedClientTypeRegistersConfidentialApplication(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	application := service.RegisterApplication("a server-side application", externalCallbackURI)
	applicationAccessToken(t, service, application.ID, application.RefreshToken)

	var reset struct {
		ClientType string `json:"client_type"`
		Token      string `json:"token"`
	}

	service.PATCHJSON("/developer_application/"+application.ID.String()+"/reset_token", nil, service.Protected).
		ExpectStatus(http.StatusOK).DecodeInto(&reset)

	if reset.ClientType != "confidential" || reset.Token == "" {
		t.Errorf("a confidential reset answered %+v", reset)
	}

	for _, clientType := range []any{"native", "Public", "", 1} {
		service.POSTJSON("/developer_application", map[string]any{"name": "x", "client_type": clientType}, service.Protected).
			ExpectRejectedInput("body", "client_type")
	}
}

// A public client registers only portless loopback templates, and a
// confidential application keeps its own callback policy.
func TestCallbackPolicyFollowsClientType(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	public := service.RegisterPublicClient("an installed application")
	confidential := service.RegisterApplication("a server-side application")

	replace := func(application servertest.Application, uris ...string) *servertest.Response {
		return service.PATCHJSON("/developer_application/"+application.ID.String()+"/callback_uris", uris, service.Protected)
	}

	for _, refused := range []string{
		externalCallbackURI,
		"http://127.0.0.1:8080/oauth/callback",
		"http://localhost/oauth/callback",
		"http://127.0.0.1",
		"http://127.0.0.1/oauth/callback?state=x",
		"http://127.0.0.1/oauth/callback?ISS=x",
		"http://127.0.0.1/oauth/callback#x",
		"myapp://callback",
	} {
		replace(public, ipv4Template, refused).
			ExpectStatus(http.StatusBadRequest).
			ExpectDetail("Callback URI at index 1 is invalid")
	}

	replace(public, ipv4Template, ipv6Template, "http://127.0.0.1/oauth/callback?tenant=a").ExpectStatus(http.StatusOK)
	replace(confidential, ipv4Template).ExpectStatus(http.StatusBadRequest)
	replace(confidential, externalCallbackURI).ExpectStatus(http.StatusOK)
}

// A public client cannot use the confidential sign-in, even with a callback
// it registered: nothing is stored and no provider is involved.
func TestPublicClientCannotStartConfidentialSignIn(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignInSomeone("the developer")

	public := service.RegisterPublicClient("an installed application", ipv4Template)
	logins := countRows(t, service, "oauth_authorization_state")

	for _, provider := range oauth.Providers {
		service.GET("/ui/" + string(provider) + "/authorize?" + url.Values{
			"application_id": {public.ID.String()},
			"callback_uri":   {ipv4Template},
		}.Encode()).
			ExpectStatus(http.StatusForbidden).
			ExpectDetail("Invalid application ID or callback URI")
	}

	if after := countRows(t, service, "oauth_authorization_state"); after != logins {
		t.Errorf("refused sign-ins stored %d logins", after-logins)
	}
}
