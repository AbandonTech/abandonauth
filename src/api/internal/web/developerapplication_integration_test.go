//go:build integration

package web_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

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
func TestAnApplicationNobodyOwnsAndOneSomebodyElseOwnsAreTheSameAnswer(t *testing.T) {
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

// An application may have no callbacks at all. Submitting an empty set is how
// it says so, and no login can be started for it afterwards.
func TestAnApplicationCanClearItsCallbacks(t *testing.T) {
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
		ExpectDetail("Invalid application ID or callback_uri")
}

// Changing an application is the owner's to do. Somebody else is told exactly
// what they would be told about an application nobody registered, and the
// owner's application is left as it was.
func TestChangingAnApplicationNeedsToOwnIt(t *testing.T) {
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
func TestAStrangersUnusableCallbacksAreStillNothingFound(t *testing.T) {
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
func TestManagingApplicationsChecksTheCredentialBeforeTheInput(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/developer_application", map[string]string{}).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")

	service.GET("/developer_application/not-an-identifier").
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")

	service.DELETE("/developer_application/not-an-identifier").
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")

	service.PATCHJSON("/developer_application/not-an-identifier/callback_uris",
		map[string][]string{"callback_uris": {}}).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")
}

// A submitted list is taken whole or not at all: one URI this service would not
// return a browser to leaves the application with what it had.
func TestOneUnusableCallbackLeavesTheRegisteredSetAlone(t *testing.T) {
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

			service.PATCHJSON(
				"/developer_application/"+application.ID.String()+"/callback_uris",
				[]string{externalCallbackURI, uri},
				service.Protected,
			).ExpectStatus(http.StatusBadRequest).
				ExpectDetail("One of the callback URIs is not a URI this service will return a browser to")

			registered := registeredCallbacks(t, service, application)
			if len(registered) != 1 || registered[0] != externalCallbackURI {
				t.Errorf("registered callbacks = %v, want the set the application already had", registered)
			}
		})
	}
}

// A callback matches by equality. Something that only looks like a registered
// URI is not one.
func TestACallbackIsMatchedExactly(t *testing.T) {
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
			ExpectDetail("Invalid application ID or callback_uri")
	}
}

// The credential an application is given is the one it can authenticate with,
// exactly as it was handed over.
func TestAnApplicationAuthenticatesWithTheCredentialItWasGiven(t *testing.T) {
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
// application exists or not, and in the same words.
func TestAnApplicationsCredentialIsNotGuessable(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")

	wrong := service.POSTJSON("/developer_application/login", map[string]string{
		"id":            application.ID.String(),
		"refresh_token": "not-the-credential",
	}).ExpectStatus(http.StatusUnauthorized)

	absent := service.POSTJSON("/developer_application/login", map[string]string{
		"id":            uuid.New().String(),
		"refresh_token": application.RefreshToken,
	}).ExpectStatus(http.StatusUnauthorized)

	if string(wrong.Body) != string(absent.Body) {
		t.Errorf("a wrong credential answers %s and an unknown application answers %s", wrong.Body, absent.Body)
	}
}

// Replacing the credential takes effect at once: every token issued against the
// one it replaces stops working, and the replaced credential no longer signs
// the application in.
func TestReplacingTheCredentialRefusesWhatWentBefore(t *testing.T) {
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
func TestDeletingAnApplicationTakesWhatReferredToIt(t *testing.T) {
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
func TestAnApplicationsTokenCannotManageItsUsersApplications(t *testing.T) {
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
func TestManagingApplicationsNeedsACredential(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.GET("/user/applications").
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")

	service.GET("/developer_application/" + uuid.New().String()).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")

	service.POSTJSON("/developer_application", map[string]string{"name": "unauthorised"}).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Not authenticated")
}

func TestAnApplicationIsRegisteredWithAName(t *testing.T) {
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
