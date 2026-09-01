//go:build integration

package web_test

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/tokens"
	"github.com/abandontech/abandonauth/src/api/internal/web"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// A credential this service did not issue identifies nobody, and being refused
// says only that.
func TestIdentifyingSomebodyNeedsACredentialThisServiceIssued(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	refusals := map[string]struct {
		authorization string
		detail        string
	}{
		"no credential at all": {authorization: "", detail: "Not authenticated"},
		"another scheme": {
			authorization: "Basic c29tZW9uZQ==", detail: "Invalid authentication credentials",
		},
		"the scheme with no value": {
			authorization: "Bearer", detail: "Invalid authentication credentials",
		},
		"the scheme with only spaces": {
			authorization: "Bearer    ", detail: "Invalid authentication credentials",
		},
		"something that is not a token": {
			authorization: "Bearer not-a-token", detail: "Invalid token format",
		},
		"a token with a broken signature": {
			authorization: "Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb21lb25lIn0.not-a-signature",
			detail:        "Invalid token format",
		},
	}

	for name, refusal := range refusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			prepare := []func(*http.Request){}
			if refusal.authorization != "" {
				prepare = append(prepare, servertest.Header("Authorization", refusal.authorization))
			}

			service.GET("/me", prepare...).
				ExpectStatus(http.StatusForbidden).
				ExpectDetail(refusal.detail)
		})
	}
}

// The credential an application holds is the application's, not its user's.
// Presenting it where a person is expected identifies nobody.
func TestAnApplicationsOwnCredentialIdentifiesNoPerson(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")
	token := applicationAccessToken(t, service, application.ID, application.RefreshToken)

	service.GET("/me", servertest.Bearer(token)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")

	service.GET("/user/applications", servertest.Bearer(token)).
		ExpectStatus(http.StatusForbidden)
}

// A token identifies a person to one application. When that application is
// gone there is nobody for it to identify them to.
func TestATokenForAnApplicationThatIsGoneIdentifiesNobody(t *testing.T) {
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

	service.DELETE("/developer_application/"+application.ID.String(), service.Protected).
		ExpectStatus(http.StatusOK)

	service.GET("/me", servertest.Bearer(granted.Token)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")
}

// An application collecting a token has to say who it is, and a code cannot be
// spent by saying nothing.
func TestSpendingACodeRequiresTheApplicationToIdentifyItself(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	service.POSTJSON("/login", nil, servertest.Header("exchange-token", code)).
		ExpectStatus(http.StatusUnauthorized).
		ExpectDetail("Either a developer application JWT must be given in headers " +
			"or the developer application credentials must be passed in the request body")

	service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": "not-the-credential"},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid username or refresh token")

	// The code was never spent by any of that, so it is still good.
	service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusOK)
}

// An application may present its own access token instead of its credentials,
// and a token in the header is the claim being made: it is not fallen back on.
func TestAnApplicationMaySpendACodeWithItsOwnToken(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	token := applicationAccessToken(t, service, application.ID, application.RefreshToken)
	code := signInToApplication(t, service, application, externalCallbackURI)

	service.POSTJSON("/login", nil,
		servertest.Header("exchange-token", code),
		servertest.Bearer(token),
	).ExpectStatus(http.StatusOK)
}

func TestSpendingACodeNeedsTheCode(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/login", nil).ExpectRejectedInput("header", "exchange-token")
}

// The request is read before the credential it carries is looked at, so an
// application holding a token this service issued still has to send something
// this service can read. Nothing is spent by a request that was never read.
func TestSpendingACodeReadsTheRequestBeforeTheCredential(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	token := applicationAccessToken(t, service, application.ID, application.RefreshToken)
	code := signInToApplication(t, service, application, externalCallbackURI)

	service.POSTRaw("/login", "{",
		servertest.Header("Content-Type", "application/json"),
		servertest.Header("exchange-token", code),
		servertest.Bearer(token),
	).ExpectRejectedInput("body")

	service.POSTRaw("/login", "",
		servertest.Header("exchange-token", code),
		servertest.Bearer(token),
	).ExpectStatus(http.StatusOK)
}

// A person's token speaks for a person. Presenting it where an application is
// expected identifies nobody, which is the mirror of an application's own
// credential identifying no person.
func TestAPersonsCredentialIsNotAnApplicationsCredential(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	token := userAccessToken(t, service, application)

	service.GET("/me", servertest.Bearer(token)).ExpectStatus(http.StatusOK)

	service.GET("/developer_application/me", servertest.Bearer(token)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")
}

// A token is good for a quarter of an hour. Once it has aged out the person
// holding it is told that, rather than that it was never this service's.
func TestAnAgedOutTokenIsRefusedAsExpired(t *testing.T) {
	t.Parallel()

	clock := &heldClock{at: time.Now().UTC()}

	service := servertest.New(t, servertest.WithDependencies(func(dependencies *web.Dependencies) {
		dependencies.Now = clock.read
	}))

	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	token := userAccessToken(t, service, application)

	service.GET("/me", servertest.Bearer(token)).ExpectStatus(http.StatusOK)

	clock.advance(tokens.AccessLifetime + tokens.MaxClockSkew + time.Second)

	service.GET("/me", servertest.Bearer(token)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Token has expired")
}

// heldClock is a clock the test moves itself. The service reads it while
// answering requests, so the reads and the moves are guarded.
type heldClock struct {
	guard sync.Mutex
	at    time.Time
}

func (c *heldClock) read() time.Time {
	c.guard.Lock()
	defer c.guard.Unlock()

	return c.at
}

func (c *heldClock) advance(by time.Duration) {
	c.guard.Lock()
	defer c.guard.Unlock()

	c.at = c.at.Add(by)
}
