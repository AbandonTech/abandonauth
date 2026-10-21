//go:build integration && !devtools

package web_test

import (
	"bytes"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/tokens"
	"github.com/abandontech/abandonauth/src/api/internal/web"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// A credential this service did not issue authenticates no principal. A
// malformed Authorization header is reported as such; every unusable bearer
// value is the same invalid access token.
func TestIdentifyingSomebodyNeedsCredentialThisServiceIssued(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	refusals := map[string]struct {
		authorization string
		detail        string
	}{
		"no credential at all": {authorization: "", detail: "Authentication required"},
		"another scheme": {
			authorization: "Basic c29tZW9uZQ==", detail: "Invalid Authorization header",
		},
		"the scheme with no value": {
			authorization: "Bearer", detail: "Invalid Authorization header",
		},
		"the scheme with only spaces": {
			authorization: "Bearer    ", detail: "Invalid Authorization header",
		},
		"something that is not a token": {
			authorization: "Bearer not-a-token", detail: "Invalid access token",
		},
		"a token with a broken signature": {
			authorization: "Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb21lb25lIn0.not-a-signature",
			detail:        "Invalid access token",
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

// A developer application access token authenticates the application, not its
// owner. Presenting it where a user principal is required authenticates no one.
func TestApplicationsOwnCredentialIdentifiesNoPerson(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("an application")
	token := applicationAccessToken(t, service, application.ID, application.RefreshToken)

	service.GET("/me", servertest.Bearer(token)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid access token")

	service.GET("/user/applications", servertest.Bearer(token)).
		ExpectStatus(http.StatusForbidden)
}

// A user access token's audience is one application. Once that application is
// deleted the audience check refuses the token.
func TestTokenForApplicationThatIsGoneIdentifiesNobody(t *testing.T) {
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
		ExpectDetail("Invalid access token")
}

// An application collecting a token has to authenticate, and a code cannot be
// spent without application authentication.
func TestSpendingCodeRequiresApplicationToIdentifyItself(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	service.POSTJSON("/login", nil, servertest.Header("exchange-token", code)).
		ExpectStatus(http.StatusUnauthorized).
		ExpectDetail("Application authentication required")

	wrongCredential := service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": "not-the-credential"},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid application credentials")

	unknownApplication := service.POSTJSON("/login",
		map[string]string{"id": uuid.NewString(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusForbidden)

	if !bytes.Equal(unknownApplication.Body, wrongCredential.Body) {
		t.Errorf("an unknown application was refused as %s, a wrong credential as %s",
			unknownApplication.Body, wrongCredential.Body)
	}

	// The code was never spent by any of that, so it is still good.
	service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusOK)
}

// An application may present its own access token instead of its credentials,
// and a token in the header is the claim being made: it is not fallen back on.
func TestApplicationMaySpendCodeWithItsOwnToken(t *testing.T) {
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

func TestSpendingRequiresCode(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/login", nil).ExpectRejectedInput("header", "exchange-token")
}

// The request is read before the credential it carries is looked at, so an
// application holding a token this service issued still has to send something
// this service can read. Nothing is spent by a request that was never read.
func TestSpendingCodeReadsRequestBeforeCredential(t *testing.T) {
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

// A user access token authenticates a user. Presenting it where a developer
// application principal is required authenticates no one, which is the mirror
// of a developer application token authenticating no user.
func TestPersonsCredentialIsNotApplicationsCredential(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	token := userAccessToken(t, service, application)

	service.GET("/me", servertest.Bearer(token)).ExpectStatus(http.StatusOK)

	service.GET("/developer_application/me", servertest.Bearer(token)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid access token")
}

// An access token is valid for fifteen minutes. Once it has expired the client
// is told so, which is the one refusal reported separately from an invalid
// token.
func TestAgedOutTokenIsRefusedAsExpired(t *testing.T) {
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
		ExpectDetail("Access token expired")
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
