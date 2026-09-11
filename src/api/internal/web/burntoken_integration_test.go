//go:build integration && !devtools

package web_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// A token that has been withdrawn stops identifying anybody, straight away and
// for the rest of the life it would have had.
func TestAWithdrawnTokenIdentifiesNobody(t *testing.T) {
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

	withdrawn := service.POSTJSON("/burn-token", map[string]string{"token": granted.Token}).
		ExpectStatus(http.StatusOK)

	if len(withdrawn.Body) != 0 {
		t.Errorf("withdrawing a token answered with %s, want nothing", withdrawn.Body)
	}

	service.GET("/me", servertest.Bearer(granted.Token)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")
}

// A one-time code can be withdrawn before it is spent, and then it cannot be
// spent at all.
func TestAWithdrawnCodeCannotBeSpent(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	service.POSTJSON("/burn-token", map[string]string{"token": code}).ExpectStatus(http.StatusOK)

	service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusUnauthorized).ExpectDetail("Token is not valid.")
}

// The answer is the same whatever was presented, so the endpoint cannot be used
// to find out which credentials are outstanding.
func TestWithdrawingSomethingSaysNothingAboutIt(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	values := []string{
		"a value that was never issued",
		"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb21lb25lIn0.not-a-signature",
		"",
	}

	for _, value := range values {
		service.POSTJSON("/burn-token", map[string]string{"token": value})
	}

	first := service.POSTJSON("/burn-token", map[string]string{"token": "the same value twice"}).
		ExpectStatus(http.StatusOK)
	second := service.POSTJSON("/burn-token", map[string]string{"token": "the same value twice"}).
		ExpectStatus(http.StatusOK)

	if string(first.Body) != string(second.Body) {
		t.Errorf("withdrawing the same value twice answered %q then %q", first.Body, second.Body)
	}
}

func TestWithdrawingNeedsSomethingToWithdraw(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)

	service.POSTJSON("/burn-token", map[string]string{}).ExpectRejectedInput("body", "token")
	service.POSTRaw("/burn-token", "").ExpectRejectedInput("body")
	service.POSTRaw("/burn-token", "{", servertest.Header("Content-Type", "application/json")).
		ExpectStatus(http.StatusUnprocessableEntity)
}

// The site's own session is ended by logging out, not by withdrawing a token,
// and one does not do the other's work.
func TestWithdrawingATokenDoesNotEndABrowserSession(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	session := service.CookieValue(service.SessionCookieName())

	service.POSTJSON("/burn-token", map[string]string{"token": session}).ExpectStatus(http.StatusOK)

	service.GET("/me").ExpectStatus(http.StatusOK)
}

// A code is spent at the endpoint that collects it, so a code seen in a
// redirect cannot be turned into a token by anybody who saw it.
func TestACodeInARedirectIsNotACredentialOnItsOwn(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	service.GET("/me", servertest.Bearer(code)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid token format")

	service.GET("/ui/?" + url.Values{"code": {code}}.Encode()).
		ExpectStatus(http.StatusTemporaryRedirect)
}
