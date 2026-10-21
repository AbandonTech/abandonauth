//go:build integration && !devtools

package web_test

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// A withdrawn access token stops authenticating its principal straight away and
// for the rest of its lifetime, and its refusal is indistinguishable from any
// other invalid access token.
func TestWithdrawnTokenIsRefusedAsInvalid(t *testing.T) {
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

	refused := service.GET("/me", servertest.Bearer(granted.Token)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid access token")

	forged := service.GET("/me", servertest.Bearer("not-a-token")).ExpectStatus(http.StatusForbidden)

	if !bytes.Equal(refused.Body, forged.Body) {
		t.Errorf("a withdrawn token was refused as %s, a forged token as %s", refused.Body, forged.Body)
	}

	if len(refused.Cookies) != 0 {
		t.Errorf("refusing a withdrawn token set %d cookies, want none", len(refused.Cookies))
	}
}

// A one-time code can be withdrawn before it is spent, and then it cannot be
// spent at all.
func TestWithdrawnCodeCannotBeSpent(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	service.POSTJSON("/burn-token", map[string]string{"token": code}).ExpectStatus(http.StatusOK)

	withdrawn := service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", code),
	).ExpectStatus(http.StatusUnauthorized).ExpectDetail("Invalid exchange code")

	unknown := service.POSTJSON("/login",
		map[string]string{"id": application.ID.String(), "refresh_token": application.RefreshToken},
		servertest.Header("exchange-token", "a value that was never issued"),
	).ExpectStatus(http.StatusUnauthorized)

	if !bytes.Equal(withdrawn.Body, unknown.Body) {
		t.Errorf("a withdrawn code was refused as %s, an unknown one as %s", withdrawn.Body, unknown.Body)
	}
}

// The answer is the same empty success whatever was presented, so the endpoint
// cannot be used to find out which credentials are outstanding.
func TestWithdrawingSomethingSaysNothingAboutIt(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	issuedToken := userAccessToken(t, service, application)
	issuedCode := signInToApplication(t, service, application, externalCallbackURI)

	// In order, so that each repeat follows the withdrawal it repeats.
	values := []struct {
		name  string
		value string
	}{
		{"an issued access token", issuedToken},
		{"the same access token again", issuedToken},
		{"an issued exchange code", issuedCode},
		{"the same exchange code again", issuedCode},
		{"a value that was never issued", "a value that was never issued"},
		{"a token with a forged signature", "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb21lb25lIn0.not-a-signature"},
		{"an empty value", ""},
	}

	for _, withdrawn := range values {
		answered := service.POSTJSON("/burn-token", map[string]string{"token": withdrawn.value}).
			ExpectStatus(http.StatusOK)

		if len(answered.Body) != 0 {
			t.Errorf("withdrawing %s answered with %d bytes, want none", withdrawn.name, len(answered.Body))
		}
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
func TestWithdrawingTokenDoesNotEndBrowserSession(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "a person"))

	session := service.CookieValue(service.SessionCookieName())

	service.POSTJSON("/burn-token", map[string]string{"token": session}).ExpectStatus(http.StatusOK)

	service.GET("/me").ExpectStatus(http.StatusOK)
}

// A code is spent at the endpoint that collects it, so a code seen in a
// redirect cannot be turned into a token by anybody who saw it.
func TestCodeInRedirectIsNotCredentialOnItsOwn(t *testing.T) {
	t.Parallel()

	service := servertest.New(t)
	service.SignIn(service.Providers.Someone(oauth.Discord, "the owner"))

	application := service.RegisterApplication("a relying application", externalCallbackURI)
	code := signInToApplication(t, service, application, externalCallbackURI)

	service.GET("/me", servertest.Bearer(code)).
		ExpectStatus(http.StatusForbidden).
		ExpectDetail("Invalid access token")

	service.GET("/ui/?" + url.Values{"code": {code}}.Encode()).
		ExpectStatus(http.StatusTemporaryRedirect)
}
