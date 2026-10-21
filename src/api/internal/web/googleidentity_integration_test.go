//go:build integration && !devtools

package web_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// identityMarker is part of every claim value and identity a test below
// controls, so one search shows whether any of them reached a response or the
// log.
const identityMarker = "synthetic-identity-marker"

// googleSignIn is one Google callback and what the test knows about it.
type googleSignIn struct {
	service  *servertest.Service
	response *servertest.Response
	code     string
}

// signInWithGoogleAnswering completes a Google sign-in to the site against a
// provider that answers as the test describes.
func signInWithGoogleAnswering(t *testing.T, answering func(*providertest.Options)) googleSignIn {
	t.Helper()

	service := servertest.New(t, servertest.WithProviderAnswering(answering))

	started := service.StartLogin(oauth.Google, service.Site.ApplicationID, service.Site.CallbackURI)
	code := service.Providers.Issue(oauth.Google, providertest.Grant{
		Identity: providertest.Identity{
			ID:       "google-subject-" + identityMarker,
			Username: identityMarker + " name",
		},
		Challenge: started.Challenge,
		Nonce:     started.Nonce,
	})

	return googleSignIn{
		service:  service,
		response: service.ReturnFromProvider(oauth.Google, code, started.State),
		code:     code,
	}
}

func alteringIdentityToken(change func(jwt.MapClaims)) func(*providertest.Options) {
	return func(options *providertest.Options) { options.AlterIdentityToken = change }
}

// The identity tokens Google must be refused for: each claims an identity for
// another issuer, audience, authorized party, login, time or access token, or
// is not signed with a key Google publishes. Every refusal is the same 403
// response, grants no session, and repeats no claim, code or identity value in
// the response or the log.
func TestIdentityTokenIsRefusedUnlessGoogleIssuedItForThisLogin(t *testing.T) {
	t.Parallel()

	other := identityMarker + "-client-id"

	refusals := map[string]func(*providertest.Options){
		"another issuer": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["iss"] = "https://" + identityMarker + ".example.test"
		}),
		"another audience": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["aud"] = other
		}),
		"an audience claim of the wrong type": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["aud"] = map[string]any{identityMarker: true}
		}),
		"several audiences without an authorized party": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["aud"] = []string{claims["aud"].(string), other}
		}),
		"an authorized party that is somebody else": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["aud"] = []string{claims["aud"].(string), other}
			claims["azp"] = other
		}),
		"a nonce from another login": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["nonce"] = identityMarker + "-nonce"
		}),
		"no nonce at all": alteringIdentityToken(func(claims jwt.MapClaims) { delete(claims, "nonce") }),
		"a token that has expired": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
		}),
		"a token issued in the future": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["iat"] = time.Now().Add(time.Hour).Unix()
		}),
		"a token not yet active": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["nbf"] = time.Now().Add(time.Hour).Unix()
		}),
		"a token with no expiry":     alteringIdentityToken(func(claims jwt.MapClaims) { delete(claims, "exp") }),
		"a token with no issue time": alteringIdentityToken(func(claims jwt.MapClaims) { delete(claims, "iat") }),
		"nobody in particular":       alteringIdentityToken(func(claims jwt.MapClaims) { claims["sub"] = "" }),
		"an access token hash that does not match": alteringIdentityToken(func(claims jwt.MapClaims) {
			claims["at_hash"] = identityMarker + "-at-hash"
		}),
		"a signature from a key Google does not publish": func(options *providertest.Options) {
			options.SignIdentityTokenWithAnotherKey = true
		},
		"a symmetric signature": func(options *providertest.Options) {
			options.IdentityTokenAlgorithm = jwt.SigningMethodHS256
		},
	}

	for what, answering := range refusals {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			signIn := signInWithGoogleAnswering(t, answering)

			expectSignInValidationFailed(t, signIn.service, signIn.response)

			for where, written := range map[string]string{
				"the response": string(signIn.response.Body),
				"the log":      signIn.service.Logs.String(),
			} {
				if strings.Contains(written, identityMarker) {
					t.Errorf("%s repeats a claim or identity value", where)
				}

				if strings.Contains(written, signIn.code) {
					t.Errorf("%s repeats the authorization code", where)
				}
			}
		})
	}
}

// The same journey, with Google answering as Google does, signs the person in.
// Without this the refusals above would pass for the wrong reason.
func TestGoogleSigningSomebodyInStillWorks(t *testing.T) {
	t.Parallel()

	signIn := signInWithGoogleAnswering(t, func(*providertest.Options) {})

	signIn.response.
		ExpectStatus(http.StatusTemporaryRedirect).
		ExpectRedirectTo(signIn.service.Site.CallbackURI)

	if signIn.response.Cookie(signIn.service.SessionCookieName()) == nil {
		t.Error("a correct identity token did not sign anybody in")
	}
}
