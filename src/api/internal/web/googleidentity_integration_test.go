//go:build integration

package web_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/providers/providertest"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// signInWithGoogleAnswering completes a Google sign-in against a provider that
// answers as the test describes, and reports whether the browser ended up
// signed in.
func signInWithGoogleAnswering(t *testing.T, answering func(*providertest.Options)) bool {
	t.Helper()

	service := servertest.New(t, servertest.WithProviderAnswering(answering))

	started := service.StartLogin(oauth.Google, service.Site.ApplicationID, service.Site.CallbackURI)
	response := service.FinishLogin(started, service.Providers.Someone(oauth.Google, "someone"))

	if response.Status == http.StatusInternalServerError {
		t.Errorf("a refused identity token was reported as a failure of this service: %s", response.Body)
	}

	return response.Cookie(service.SessionCookieName()) != nil
}

// An identity token is what Google says about a person, and every one of these
// is a way of saying it about somebody else, or of saying it without being
// Google. None of them signs anybody in.
func TestAnIdentityTokenIsRefusedUnlessGoogleIssuedItForThisLogin(t *testing.T) {
	t.Parallel()

	refusals := map[string]func(*providertest.Options){
		"another issuer": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) {
				claims["iss"] = "https://accounts.example.test"
			}
		},
		"another audience": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) {
				claims["aud"] = "somebody-else's-client-id"
			}
		},
		"several audiences without an authorized party": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) {
				claims["aud"] = []string{claims["aud"].(string), "somebody-else's-client-id"}
			}
		},
		"an authorized party that is somebody else": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) {
				claims["aud"] = []string{claims["aud"].(string), "somebody-else's-client-id"}
				claims["azp"] = "somebody-else's-client-id"
			}
		},
		"a nonce from another login": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) {
				claims["nonce"] = "a-nonce-this-login-never-asked-for"
			}
		},
		"no nonce at all": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) { delete(claims, "nonce") }
		},
		"a token that has expired": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) {
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			}
		},
		"a token issued in the future": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) {
				claims["iat"] = time.Now().Add(time.Hour).Unix()
			}
		},
		"a token with no expiry": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) { delete(claims, "exp") }
		},
		"nobody in particular": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) { claims["sub"] = "" }
		},
		"an access token hash that does not match": func(options *providertest.Options) {
			options.AlterIdentityToken = func(claims jwt.MapClaims) {
				claims["at_hash"] = "not-the-hash-of-the-token-that-came-with-it"
			}
		},
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

			if signInWithGoogleAnswering(t, answering) {
				t.Error("the browser was signed in")
			}
		})
	}
}

// The same journey, with Google answering as Google does, signs the person in.
// Without this the refusals above would pass for the wrong reason.
func TestGoogleSigningSomebodyInStillWorks(t *testing.T) {
	t.Parallel()

	if !signInWithGoogleAnswering(t, func(*providertest.Options) {}) {
		t.Error("a correct identity token did not sign anybody in")
	}
}
