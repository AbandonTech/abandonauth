//go:build integration && devtools

// Package passwordsignintest drives the password sign-in routes only the
// development build carries, through the running service.
package passwordsignintest

import (
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/abandontech/abandonauth/src/api/internal/config"
	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/web/servertest"
)

// The password a developer signs the seeded account in with. It is a
// placeholder: these routes exist to seed a machine that no other machine can
// reach.
const developerPassword = "placeholder-password"

// developmentService runs the service the way a developer runs it: this build,
// debug mode on, and a listener only the local machine can reach. All three are
// required before the password routes answer at all.
func developmentService(t *testing.T, choices ...servertest.Option) *servertest.Service {
	t.Helper()

	development := servertest.WithSetting(func(settings *config.Settings) {
		settings.DevelopmentBuild = true
		settings.Debug = true
		settings.BindAddress = "127.0.0.1:8000"
	})

	return servertest.New(t, append([]servertest.Option{development}, choices...)...)
}

// seedAccount creates an account that signs in with a password and returns who
// it turned out to be.
func seedAccount(t *testing.T, service *servertest.Service, username string) string {
	t.Helper()

	var created struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}

	service.POSTJSON("/create_test_user", map[string]string{
		"username": username,
		"password": developerPassword,
	}).ExpectStatus(http.StatusOK).DecodeInto(&created)

	if created.Username != username {
		t.Errorf("username = %q, want %q", created.Username, username)
	}

	if created.ID == "" {
		t.Fatal("the account was created without an identifier")
	}

	return created.ID
}

// Even where these routes exist, they exist at one address each. A target the
// router would clean or decode into one of them is refused before it gets
// there, so seeding an account has exactly the one way in that the three
// conditions above guard.
func TestSeedingAccountHasOnlyOneAddress(t *testing.T) {
	t.Parallel()

	service := developmentService(t)

	spellings := []string{
		"/create_test_user",
		"/login_test_user",
		"/api//create_test_user",
		"/api/../api/create_test_user",
		"/api/%63reate_test_user",
		"/api/ui/../create_test_user",
		"/api/create_test_user/",
	}

	for _, target := range spellings {
		service.AtExactTarget(http.MethodPost, target).
			ExpectStatus(http.StatusNotFound).
			ExpectDetail("Not Found")
	}
}

// A developer with no provider credentials can still get an account and sign in
// as it, which is the whole reason these routes exist.
func TestAccountSeededWithPasswordCanSignIn(t *testing.T) {
	t.Parallel()

	service := developmentService(t)
	userID := seedAccount(t, service, "a developer")

	service.POSTJSON("/login_test_user", map[string]string{
		"user_id":  userID,
		"password": developerPassword,
	}).ExpectStatus(http.StatusOK)

	var identified struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}

	service.GET("/me").ExpectStatus(http.StatusOK).DecodeInto(&identified)

	if identified.ID != userID {
		t.Errorf("/me identified %q, want %q", identified.ID, userID)
	}
}

// Signing in this way leaves the browser holding the same session a provider
// sign-in leaves, so development exercises the session and its cross-site
// checks rather than a credential a script could read out of the browser.
func TestPasswordSignInEstablishesSameSessionAsProvider(t *testing.T) {
	t.Parallel()

	service := developmentService(t)
	userID := seedAccount(t, service, "a developer")

	signedIn := service.POSTJSON("/login_test_user", map[string]string{
		"user_id":  userID,
		"password": developerPassword,
	}).ExpectStatus(http.StatusOK)

	session := signedIn.Cookie(service.SessionCookieName())
	if session == nil {
		t.Fatal("signing in did not establish a session")
	}

	if !session.HttpOnly {
		t.Error("the session cookie is readable by a script")
	}

	csrf := signedIn.Cookie(service.CSRFCookieName())
	if csrf == nil {
		t.Fatal("signing in left the browser nothing to prove a request came from the site")
	}

	if csrf.HttpOnly {
		t.Error("the site cannot read the token it has to echo back")
	}

	for _, cookie := range signedIn.Cookies {
		if strings.Count(cookie.Value, ".") == 2 {
			t.Errorf("cookie %q looks like a token the browser was handed", cookie.Name)
		}
	}
}

// The session is the authority, so a request that changes something is subject
// to the same cross-site check as any other.
func TestSessionFromPasswordSignInIsSubjectToSiteCheck(t *testing.T) {
	t.Parallel()

	service := developmentService(t)
	userID := seedAccount(t, service, "a developer")

	service.POSTJSON("/login_test_user", map[string]string{
		"user_id":  userID,
		"password": developerPassword,
	}).ExpectStatus(http.StatusOK)

	// The cookies alone, with nothing to show the request came from the site.
	service.POSTJSON("/developer_application", map[string]string{"name": "an application"}).
		ExpectStatus(http.StatusForbidden)

	service.POSTJSON("/developer_application",
		map[string]string{"name": "an application"},
		service.Protected,
	).ExpectStatus(http.StatusOK)
}

// Whether the account exists is not something an attempt reveals.
func TestRefusedPasswordSaysNothingAboutAccount(t *testing.T) {
	t.Parallel()

	service := developmentService(t)
	userID := seedAccount(t, service, "a developer")

	wrongPassword := service.POSTJSON("/login_test_user", map[string]string{
		"user_id":  userID,
		"password": "not-the-password",
	}).ExpectStatus(http.StatusUnauthorized)

	noSuchAccount := service.POSTJSON("/login_test_user", map[string]string{
		"user_id":  "00000000-0000-0000-0000-000000000000",
		"password": developerPassword,
	}).ExpectStatus(http.StatusUnauthorized)

	wrongPassword.ExpectDetail("Invalid user credentials")
	noSuchAccount.ExpectDetail("Invalid user credentials")

	if string(wrongPassword.Body) != string(noSuchAccount.Body) {
		t.Errorf("a wrong password answers %s and an unknown account answers %s", wrongPassword.Body, noSuchAccount.Body)
	}

	if len(wrongPassword.Cookies) != 0 || len(noSuchAccount.Cookies) != 0 {
		t.Error("a refused sign-in set a cookie")
	}

	if service.CookieValue(service.SessionCookieName()) != "" {
		t.Error("a refused sign-in left the browser holding a session")
	}
}

// A password no account can be created with is refused as a password, which is
// a different answer from refusing a sign-in.
func TestAccountCannotBeCreatedWithUnusablePassword(t *testing.T) {
	t.Parallel()

	service := developmentService(t)

	unusable := map[string]string{
		"empty":    "",
		"too long": strings.Repeat("x", credentials.MaxSecretBytes+1),
	}

	for name, password := range unusable {
		t.Run(name, func(t *testing.T) {
			service.POSTJSON("/create_test_user", map[string]string{
				"username": "a developer",
				"password": password,
			}).ExpectStatus(http.StatusBadRequest).
				ExpectDetail("Invalid password")
		})
	}
}

// A password that was accepted is not a session. Everything that can still fail
// after it, here the authority every credential is issued under, fails the
// request whole: no cookie, no token, no stored session.
func TestAcceptedPasswordGrantsNothingWhenAuthorityCannotBeRead(t *testing.T) {
	t.Parallel()

	service := developmentService(t)
	userID := seedAccount(t, service, "a developer")

	signIn := map[string]string{"user_id": userID, "password": developerPassword}

	// The positive control: this password signs the account in.
	service.POSTJSON("/login_test_user", signIn).ExpectStatus(http.StatusOK)

	service.Forget(service.SessionCookieName())
	service.Forget(service.CSRFCookieName())

	var sessionsBefore int
	if err := service.Pool.QueryRow(t.Context(), "SELECT count(*) FROM browser_session").Scan(&sessionsBefore); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}

	// The one row every credential is measured against. Without it there is no
	// authority to issue anything under.
	testdatabase.Execute(t, service.Pool, "DELETE FROM auth_epoch")

	refused := service.POSTJSON("/login_test_user", signIn).
		ExpectStatus(http.StatusInternalServerError).
		ExpectDetail("Internal Server Error")

	if refused.Cookie(service.SessionCookieName()) != nil {
		t.Error("a sign-in that failed after the password was accepted set a session cookie")
	}

	if refused.Cookie(service.CSRFCookieName()) != nil {
		t.Error("a sign-in that failed after the password was accepted set a CSRF cookie")
	}

	if len(refused.Cookies) != 0 {
		t.Errorf("a failed sign-in set %d cookies", len(refused.Cookies))
	}

	var body struct {
		Token string `json:"token"`
	}

	refused.DecodeInto(&body)

	if body.Token != "" {
		t.Error("a failed sign-in answered with a token")
	}

	var sessionsAfter int
	if err := service.Pool.QueryRow(t.Context(), "SELECT count(*) FROM browser_session").Scan(&sessionsAfter); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}

	if sessionsAfter != sessionsBefore {
		t.Errorf("a failed sign-in stored a session: %d sessions, was %d", sessionsAfter, sessionsBefore)
	}

	if service.CookieValue(service.SessionCookieName()) != "" {
		t.Error("the browser is holding a session after a failed sign-in")
	}

	service.GET("/me").ExpectStatus(http.StatusForbidden)
}

// The password is stored as something a reader of the database cannot sign in
// with, at the work factor every stored secret is made with.
func TestStoredPasswordIsNotPasswordThatWasSent(t *testing.T) {
	t.Parallel()

	service := developmentService(t)
	userID := seedAccount(t, service, "a developer")

	var stored string

	err := service.Pool.QueryRow(t.Context(),
		`SELECT "password" FROM "PasswordAccount" WHERE "user_id" = $1`, userID,
	).Scan(&stored)
	if err != nil {
		t.Fatalf("reading what the account was left with: %v", err)
	}

	if stored == developerPassword {
		t.Fatal("the password was stored as it was sent")
	}

	if bcrypt.CompareHashAndPassword([]byte(stored), []byte(developerPassword)) != nil {
		t.Error("the stored value does not verify the password it was made from")
	}

	cost, err := bcrypt.Cost([]byte(stored))
	if err != nil {
		t.Fatalf("the stored password records no cost: %v", err)
	}

	if cost != credentials.HashCost {
		t.Errorf("the password was stored at cost %d, want %d", cost, credentials.HashCost)
	}
}

// Both routes report that they do not exist unless every condition holds,
// because in a deployment they do not.
func TestPasswordRoutesAnswerOnlyOnDevelopersOwnMachine(t *testing.T) {
	t.Parallel()

	unreachable := map[string]servertest.Option{
		"without debug mode": servertest.WithSetting(func(settings *config.Settings) {
			settings.DevelopmentBuild = true
			settings.Debug = false
			settings.BindAddress = "127.0.0.1:8000"
		}),
		"on a listener other machines can reach": servertest.WithSetting(func(settings *config.Settings) {
			settings.DevelopmentBuild = true
			settings.Debug = true
			settings.BindAddress = "0.0.0.0:8000"
		}),
	}

	for name, configured := range unreachable {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := servertest.New(t, configured)

			service.POSTJSON("/create_test_user", map[string]string{
				"username": "a developer",
				"password": developerPassword,
			}).ExpectStatus(http.StatusNotFound).ExpectDetail("Not Found")

			service.POSTJSON("/login_test_user", map[string]string{
				"user_id":  "00000000-0000-0000-0000-000000000000",
				"password": developerPassword,
			}).ExpectStatus(http.StatusNotFound).ExpectDetail("Not Found")
		})
	}
}

// A request that leaves out what it needs is refused for the input it left out.
func TestSeedingAccountRefusesIncompleteRequests(t *testing.T) {
	t.Parallel()

	service := developmentService(t)

	service.POSTJSON("/create_test_user", map[string]string{"password": developerPassword}).
		ExpectRejectedInput("body", "username")

	service.POSTJSON("/create_test_user", map[string]string{"username": "a developer"}).
		ExpectRejectedInput("body", "password")

	service.POSTJSON("/login_test_user", map[string]string{
		"user_id":  "not-a-uuid",
		"password": developerPassword,
	}).ExpectRejectedInput("body", "user_id")
}

// Debug mode relaxes what the service will talk over. It does not relax who may
// talk to it.
func TestDebugModeStillAnswersOnlySite(t *testing.T) {
	t.Parallel()

	service := developmentService(t)

	answered := service.OPTIONS("/me",
		servertest.Header("Origin", "https://somewhere.else.test"),
		servertest.Header("Access-Control-Request-Method", "GET"),
	)

	if origin := answered.Header.Get("Access-Control-Allow-Origin"); origin != "" {
		t.Errorf("Access-Control-Allow-Origin = %q for an origin that is not the site", origin)
	}

	allowed := service.OPTIONS("/me",
		servertest.Header("Origin", service.Config.Site.String()),
		servertest.Header("Access-Control-Request-Method", "GET"),
	)

	if origin := allowed.Header.Get("Access-Control-Allow-Origin"); origin != service.Config.Site.String() {
		t.Errorf("Access-Control-Allow-Origin = %q, want the site", origin)
	}

	if origin := allowed.Header.Get("Access-Control-Allow-Origin"); origin == "*" {
		t.Error("every origin is allowed to send credentials")
	}
}

// A password is a credential, and no credential reaches the logs.
func TestPasswordNeverReachesLogs(t *testing.T) {
	t.Parallel()

	service := developmentService(t)
	userID := seedAccount(t, service, "a developer")

	service.POSTJSON("/login_test_user", map[string]string{
		"user_id":  userID,
		"password": developerPassword,
	}).ExpectStatus(http.StatusOK)

	if strings.Contains(service.Logs.String(), developerPassword) {
		t.Error("the password was written to the logs")
	}
}
