package servertest

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/applications"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/web"
)

// SiteCallbackURI is where the site's own sign-in returns a browser: the site's
// own origin, which forwards the call to this service's entry point. The
// session the callback created belongs to that origin, so a browser returned to
// the API's origin instead would carry none of it.
const SiteCallbackURI = SiteOrigin + web.APIRoot + "/ui"

// Site is the developer application that stands for AbandonAuth's own site.
type Site struct {
	ApplicationID uuid.UUID
	OwnerID       uuid.UUID

	// RefreshToken is the credential the application authenticates with. It is
	// shown once, here, exactly as it is to whoever registers an application.
	RefreshToken string

	CallbackURI string
}

// registerSite puts the site's own application in the database before the
// service starts.
//
// An operator does this once, by hand, when the service is first deployed:
// registering an application needs an account, an account is created by a
// sign-in, and a sign-in has to name an application that is already registered,
// so nothing the service serves can produce the first of the three. The
// identifier that comes out is what the service is then configured with, which
// is what New does with it.
func registerSite(t *testing.T, pool *pgxpool.Pool, hasher credentials.Hasher) Site {
	t.Helper()

	owner, err := accounts.New(pool).Resolve(t.Context(), accounts.Identity{
		Provider: oauth.Discord,
		ID:       "1",
		Username: "the operator",
	})
	if err != nil {
		t.Fatalf("registering the operator account: %v", err)
	}

	registry := applications.New(pool, hasher)

	application, token, err := registry.Create(t.Context(), owner.ID, "AbandonAuth")
	if err != nil {
		t.Fatalf("registering the site's application: %v", err)
	}

	if err := registry.ReplaceCallbackURIs(t.Context(), application.ID, []string{SiteCallbackURI}); err != nil {
		t.Fatalf("registering the site's callback: %v", err)
	}

	return Site{
		ApplicationID: application.ID,
		OwnerID:       owner.ID,
		RefreshToken:  token,
		CallbackURI:   SiteCallbackURI,
	}
}
