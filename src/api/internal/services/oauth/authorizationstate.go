// Package oauth holds a login that has been started with a provider until the
// provider sends the browser back.
//
// Nothing about the login travels in the redirect except an opaque state value.
// Everything the callback has to agree with — which browser started it, which
// provider it went to, which application it was for, and exactly where the
// person is to be returned — is held in the database and can only be read by
// presenting the state value and the browser's own cookie together. Consuming
// it is a single delete, so a state value works once and only once, whichever
// worker sees it.
package oauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abandontech/abandonauth/src/api/internal/database/query"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
)

// Provider names the identity providers a login can be started with. They are
// the values the database accepts, so a name that is not one of these cannot be
// stored at all.
type Provider string

// The providers this service starts logins with.
const (
	Discord Provider = "discord"
	GitHub  Provider = "github"
	Google  Provider = "google"
)

// Providers lists every provider, in the order they are offered.
var Providers = []Provider{Discord, GitHub, Google}

// ParseProvider returns the provider a path segment names.
func ParseProvider(value string) (Provider, bool) {
	for _, provider := range Providers {
		if string(provider) == value {
			return provider, true
		}
	}

	return "", false
}

// StateLifetime is how long a person has to finish signing in with a provider.
// It is short because the state, the binding cookie and the provider's own
// authorization code are all live during it.
const StateLifetime = 5 * time.Minute

// ErrNoSuchLogin reports that no login in progress matches what was presented.
// It is returned whether the state was never issued, has expired, was already
// used, belongs to another browser, or was started with another provider, so a
// caller learns nothing from being refused.
var ErrNoSuchLogin = errors.New("no login in progress matches this request")

// Start is what a browser needs to be sent to the provider.
type Start struct {
	// State is the opaque value the provider returns unchanged.
	State string

	// BrowserBinding is set as a short-lived cookie. Without it the state value
	// alone cannot complete the login, so a state observed in a redirect or a
	// log is useless in another browser.
	BrowserBinding string

	// Challenge is the PKCE challenge sent to the provider. The verifier it was
	// derived from stays in the database, encrypted, until the callback.
	Challenge string

	// Nonce ties an identity token to this login and is empty for a provider
	// that does not issue one.
	Nonce string
}

// Login is a login in progress that has just been consumed.
type Login struct {
	Provider      Provider
	ApplicationID uuid.UUID

	// CallbackURI is exactly the string the application registered, which is
	// where the person is returned and nowhere else.
	CallbackURI string

	// Verifier is the PKCE verifier, decrypted, to be sent to the provider with
	// the authorization code.
	Verifier string

	// NonceDigest is what the identity token's nonce must digest to.
	NonceDigest []byte
}

// Store records and consumes logins in progress.
type Store struct {
	queries   *query.Queries
	encrypter cipher.AEAD
}

// NewStore builds the store over a database handle and the key that protects
// the PKCE verifier at rest.
func NewStore(database query.DBTX, verifierKey []byte) (*Store, error) {
	block, err := aes.NewCipher(verifierKey)
	if err != nil {
		return nil, fmt.Errorf("preparing the verifier key: %w", err)
	}

	encrypter, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("preparing the verifier cipher: %w", err)
	}

	return &Store{queries: query.New(database), encrypter: encrypter}, nil
}

// Begin records a login and returns what the browser has to carry.
//
// The callback URI is stored as given, and the callback compares it by
// equality: an application is returned to the exact string it registered.
//
// A browser that is already part-way through a login keeps the binding it has,
// so a person with two tabs open can finish either of them. The state, the
// verifier and the nonce are new every time, so the two logins are otherwise
// unrelated and one being finished does nothing to the other.
func (s *Store) Begin(
	ctx context.Context, provider Provider, applicationID uuid.UUID, callbackURI, heldBinding string,
) (Start, error) {
	if applicationID == uuid.Nil || callbackURI == "" {
		return Start{}, errors.New("a login needs an application and a callback")
	}

	state, err := credentials.NewOpaqueValue()
	if err != nil {
		return Start{}, err
	}

	binding := heldBinding

	if binding == "" {
		binding, err = credentials.NewOpaqueValue()
		if err != nil {
			return Start{}, err
		}
	}

	verifier, err := credentials.NewOpaqueValue()
	if err != nil {
		return Start{}, err
	}

	nonce, nonceDigest, err := nonceFor(provider)
	if err != nil {
		return Start{}, err
	}

	sealed, sealNonce, err := s.seal(verifier)
	if err != nil {
		return Start{}, err
	}

	err = s.queries.CreateAuthorizationState(ctx, query.CreateAuthorizationStateParams{
		StateHash:              credentials.Digest(credentials.DomainAuthorizationState, state),
		BrowserBindingHash:     credentials.Digest(credentials.DomainBrowserBinding, binding),
		Provider:               string(provider),
		ApplicationID:          applicationID,
		CallbackUri:            callbackURI,
		PkceVerifierNonce:      sealNonce,
		PkceVerifierCiphertext: sealed,
		GoogleNonceHash:        nonceDigest,
		LifetimeSeconds:        StateLifetime.Seconds(),
	})
	if err != nil {
		return Start{}, fmt.Errorf("recording a login in progress: %w", err)
	}

	return Start{
		State:          state,
		BrowserBinding: binding,
		Challenge:      challengeFor(verifier),
		Nonce:          nonce,
	}, nil
}

// Consume spends a login in progress, returning what the callback must honour.
//
// The row is deleted in the same statement that reads it, so a state value
// presented twice, or presented at the same moment by two workers, succeeds at
// most once.
func (s *Store) Consume(ctx context.Context, provider Provider, state, browserBinding string) (Login, error) {
	if state == "" || browserBinding == "" {
		return Login{}, ErrNoSuchLogin
	}

	consumed, err := s.queries.ConsumeAuthorizationState(ctx, query.ConsumeAuthorizationStateParams{
		StateHash:          credentials.Digest(credentials.DomainAuthorizationState, state),
		BrowserBindingHash: credentials.Digest(credentials.DomainBrowserBinding, browserBinding),
		Provider:           string(provider),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Login{}, ErrNoSuchLogin
	}

	if err != nil {
		return Login{}, fmt.Errorf("consuming a login in progress: %w", err)
	}

	verifier, err := s.open(consumed.PkceVerifierNonce, consumed.PkceVerifierCiphertext)
	if err != nil {
		return Login{}, err
	}

	return Login{
		Provider:      provider,
		ApplicationID: consumed.ApplicationID,
		CallbackURI:   consumed.CallbackUri,
		Verifier:      verifier,
		NonceDigest:   consumed.GoogleNonceHash,
	}, nil
}

// seal encrypts the verifier under a nonce that is never reused, because the
// key protects every login in progress at once.
func (s *Store) seal(verifier string) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, s.encrypter.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generating an encryption nonce: %w", err)
	}

	return s.encrypter.Seal(nil, nonce, []byte(verifier), nil), nonce, nil
}

func (s *Store) open(nonce, ciphertext []byte) (string, error) {
	verifier, err := s.encrypter.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// The stored value was written by this service, so failing to open it
		// means the row was altered. The login is abandoned rather than
		// completed with an unverified proof.
		return "", ErrNoSuchLogin
	}

	return string(verifier), nil
}

// nonceFor returns the value that ties an identity token to this login, for the
// providers that issue one.
func nonceFor(provider Provider) (string, []byte, error) {
	if provider != Google {
		return "", nil, nil
	}

	nonce, err := credentials.NewOpaqueValue()
	if err != nil {
		return "", nil, err
	}

	return nonce, credentials.Digest(credentials.DomainIdentityNonce, nonce), nil
}

// maximumCleanupRows bounds one sweep so that tidying up can never become the
// slowest thing running against the database.
const maximumCleanupRows = 500

// Forget removes logins that were started and never completed.
//
// Consuming a login already requires it to be unexpired, so nothing here could
// still have been finished.
func (s *Store) Forget(ctx context.Context) (int64, error) {
	removed, err := s.queries.DeleteExpiredAuthorizationState(ctx, maximumCleanupRows)
	if err != nil {
		return 0, fmt.Errorf("removing abandoned logins: %w", err)
	}

	return removed, nil
}

// challengeFor derives the PKCE challenge the provider is given. Only the
// challenge travels to the provider, so an intercepted authorization code
// cannot be exchanged without the verifier this service kept.
func challengeFor(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}
