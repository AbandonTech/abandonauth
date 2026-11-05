package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The fixed lifetimes of the two token classes.
const (
	IDTokenLifetime     = 5 * time.Minute
	AccessTokenLifetime = 15 * time.Minute
)

// The header type each class is signed with. A validator of one class refuses
// the other's.
const (
	idTokenType     = "JWT"
	accessTokenType = "at+jwt"
)

// Issuer signs the tokens a public client receives.
type Issuer struct {
	issuer string
	keys   SigningKeys
	now    func() time.Time
}

// NewIssuer builds the signer for one issuer identifier.
func NewIssuer(issuer string, keys SigningKeys, now func() time.Time) (*Issuer, error) {
	if issuer == "" || keys.idToken.active.private == nil || keys.accessToken.active.private == nil {
		return nil, errors.New("an OpenID issuer needs an identifier and both active signing keys")
	}

	if now == nil {
		now = time.Now
	}

	return &Issuer{issuer: issuer, keys: keys, now: now}, nil
}

// Identifier is the issuer identifier every token and the discovery document
// carry.
func (i *Issuer) Identifier() string {
	return i.issuer
}

// Identity is what an ID token says about the person to one client. Subject is
// the AbandonAuth user identifier.
type Identity struct {
	Subject  uuid.UUID
	ClientID uuid.UUID
	AuthTime time.Time

	// Nonce is the authorization's nonce, and empty for a refreshed token.
	Nonce string

	// Username is released only under profile; nil omits it.
	Username *string
}

// IssueIDToken signs an ID token valid for exactly IDTokenLifetime.
func (i *Issuer) IssueIDToken(identity Identity) (string, error) {
	if identity.Subject == uuid.Nil || identity.ClientID == uuid.Nil || identity.AuthTime.IsZero() {
		return "", errors.New("an ID token needs a subject, a client and an authentication time")
	}

	issuedAt := i.now().Unix()

	return sign(i.keys.idToken.active, idTokenType, IDTokenClaims{
		Issuer:            i.issuer,
		Subject:           identity.Subject.String(),
		Audience:          identity.ClientID.String(),
		ExpiresAt:         issuedAt + int64(IDTokenLifetime/time.Second),
		IssuedAt:          issuedAt,
		AuthTime:          identity.AuthTime.Unix(),
		Nonce:             identity.Nonce,
		PreferredUsername: identity.Username,
	})
}

// Access is what an access token grants one client. Subject is the AbandonAuth
// user identifier.
type Access struct {
	Subject   uuid.UUID
	ClientID  uuid.UUID
	Scopes    Scopes
	AuthEpoch uuid.UUID
}

// IssueAccessToken signs an RFC 9068 access token valid for exactly
// AccessTokenLifetime from the moment of issue, and returns its claims.
func (i *Issuer) IssueAccessToken(access Access) (string, AccessTokenClaims, error) {
	if access.Subject == uuid.Nil || access.ClientID == uuid.Nil || access.AuthEpoch == uuid.Nil ||
		!access.Scopes.Has(ScopeOpenID) {
		return "", AccessTokenClaims{}, errors.New("an access token needs a subject, a client, openid and an epoch")
	}

	identifier, err := uuid.NewRandom()
	if err != nil {
		return "", AccessTokenClaims{}, fmt.Errorf("identifying an access token: %w", err)
	}

	issuedAt := i.now().Unix()

	claims := AccessTokenClaims{
		Issuer:    i.issuer,
		Subject:   access.Subject.String(),
		Audience:  access.ClientID.String(),
		ClientID:  access.ClientID.String(),
		Scope:     access.Scopes.String(),
		TokenID:   identifier.String(),
		AuthEpoch: access.AuthEpoch.String(),
		IssuedAt:  issuedAt,
		NotBefore: issuedAt,
		ExpiresAt: issuedAt + int64(AccessTokenLifetime/time.Second),
	}

	token, err := sign(i.keys.accessToken.active, accessTokenType, claims)
	if err != nil {
		return "", AccessTokenClaims{}, err
	}

	return token, claims, nil
}

type signedHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

func sign(key rsaKey, tokenType string, claims any) (string, error) {
	header, err := json.Marshal(signedHeader{Algorithm: keyAlgorithm, KeyID: key.id, Type: tokenType})
	if err != nil {
		return "", fmt.Errorf("encoding a token header: %w", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding token claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key.private, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing a token: %w", err)
	}

	var token strings.Builder

	token.WriteString(signingInput)
	token.WriteString(".")
	token.WriteString(base64.RawURLEncoding.EncodeToString(signature))

	return token.String(), nil
}
