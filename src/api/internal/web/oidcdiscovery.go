package web

import (
	"encoding/json"
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// openIDProviderMetadata is the discovery document for an issuer. It names the
// implemented profile and nothing more.
func openIDProviderMetadata(issuer string) ([]byte, error) {
	return json.Marshal(models.OpenIDProviderMetadataDto{
		Issuer:                                 issuer,
		AuthorizationEndpoint:                  issuer + nativeAuthorizePath,
		TokenEndpoint:                          issuer + nativeTokenPath,
		UserInfoEndpoint:                       issuer + nativeUserInfoPath,
		RevocationEndpoint:                     issuer + nativeRevocationPath,
		JWKSURI:                                issuer + idTokenJWKSPath,
		AccessTokenJWKSURI:                     issuer + accessTokenJWKSPath,
		ResponseTypesSupported:                 []string{"code"},
		ResponseModesSupported:                 []string{"query"},
		GrantTypesSupported:                    []string{grantAuthorizationCode, grantRefreshToken},
		SubjectTypesSupported:                  []string{"pairwise"},
		IDTokenSigningAlgValuesSupported:       []string{"RS256"},
		ScopesSupported:                        []string{"openid", "profile", "offline_access"},
		TokenEndpointAuthMethodsSupported:      []string{"none"},
		RevocationEndpointAuthMethodsSupported: []string{"none"},
		CodeChallengeMethodsSupported:          []string{"S256"},
		AuthorizationResponseIssSupported:      true,
	})
}

// oidcDiscovery serves the discovery document built at start-up.
func (s *Server) oidcDiscovery() http.Handler {
	return publishedDocument(s.discovery)
}

// idTokenJWKS serves the public key that verifies ID tokens, and only that.
func (s *Server) idTokenJWKS() http.Handler {
	return publishedDocument(s.config.SigningKeys.IDToken().PublicJWKSet())
}

// accessTokenJWKS serves the public key that verifies access tokens, and only
// that.
func (s *Server) accessTokenJWKS() http.Handler {
	return publishedDocument(s.config.SigningKeys.AccessToken().PublicJWKSet())
}

// publishedDocument serves fixed public bytes that any cache may keep for five
// minutes. Nothing about the request is read.
func publishedDocument(document []byte) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		response.CacheableForFiveMinutes(writer)
		writer.Header().Set("Content-Type", response.ContentTypeJSON)
		writer.WriteHeader(http.StatusOK)

		_, _ = writer.Write(document)
	})
}
