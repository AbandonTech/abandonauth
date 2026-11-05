package response

import "net/http"

// The OAuth error codes this service answers with. Each is the whole of an
// OAuth refusal: no description and nothing the request carried.
const (
	OAuthInvalidRequest          = "invalid_request"
	OAuthUnsupportedResponseType = "unsupported_response_type"
	OAuthInvalidScope            = "invalid_scope"
	OAuthAccessDenied            = "access_denied"
	OAuthServerError             = "server_error"
	OAuthTemporarilyUnavailable  = "temporarily_unavailable"
	OAuthUnsupportedGrantType    = "unsupported_grant_type"
	OAuthInvalidClient           = "invalid_client"
	OAuthInvalidGrant            = "invalid_grant"
	OAuthInvalidToken            = "invalid_token"
	OAuthInsufficientScope       = "insufficient_scope"
)

// The fixed Bearer challenges. Neither quotes a token or a claim.
const (
	InvalidTokenChallenge      = `Bearer error="invalid_token"`
	InsufficientScopeChallenge = `Bearer error="insufficient_scope", scope="openid"`
)

const (
	headerCacheControl    = "Cache-Control"
	headerPragma          = "Pragma"
	headerWWWAuthenticate = "WWW-Authenticate"
	headerReferrerPolicy  = "Referrer-Policy"
	headerFrameOptions    = "X-Frame-Options"
	headerContentSecurity = "Content-Security-Policy"
)

// OAuthFailure is the body of an OAuth refusal.
type OAuthFailure struct {
	Error string `json:"error"`
}

// NoStore forbids every cache, including those that read only Pragma, from
// keeping the answer.
func NoStore(writer http.ResponseWriter) {
	writer.Header().Set(headerCacheControl, "no-store")
	writer.Header().Set(headerPragma, "no-cache")
}

// AuthorizationPage marks an answer that belongs to a public client's
// authorization: never cached, never framed, and never the source of a
// referrer, because what it leads to can carry a code or a handle.
func AuthorizationPage(writer http.ResponseWriter) {
	writer.Header().Set(headerCacheControl, "no-store")
	writer.Header().Set(headerReferrerPolicy, "no-referrer")
	writer.Header().Set(headerFrameOptions, "DENY")
	writer.Header().Set(headerContentSecurity, "frame-ancestors 'none'")
}

// CacheableForFiveMinutes lets any cache keep a public document for five
// minutes.
func CacheableForFiveMinutes(writer http.ResponseWriter) {
	writer.Header().Set(headerCacheControl, "public, max-age=300")
}

// OAuthError writes an OAuth refusal that no cache keeps.
func OAuthError(writer http.ResponseWriter, status int, code string) {
	NoStore(writer)
	JSON(writer, status, OAuthFailure{Error: code})
}

// BearerError writes an OAuth refusal of a bearer token with its fixed
// challenge.
func BearerError(writer http.ResponseWriter, status int, code, challenge string) {
	writer.Header().Set(headerWWWAuthenticate, challenge)
	OAuthError(writer, status, code)
}

// OAuthRedirect sends a browser on with 303, so it follows with GET and never
// repeats a form body at the next address.
func OAuthRedirect(writer http.ResponseWriter, location string) {
	Redirect(writer, http.StatusSeeOther, location)
}
