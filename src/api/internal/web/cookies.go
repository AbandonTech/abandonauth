package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
	"github.com/abandontech/abandonauth/src/api/internal/services/sessions"
)

// Cookie names. Over TLS they carry the __Host- prefix, which makes a browser
// refuse a cookie of that name that was not set for this exact host, over TLS,
// for the whole site. Local development has no TLS, where such a cookie would
// never be sent back, so the prefix is dropped there and nowhere else.
const (
	sessionCookieName     = "abandonauth_session"
	csrfCookieName        = "abandonauth_csrf"
	loginCookieName       = "abandonauth_oauth"
	nativeLoginCookieName = "abandonauth_native_oauth"

	hostCookiePrefix = "__Host-"
)

// SessionCookieName is the name of the cookie holding a signed-in browser.
func (s *Server) SessionCookieName() string {
	return s.cookieName(sessionCookieName)
}

// CSRFCookieName is the name of the cookie the site reads and echoes back.
func (s *Server) CSRFCookieName() string {
	return s.cookieName(csrfCookieName)
}

// LoginCookieName is the name of the cookie that ties a login in progress to
// the browser that started it.
func (s *Server) LoginCookieName() string {
	return s.cookieName(loginCookieName)
}

// NativeLoginCookieName is the name of the cookie that ties a public client's
// authorization to the browser that began it. It is not the confidential
// login's cookie, so authorizations and sign-ins in other tabs never overwrite
// one another.
func (s *Server) NativeLoginCookieName() string {
	return s.cookieName(nativeLoginCookieName)
}

func (s *Server) cookieName(base string) string {
	if s.config.RequireSecureCookies() {
		return hostCookiePrefix + base
	}

	return base
}

// startSession gives a browser the two cookies a signed-in session needs.
//
// The session cookie is unreadable by script, so a defect in the site cannot
// hand the session to another origin. The token cookie is deliberately
// readable: the site copies it into a header, which an origin that can only
// cause the cookie to be sent cannot do.
func (s *Server) startSession(writer http.ResponseWriter, issued sessions.Issued) {
	maxAge := int(s.sessions.Lifetime().Seconds())

	http.SetCookie(writer, s.newCookie(s.SessionCookieName(), issued.Value, maxAge, true))
	http.SetCookie(writer, s.newCookie(s.CSRFCookieName(), issued.CSRFToken, maxAge, false))
}

// endSession clears both cookies with the attributes they were set with, which
// is what a browser requires before it will remove them.
func (s *Server) endSession(writer http.ResponseWriter) {
	http.SetCookie(writer, s.newCookie(s.SessionCookieName(), "", -1, true))
	http.SetCookie(writer, s.newCookie(s.CSRFCookieName(), "", -1, false))
}

// bindLoginToBrowser sets the short-lived cookie a callback must present along
// with the state value.
//
// It is set again on every login a browser starts, which keeps a person with
// two tabs open from losing the older one, and is not cleared when a login
// finishes: on its own it is authority over nothing, and it stops being
// anything at all when it expires.
func (s *Server) bindLoginToBrowser(writer http.ResponseWriter, binding string) {
	http.SetCookie(writer, s.newCookie(
		s.LoginCookieName(), binding, int(oauth.StateLifetime.Seconds()), true,
	))
}

// bindAuthorizationToBrowser sets the cookie a public client's authorization is
// bound to. Only its browser expiry is renewed when a browser reuses it; every
// authorization keeps its own five-minute deadline in the database, and none is
// cleared when one ends, because another tab may still need it.
func (s *Server) bindAuthorizationToBrowser(writer http.ResponseWriter, binding string) {
	http.SetCookie(writer, s.newCookie(
		s.NativeLoginCookieName(), binding, int(oauth.NativeAuthorizationLifetime.Seconds()), true,
	))
}

// nativeBinding returns the authorization binding a request carried, read from
// the raw Cookie headers: the standard reader strips the quotes from a quoted
// value and keeps whichever of several copies comes first. A quoted, malformed
// or non-opaque value, or copies that differ, bind nothing.
func (s *Server) nativeBinding(request *http.Request) string {
	name := s.NativeLoginCookieName()
	found := ""

	for _, header := range request.Header.Values("Cookie") {
		for pair := range strings.SplitSeq(header, ";") {
			cookieName, value, hasValue := strings.Cut(strings.TrimSpace(pair), "=")
			if !hasValue || cookieName != name {
				continue
			}

			if !credentials.IsOpaqueValue(value) || (found != "" && found != value) {
				return ""
			}

			found = value
		}
	}

	return found
}

// newCookie builds a cookie with the attributes every cookie this service sets
// must carry: the whole site, no domain of its own, and never sent from another
// site's form or script.
//
// A negative age clears the cookie, and browsers require an explicit past
// expiry as well as the age.
func (s *Server) newCookie(name, value string, maxAge int, hidden bool) *http.Cookie {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: hidden,
		Secure:   s.config.RequireSecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}

	if maxAge > 0 {
		cookie.Expires = s.now().UTC().Add(time.Duration(maxAge) * time.Second)
	} else if maxAge < 0 {
		cookie.Expires = time.Unix(0, 0).UTC()
	}

	return cookie
}

// cookieValue returns a cookie a request carried, or the empty string.
func cookieValue(request *http.Request, name string) string {
	cookie, err := request.Cookie(name)
	if err != nil {
		return ""
	}

	return cookie.Value
}
