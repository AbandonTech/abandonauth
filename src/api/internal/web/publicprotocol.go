package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// publicProtocolPermits is how many public-protocol requests one worker serves
// at once. These requests need no credential, so this fixed bound is what keeps
// strangers from spending the worker's processor, database connections and
// outbound provider requests without limit.
const publicProtocolPermits = 64

// detailServiceTemporarilyUnavailable is what a website-facing request is told
// when every permit is in use.
const detailServiceTemporarilyUnavailable = "Service temporarily unavailable"

// publicProtocolAdmission holds the worker's permits. Nothing is bucketed by
// anything a caller sends, so no stranger can spend a named principal's share.
type publicProtocolAdmission struct {
	permits chan struct{}
}

func newPublicProtocolAdmission() *publicProtocolAdmission {
	return &publicProtocolAdmission{permits: make(chan struct{}, publicProtocolPermits)}
}

// withPublicProtocolAdmission serves a request only while it holds a permit,
// and answers with refuse at once when none is free, before anything of the
// request is read. The permit is returned however the handler ends, a panic
// included.
func withPublicProtocolAdmission(
	admission *publicProtocolAdmission, refuse func(http.ResponseWriter), next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case admission.permits <- struct{}{}:
		default:
			refuse(writer)

			return
		}

		defer func() { <-admission.permits }()

		next.ServeHTTP(writer, request)
	})
}

// refuseOAuthOverload answers an OAuth endpoint that has no permit to spare.
func refuseOAuthOverload(writer http.ResponseWriter) {
	response.OAuthError(writer, http.StatusServiceUnavailable, response.OAuthTemporarilyUnavailable)
}

// refuseAuthorizationOverload answers the authorization request itself, which
// a browser opened and so carries the page headers too.
func refuseAuthorizationOverload(writer http.ResponseWriter) {
	response.AuthorizationPage(writer)
	refuseOAuthOverload(writer)
}

// refusePageOverload answers the authorization page's own requests.
func refusePageOverload(writer http.ResponseWriter) {
	response.AuthorizationPage(writer)
	response.Error(writer, http.StatusServiceUnavailable, detailServiceTemporarilyUnavailable)
}

// refuseCallbackOverload answers a provider callback before its state is
// consumed, so the same callback can be retried.
func refuseCallbackOverload(writer http.ResponseWriter) {
	response.Error(writer, http.StatusServiceUnavailable, detailServiceTemporarilyUnavailable)
}
