package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// maintenanceRetryAfter is how long a client is asked to wait. It is a fixed,
// short interval: a deployment that is down cannot know when it will be back,
// and a long one would keep clients away after it recovers.
const maintenanceRetryAfter = 120 * time.Second

// maintenanceDetail is the whole explanation. It is fixed text rather than
// anything rendered from the deployment's state, so a service that is failing
// discloses nothing about why.
const maintenanceDetail = "AbandonAuth is temporarily unavailable."

// MaintenanceHandler answers every request with 503 and a Retry-After header.
//
// It ignores the path and the method. No route is registered alongside it, so
// while this is serving there is no reachable handler, service or database
// call.
func MaintenanceHandler() http.Handler {
	retryAfter := strconv.Itoa(int(maintenanceRetryAfter.Seconds()))

	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Retry-After", retryAfter)
		writer.Header().Set("Cache-Control", "no-store")

		response.Error(writer, http.StatusServiceUnavailable, maintenanceDetail)
	})
}
