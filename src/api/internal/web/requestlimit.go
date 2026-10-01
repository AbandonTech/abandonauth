package web

import (
	"net/http"

	"github.com/abandontech/abandonauth/src/api/internal/services/ratelimit"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// withinLimit counts a request and answers it when the budget is spent.
//
// It is called before the work a limit exists to protect: a hash comparison, a
// request to a provider, or the issuing of a credential. Counting after that
// work would let an attacker pay only in this service's time.
//
// A failure to count is a refusal, not a pass. A limit that cannot be enforced
// is not a limit.
func (s *Server) withinLimit(
	writer http.ResponseWriter, request *http.Request, group ratelimit.Group, parts ...string,
) bool {
	decision, err := s.limiter.Count(request.Context(), group, parts...)
	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return false
	}

	if !decision.Allowed {
		response.TooManyRequests(writer, decision.RetryAfter)

		return false
	}

	return true
}
