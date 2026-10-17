//go:build devtools

package web

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/abandontech/abandonauth/src/api/internal/database"
	"github.com/abandontech/abandonauth/src/api/internal/database/query"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/web/models"
	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
	"github.com/abandontech/abandonauth/src/api/internal/web/response"
)

// detailPasswordRejected is the answer to a password sign-in that was not
// accepted, whether the account exists or not.
const detailPasswordRejected = "Invalid username or password"

// createPasswordAccount makes an account that signs in with a password.
//
// It answers only in a development build, with debug mode on, on a listener no
// other machine can reach. Any of those three missing and the route reports
// that it does not exist, because in a deployment it does not.
func (s *Server) createPasswordAccount() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.passwordSignInReachable(writer) {
			return
		}

		given := inputs.New(request)
		given.DecodeObjectBody()
		username := given.BodyString("username")
		password := given.BodyString("password")

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		hashed, err := credentials.Hash(password)
		if err != nil {
			response.Error(writer, http.StatusBadRequest, detailPasswordRejected)

			return
		}

		transaction, err := s.pool.Begin(request.Context())
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		defer func() { _ = database.Rollback(request.Context(), transaction) }()

		queries := query.New(transaction)

		person, err := queries.CreateUser(request.Context(), username)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		err = queries.CreatePasswordAccount(request.Context(), query.CreatePasswordAccountParams{
			Password: hashed,
			UserID:   person.ID,
		})
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		if err := transaction.Commit(request.Context()); err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		response.JSON(writer, http.StatusOK, models.UserDto{
			ID:       person.ID.String(),
			Username: person.Username,
		})
	})
}

// signInWithPassword signs a browser in as an account created with a password.
//
// The browser is given the same session a provider sign-in would create, so
// development exercises the session and its cross-site checks rather than a
// credential a script could read.
func (s *Server) signInWithPassword() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.passwordSignInReachable(writer) {
			return
		}

		given := inputs.New(request)
		given.DecodeObjectBody()
		userID := given.BodyUUID("user_id")
		password := given.BodyString("password")

		if !given.OK() {
			response.Invalid(writer, given.Failures())

			return
		}

		if !s.passwordAccepted(writer, request, userID, password) {
			return
		}

		// Everything that can fail happens before anything is written, so a
		// refusal never arrives alongside a session cookie that was already set.
		epoch, err := s.authority.Current(request.Context())
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		token, _, err := s.signer.IssueUserAccess(userID, s.config.InternalApplicationID, epoch)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		issued, err := s.sessions.Create(request.Context(), userID)
		if err != nil {
			s.refuseUnavailable(writer, request, err)

			return
		}

		s.startSession(writer, issued)
		response.JSON(writer, http.StatusOK, models.JwtDto{Token: token})
	})
}

func (s *Server) passwordAccepted(
	writer http.ResponseWriter, request *http.Request, userID uuid.UUID, password string,
) bool {
	account, err := query.New(s.pool).GetPasswordAccountByUser(request.Context(), userID)
	if errors.Is(err, pgx.ErrNoRows) {
		response.Error(writer, http.StatusUnauthorized, detailPasswordRejected)

		return false
	}

	if err != nil {
		s.refuseUnavailable(writer, request, err)

		return false
	}

	if !credentials.Matches(password, account.Password) {
		response.Error(writer, http.StatusUnauthorized, detailPasswordRejected)

		return false
	}

	return true
}

// passwordSignInReachable reports whether these routes may answer at all, and
// otherwise answers as if they were not compiled in.
func (s *Server) passwordSignInReachable(writer http.ResponseWriter) bool {
	if s.config.PasswordSignInEnabled() {
		return true
	}

	response.NotFound(writer)

	return false
}
