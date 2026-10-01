package servertest

import (
	"net/http"

	"github.com/google/uuid"
)

// Application is a developer application, as whoever registered it sees it.
type Application struct {
	ID      uuid.UUID
	Name    string
	OwnerID uuid.UUID

	// RefreshToken is the credential the application authenticates with, shown
	// once when it is registered.
	RefreshToken string

	CallbackURIs []string
}

// RegisterApplication registers an application for the signed-in browser and
// gives it the callbacks it may be returned to.
func (s *Service) RegisterApplication(name string, callbacks ...string) Application {
	s.t.Helper()

	var registered struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		OwnerID string `json:"owner_id"`
		Token   string `json:"token"`
	}

	s.POSTJSON("/developer_application", map[string]string{"name": name}, s.Protected).
		ExpectStatus(http.StatusOK).
		DecodeInto(&registered)

	application := Application{
		Name:         registered.Name,
		RefreshToken: registered.Token,
		CallbackURIs: callbacks,
	}

	application.ID = s.identifier(registered.ID)
	application.OwnerID = s.identifier(registered.OwnerID)

	if len(callbacks) > 0 {
		s.PATCHJSON("/developer_application/"+registered.ID+"/callback_uris", callbacks, s.Protected).
			ExpectStatus(http.StatusOK)
	}

	return application
}

func (s *Service) identifier(value string) uuid.UUID {
	s.t.Helper()

	parsed, err := uuid.Parse(value)
	if err != nil {
		s.t.Fatalf("the service answered with %q where an identifier was expected", value)
	}

	return parsed
}
