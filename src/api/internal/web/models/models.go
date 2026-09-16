// Package models is what the API sends and receives.
//
// These types are the published contract. A field name, its spelling and
// whether it is present are what applications parse, so they are written out
// here rather than derived from the database rows or the service types they
// happen to resemble today.
package models

// JwtDto carries an access token to a client.
type JwtDto struct {
	Token string `json:"token"`
}

// UserDto is what an application may learn about the person who signed in.
type UserDto struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// DeveloperApplicationDto is a developer application.
type DeveloperApplicationDto struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	OwnerID string `json:"owner_id"`
}

// DeveloperApplicationWithCallbackURIDto is a developer application together
// with the exact URIs it may be returned to.
type DeveloperApplicationWithCallbackURIDto struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	OwnerID      string   `json:"owner_id"`
	CallbackUris []string `json:"callback_uris"`
}

// CreateDeveloperApplicationDto is a developer application and its refresh
// token, which is the only time the token is readable.
type CreateDeveloperApplicationDto struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	OwnerID string `json:"owner_id"`
	Token   string `json:"token"`
}

// DeveloperApplicationName names an application being created.
type DeveloperApplicationName struct {
	Name string `json:"name"`
}

// LoginDeveloperApplicationDto is an application's own credentials.
type LoginDeveloperApplicationDto struct {
	ID           string `json:"id"`
	RefreshToken string `json:"refresh_token"`
}
