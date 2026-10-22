//go:build devtools

package models

// PasswordAccountSchema creates an account that signs in with a password
// instead of a provider. It exists so that local development has accounts
// without contacting Discord, GitHub or Google.
type PasswordAccountSchema struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// PasswordLoginDto signs in as an account created with a password.
type PasswordLoginDto struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}
