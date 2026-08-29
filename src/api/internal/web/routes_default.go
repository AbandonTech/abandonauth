//go:build !devtools

package web

// devtoolsRoutes is empty in this build: the password sign-in and documentation
// handlers are not compiled in, so no configuration can reach them.
var devtoolsRoutes []Route
