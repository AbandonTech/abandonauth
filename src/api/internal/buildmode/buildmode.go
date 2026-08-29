// Package buildmode exposes which variant of the service was compiled.
//
// Password sign-in and the API documentation UI are selected by build tag
// rather than by configuration, so that a mistake in a production environment
// file cannot turn them on. Code that must behave differently in the two
// variants reads Devtools; code that must not exist at all in the production
// binary lives in a file guarded by the devtools build tag.
package buildmode
