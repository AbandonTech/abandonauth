//go:build !devtools

package buildmode

// Devtools reports that this binary was built without -tags=devtools.
const Devtools = false

// Name identifies the build in logs and image labels.
const Name = "production"
