//go:build devtools

package buildmode

// Devtools reports that this binary was built with -tags=devtools.
const Devtools = true

// Name identifies the build in logs and image labels.
const Name = "devtools"
