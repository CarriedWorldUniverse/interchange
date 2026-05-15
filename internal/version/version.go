// Package version holds the build-time version string for binaries in
// this repo. Default is "dev"; release builds override via -ldflags.
package version

// Version is the build-time version string. Overridden via -ldflags at
// build time; "dev" when unset.
var Version = "dev"
