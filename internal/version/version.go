// Package version exposes the application version string.
//
// The default value is "dev" and is intended to be overridden at build time
// using ldflags, for example:
//
//	go build -ldflags "-X github.com/starttoaster/trivy-operator-explorer/internal/version.Version=v1.2.3" ./...
package version

// Version is the current build version. Override at link time via ldflags.
var Version = "dev"
