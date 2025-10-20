package utils

import (
	"fmt"
	"strings"
)

// FormatPrettyImageRegistry returns a prettified image registry string
func FormatPrettyImageRegistry(registry string) string {
	if registry == "index.docker.io" {
		// If Docker Hub, it's more common to see this without the index.docker.io registry, so we just strip it here
		return ""
	}
	return registry
}

// FormatPrettyImageRepo returns a prettified image repository string
func FormatPrettyImageRepo(repo string) string {
	return strings.TrimPrefix(repo, "library/")
}

// AssembleImageFullName is a helper to combine an optional image registry, with a repository and tag
func AssembleImageFullName(registry, repo, tag string) string {
	if registry == "" {
		return fmt.Sprintf("%s:%s", repo, tag)
	}
	return fmt.Sprintf("%s/%s:%s", registry, repo, tag)
}
