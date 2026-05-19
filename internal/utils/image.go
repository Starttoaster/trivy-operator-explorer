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
func AssembleImageFullName(registry, repo, tag, digest string) string {
	var imageSuffix string
	if tag != "" {
		imageSuffix = fmt.Sprintf(":%s", tag)
	} else if digest != "" {
		imageSuffix = fmt.Sprintf("@%s", digest)
	}

	if registry == "" {
		return fmt.Sprintf("%s%s", repo, imageSuffix)
	}
	return fmt.Sprintf("%s/%s%s", registry, repo, imageSuffix)
}

// NormalizeArtifact sanitizes the four fields that come back from a
// trivy-operator VulnerabilityReport's artifact spec
// (registry.server, artifact.repository, artifact.tag, artifact.digest).
//
// Some trivy-operator versions occasionally produce reports whose Tag field
// contains the entire image reference (e.g. "docker.io/valkey/valkey:9.1-alpine"
// or even "docker.io/valkey/valkey:9.1-alpine@sha256:...") instead of just the
// tag ("9.1-alpine"). A valid docker tag cannot contain '/' or ':', so when we
// see either of those characters in the tag we treat the field as a malformed
// image reference, parse it, and recover the real tag (and any missing
// registry / repository / digest).
//
// When the report's own registry / repository / digest fields are already
// populated, we keep them; we only fill in missing values from what we
// recovered out of the malformed tag.
func NormalizeArtifact(registry, repository, tag, digest string) (string, string, string, string) {
	if !strings.ContainsAny(tag, "/:") {
		return registry, repository, tag, digest
	}

	parsedRegistry, parsedRepository, parsedTag, parsedDigest, err := ParseImageRef(tag)
	if err != nil {
		// We can't recover a tag value from this malformed input, so drop it
		// rather than letting the bad string flow through into rendered output.
		return registry, repository, "", digest
	}

	tag = parsedTag
	if registry == "" {
		registry = parsedRegistry
	}
	if repository == "" {
		repository = parsedRepository
	}
	if digest == "" {
		digest = parsedDigest
	}
	return registry, repository, tag, digest
}

// AssembleImageRef returns a canonical, fully-qualified, round-trippable image
// reference of the form "<registry>/<repository>[:<tag>][@<digest>]".
// Unlike AssembleImageFullName it always includes the registry (defaulting to
// index.docker.io when empty) and never strips the library/ prefix or hides
// the tag in favor of the digest. The result is intended to be passed back
// into ParseImageRef without loss of information.
func AssembleImageRef(registry, repository, tag, digest string) string {
	if registry == "" {
		registry = "index.docker.io"
	}
	ref := fmt.Sprintf("%s/%s", registry, repository)
	if tag != "" {
		ref += ":" + tag
	}
	if digest != "" {
		ref += "@" + digest
	}
	return ref
}

// ParseImageRef parses a canonical image reference of the form produced by
// AssembleImageRef: "<registry>/<repository>[:<tag>][@<digest>]". An empty
// registry component is normalized to "index.docker.io". The repository may
// contain forward slashes (e.g. "library/nginx"); the registry is the substring
// up to the first forward slash, provided that substring looks like a registry
// host (contains a "." or ":", or is "localhost"). Otherwise registry defaults
// to "index.docker.io" and the entire prefix is treated as the repository.
func ParseImageRef(ref string) (registry, repository, tag, digest string, err error) {
	if ref == "" {
		return "", "", "", "", fmt.Errorf("empty image ref")
	}

	rest := ref
	if at := strings.LastIndex(rest, "@"); at != -1 {
		digest = rest[at+1:]
		rest = rest[:at]
	}

	if colon := strings.LastIndex(rest, ":"); colon != -1 {
		// Make sure this colon belongs to a tag and not a registry port (which
		// would appear before the first forward slash).
		slashAfter := strings.Index(rest[colon:], "/")
		if slashAfter == -1 {
			tag = rest[colon+1:]
			rest = rest[:colon]
		}
	}

	registry = "index.docker.io"
	repository = rest
	if slash := strings.Index(rest, "/"); slash != -1 {
		candidate := rest[:slash]
		if strings.ContainsAny(candidate, ".:") || candidate == "localhost" {
			registry = candidate
			repository = rest[slash+1:]
		}
	}

	if repository == "" {
		return "", "", "", "", fmt.Errorf("image ref missing repository: %q", ref)
	}
	return registry, repository, tag, digest, nil
}
