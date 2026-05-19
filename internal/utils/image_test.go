package utils

import "testing"

func TestNormalizeArtifact(t *testing.T) {
	cases := []struct {
		name           string
		inRegistry     string
		inRepository   string
		inTag          string
		inDigest       string
		wantRegistry   string
		wantRepository string
		wantTag        string
		wantDigest     string
	}{
		{
			name:           "well-formed artifact passes through unchanged",
			inRegistry:     "index.docker.io",
			inRepository:   "library/nginx",
			inTag:          "1.27-alpine",
			inDigest:       "sha256:deadbeef",
			wantRegistry:   "index.docker.io",
			wantRepository: "library/nginx",
			wantTag:        "1.27-alpine",
			wantDigest:     "sha256:deadbeef",
		},
		{
			name:           "tag accidentally holds the full image reference (the valkey bug)",
			inRegistry:     "index.docker.io",
			inRepository:   "valkey/valkey",
			inTag:          "docker.io/valkey/valkey:9.1-alpine",
			inDigest:       "sha256:355ae2c6c965769a0d9b9810711e6befd5b79fe676d1faa848247733ad6a4408",
			wantRegistry:   "index.docker.io",
			wantRepository: "valkey/valkey",
			wantTag:        "9.1-alpine",
			wantDigest:     "sha256:355ae2c6c965769a0d9b9810711e6befd5b79fe676d1faa848247733ad6a4408",
		},
		{
			name:           "tag holds full reference and a trailing digest",
			inRegistry:     "index.docker.io",
			inRepository:   "valkey/valkey",
			inTag:          "docker.io/valkey/valkey:9.1-alpine@sha256:abc123",
			inDigest:       "sha256:abc123",
			wantRegistry:   "index.docker.io",
			wantRepository: "valkey/valkey",
			wantTag:        "9.1-alpine",
			wantDigest:     "sha256:abc123",
		},
		{
			name:           "tag holds full reference and report digest is empty - recovered digest is used",
			inRegistry:     "index.docker.io",
			inRepository:   "valkey/valkey",
			inTag:          "docker.io/valkey/valkey:9.1-alpine@sha256:abc123",
			inDigest:       "",
			wantRegistry:   "index.docker.io",
			wantRepository: "valkey/valkey",
			wantTag:        "9.1-alpine",
			wantDigest:     "sha256:abc123",
		},
		{
			name:           "tag holds full reference and report registry+repo are empty - recovered values fill in",
			inRegistry:     "",
			inRepository:   "",
			inTag:          "docker.io/valkey/valkey:9.1-alpine",
			inDigest:       "sha256:abc123",
			wantRegistry:   "docker.io",
			wantRepository: "valkey/valkey",
			wantTag:        "9.1-alpine",
			wantDigest:     "sha256:abc123",
		},
		{
			name:           "tag holds repo-only string with no tag - tag is cleared rather than rendered",
			inRegistry:     "index.docker.io",
			inRepository:   "valkey/valkey",
			inTag:          "valkey/valkey",
			inDigest:       "sha256:abc123",
			wantRegistry:   "index.docker.io",
			wantRepository: "valkey/valkey",
			wantTag:        "",
			wantDigest:     "sha256:abc123",
		},
		{
			name:           "empty tag passes through (no normalization needed)",
			inRegistry:     "index.docker.io",
			inRepository:   "library/nginx",
			inTag:          "",
			inDigest:       "sha256:abc123",
			wantRegistry:   "index.docker.io",
			wantRepository: "library/nginx",
			wantTag:        "",
			wantDigest:     "sha256:abc123",
		},
		{
			name:           "custom registry with port - well-formed and untouched",
			inRegistry:     "registry.example.com:5000",
			inRepository:   "team/service",
			inTag:          "v1.2.3",
			inDigest:       "",
			wantRegistry:   "registry.example.com:5000",
			wantRepository: "team/service",
			wantTag:        "v1.2.3",
			wantDigest:     "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotRegistry, gotRepository, gotTag, gotDigest := NormalizeArtifact(
				tc.inRegistry, tc.inRepository, tc.inTag, tc.inDigest,
			)
			if gotRegistry != tc.wantRegistry {
				t.Errorf("registry: got %q, want %q", gotRegistry, tc.wantRegistry)
			}
			if gotRepository != tc.wantRepository {
				t.Errorf("repository: got %q, want %q", gotRepository, tc.wantRepository)
			}
			if gotTag != tc.wantTag {
				t.Errorf("tag: got %q, want %q", gotTag, tc.wantTag)
			}
			if gotDigest != tc.wantDigest {
				t.Errorf("digest: got %q, want %q", gotDigest, tc.wantDigest)
			}
		})
	}
}

// TestNormalizeArtifact_fixesAssembledFullName is a regression test for the
// "valkey/valkey:docker.io/valkey/valkey:9.1-alpine" display bug: feeding the
// normalized artifact fields into AssembleImageFullName must now produce a
// clean, single image reference.
func TestNormalizeArtifact_fixesAssembledFullName(t *testing.T) {
	registry, repository, tag, digest := NormalizeArtifact(
		"index.docker.io",
		"valkey/valkey",
		"docker.io/valkey/valkey:9.1-alpine",
		"sha256:355ae2c6c965769a0d9b9810711e6befd5b79fe676d1faa848247733ad6a4408",
	)

	got := AssembleImageFullName(
		FormatPrettyImageRegistry(registry),
		FormatPrettyImageRepo(repository),
		tag,
		digest,
	)
	const want = "valkey/valkey:9.1-alpine"
	if got != want {
		t.Errorf("assembled full name: got %q, want %q", got, want)
	}
}
