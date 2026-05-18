package utils

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

func TestDeriveVulnerabilityClassAndPackageType(t *testing.T) {
	cases := []struct {
		name            string
		in              v1alpha1.Vulnerability
		wantClass       string
		wantPackageType string
	}{
		{
			name: "trivy populated both fields - kept as-is",
			in: v1alpha1.Vulnerability{
				Class:       "os-pkgs",
				PackageType: "apk",
				PkgPURL:     "pkg:apk/alpine/openssl@1.1.1k-r0",
			},
			wantClass:       "os-pkgs",
			wantPackageType: "apk",
		},
		{
			name: "fall back to purl when class+type are blank",
			in: v1alpha1.Vulnerability{
				PkgPURL: "pkg:apk/alpine/openssl@1.1.1k-r0?distro=alpine-3.18.0",
			},
			wantClass:       "os-pkgs",
			wantPackageType: "apk",
		},
		{
			name: "fall back to purl for deb -> dpkg",
			in: v1alpha1.Vulnerability{
				PkgPURL: "pkg:deb/debian/openssl@1.1.1k-1?distro=debian-12",
			},
			wantClass:       "os-pkgs",
			wantPackageType: "dpkg",
		},
		{
			name: "fall back to purl for rpm",
			in: v1alpha1.Vulnerability{
				PkgPURL: "pkg:rpm/redhat/openssl@1.1.1k-1",
			},
			wantClass:       "os-pkgs",
			wantPackageType: "rpm",
		},
		{
			name: "fall back to purl for npm -> lang-pkgs/node-pkg",
			in: v1alpha1.Vulnerability{
				PkgPURL: "pkg:npm/lodash@4.17.21",
			},
			wantClass:       "lang-pkgs",
			wantPackageType: "node-pkg",
		},
		{
			name: "fall back to purl for pypi -> lang-pkgs/python-pkg",
			in: v1alpha1.Vulnerability{
				PkgPURL: "pkg:pypi/requests@2.31.0",
			},
			wantClass:       "lang-pkgs",
			wantPackageType: "python-pkg",
		},
		{
			name: "fall back to purl for golang -> lang-pkgs/gobinary",
			in: v1alpha1.Vulnerability{
				PkgPURL: "pkg:golang/github.com/aquasecurity/trivy@v0.69.1",
			},
			wantClass:       "lang-pkgs",
			wantPackageType: "gobinary",
		},
		{
			name: "fall back to purl for maven -> lang-pkgs/jar",
			in: v1alpha1.Vulnerability{
				PkgPURL: "pkg:maven/org.springframework/spring-core@5.3.20",
			},
			wantClass:       "lang-pkgs",
			wantPackageType: "jar",
		},
		{
			name: "trivy populated class but not type - type still derived",
			in: v1alpha1.Vulnerability{
				Class:   "lang-pkgs",
				PkgPURL: "pkg:npm/lodash@4.17.21",
			},
			wantClass:       "lang-pkgs",
			wantPackageType: "node-pkg",
		},
		{
			name: "trivy populated type but not class - class still derived",
			in: v1alpha1.Vulnerability{
				PackageType: "apk",
				PkgPURL:     "pkg:apk/alpine/openssl@1.1.1k-r0",
			},
			wantClass:       "os-pkgs",
			wantPackageType: "apk",
		},
		{
			name:            "unknown purl type leaves both blank",
			in:              v1alpha1.Vulnerability{PkgPURL: "pkg:exotic-ecosystem/foo@1.0.0"},
			wantClass:       "",
			wantPackageType: "",
		},
		{
			name:            "no purl, no class - both blank",
			in:              v1alpha1.Vulnerability{},
			wantClass:       "",
			wantPackageType: "",
		},
		{
			name: "non-purl pkg_purl string is ignored",
			in: v1alpha1.Vulnerability{
				PkgPURL: "not-a-purl",
			},
			wantClass:       "",
			wantPackageType: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotClass, gotPackageType := DeriveVulnerabilityClassAndPackageType(tc.in)
			if gotClass != tc.wantClass {
				t.Errorf("class: got %q, want %q", gotClass, tc.wantClass)
			}
			if gotPackageType != tc.wantPackageType {
				t.Errorf("package_type: got %q, want %q", gotPackageType, tc.wantPackageType)
			}
		})
	}
}
