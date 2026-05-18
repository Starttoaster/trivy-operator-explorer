package utils

import (
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// DeriveVulnerabilityClassAndPackageType returns the Trivy classification
// fields ("os-pkgs"/"lang-pkgs") and the trivy package type (e.g. "apk",
// "dpkg", "rpm", "gobinary", "npm") for a vulnerability.
//
// trivy-operator copies v.Class and v.PackageType onto each VulnerabilityReport
// entry when the upstream trivy scanner emits them, but in practice many
// scanner configurations (and older operator builds) leave those fields blank
// even though they still populate v.PkgPURL ("packagePURL"). The purl's type
// prefix uniquely identifies whether the package was produced by an OS
// package manager or a language ecosystem, so we fall back to parsing it.
//
// This matters most for the MCP surface: list_images, list_cves, and
// list_images_with_cve all advertise class/package_type on their results so
// callers can filter "OS-introduced" vs "application-introduced" CVEs without
// re-deriving the heuristic client-side from pkg_purl strings. Empty inputs
// (both fields blank and no parseable purl) return ("", "") so the JSON
// `omitempty` behaviour is preserved.
func DeriveVulnerabilityClassAndPackageType(v v1alpha1.Vulnerability) (class, packageType string) {
	class = strings.TrimSpace(v.Class)
	packageType = strings.TrimSpace(v.PackageType)
	if class != "" && packageType != "" {
		return class, packageType
	}

	t := purlType(v.PkgPURL)
	if t == "" {
		return class, packageType
	}

	derivedClass, derivedPackageType := classAndTypeFromPurlType(t)
	if class == "" {
		class = derivedClass
	}
	if packageType == "" {
		packageType = derivedPackageType
	}
	return class, packageType
}

// purlType extracts the type segment of a package URL of the form
// "pkg:<type>/<namespace>/<name>@<version>[?qualifiers][#subpath]".
// The returned value is lowercased so callers can compare against a fixed
// map. Returns "" when s is not a recognizable purl.
func purlType(s string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "/@?#"); i != -1 {
		rest = rest[:i]
	}
	return strings.ToLower(strings.TrimSpace(rest))
}

// classAndTypeFromPurlType maps a PURL type to the trivy class
// ("os-pkgs"/"lang-pkgs") and the most representative trivy package_type
// string. The package_type values match those produced by trivy when
// scanning installed packages (e.g. "node-pkg" rather than "npm", which
// trivy only uses for lockfile-derived findings); this is the form most
// MCP clients encounter on real reports.
//
// Unknown purl types return ("", "") so the caller leaves the existing
// blanks alone — better than guessing wrong.
func classAndTypeFromPurlType(t string) (class, packageType string) {
	switch t {
	case "apk":
		return "os-pkgs", "apk"
	case "deb":
		return "os-pkgs", "dpkg"
	case "rpm":
		return "os-pkgs", "rpm"

	case "bitnami":
		return "lang-pkgs", "bitnami"
	case "cargo":
		return "lang-pkgs", "cargo"
	case "cocoapods":
		return "lang-pkgs", "cocoapods"
	case "composer":
		return "lang-pkgs", "composer"
	case "conan":
		return "lang-pkgs", "conan"
	case "conda":
		return "lang-pkgs", "conda-pkg"
	case "gem":
		return "lang-pkgs", "gemspec"
	case "golang":
		return "lang-pkgs", "gobinary"
	case "hex":
		return "lang-pkgs", "hex"
	case "maven", "gradle":
		return "lang-pkgs", "jar"
	case "npm":
		return "lang-pkgs", "node-pkg"
	case "nuget":
		return "lang-pkgs", "nuget"
	case "pub":
		return "lang-pkgs", "pub"
	case "pypi":
		return "lang-pkgs", "python-pkg"
	case "swift":
		return "lang-pkgs", "swift"
	}
	return "", ""
}
