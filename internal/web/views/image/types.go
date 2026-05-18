package image

// View data about an image and their vulnerabilities
type View Data

// Data contains data about image vulnerabilities and metadata about the Resources running that image
type Data struct {
	Ref                string          `json:"ref"`                    // canonical fully-qualified image ref accepted by /api/v1/image?ref=...
	Registry           string          `json:"registry"`               // registry server (e.g., index.docker.io)
	Repository         string          `json:"repository"`             // repository name
	Tag                string          `json:"tag"`                    // image tag
	Digest             string          `json:"digest"`                 // sha digest of the image
	OSFamily           string          `json:"os_family"`              // distro name like "debian" or "alpine"
	OSVersion          string          `json:"os_version"`             // distro version like "12.6"
	OSEndOfServiceLife string          `json:"os_end_of_service_life"` // end of service life data
	Vulnerabilities    []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability data related to a CVE
type Vulnerability struct {
	// CVE ID
	ID string `json:"id"`
	// CVE severity level (eg. Critical/High/Medium/Low)
	Severity string `json:"severity"`
	// CVE score from 0-10 with with one decimal place
	Score float64 `json:"score"`
	// URL is the URL to the proper CVE database
	URL string `json:"url"`
	// CVE vulnerable resource (eg. curl, libcurl)
	Resource string `json:"resource"`
	// CVE title (eg. libcarlsjr: remote code execution)
	Title string `json:"title"`
	// The vulnerable installed resource version
	VulnerableVersion string `json:"vulnerable_version"`
	// The version this vulnerability is fixed in
	FixedVersion string `json:"fixed_version"`
	// Class is the Trivy classification of the vulnerable package, typically
	// "os-pkgs" for OS-distribution packages (apk/dpkg/rpm/...) or "lang-pkgs"
	// for language/application packages (gobinary/npm/pypi/...). Empty when
	// Trivy did not populate it.
	Class string `json:"class,omitempty"`
	// PackageType is the specific package manager that produced the package,
	// e.g. "apk", "dpkg", "rpm" for OS packages, or "gobinary", "npm", "pypi"
	// for language packages.
	PackageType string `json:"package_type,omitempty"`
	// PkgPath is the on-disk location of the vulnerable package inside the
	// image, when known (typically populated for language packages).
	PkgPath string `json:"pkg_path,omitempty"`
	// PkgPURL is the package URL (purl) identifier for the vulnerable package.
	PkgPURL string `json:"pkg_purl,omitempty"`
	// Whether this CVE is ignored
	IsIgnored bool `json:"is_ignored"`
	// Reason why this CVE is ignored (if applicable)
	IgnoreReason string `json:"ignore_reason,omitempty"`
}
