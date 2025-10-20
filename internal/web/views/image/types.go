package image

// View data about an image and their vulnerabilities
type View Data

// Data contains data about image vulnerabilities and metadata about the Resources running that image
type Data struct {
	Registry           string // registry server (e.g., index.docker.io)
	Repository         string // repository name
	Tag                string // image tag
	Digest             string // sha digest of the image
	OSFamily           string // distro name like "debian" or "alpine"
	OSVersion          string // distro version like "12.6"
	OSEndOfServiceLife string // end of service life data
	Vulnerabilities    []Vulnerability
}

// Vulnerability data related to a CVE
type Vulnerability struct {
	// CVE ID
	ID string
	// CVE severity level (eg. Critical/High/Medium/Low)
	Severity string
	// CVE score from 0-10 with with one decimal place
	Score float64
	// URL is the URL to the proper CVE database
	URL string
	// CVE vulnerable resource (eg. curl, libcurl)
	Resource string
	// CVE title (eg. libcarlsjr: remote code execution)
	Title string
	// The vulnerable installed resource version
	VulnerableVersion string
	// The version this vulnerability is fixed in
	FixedVersion string
	// Whether this CVE is ignored
	IsIgnored bool
	// Reason why this CVE is ignored (if applicable)
	IgnoreReason string
}
