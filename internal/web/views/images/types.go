package images

// View a list of data about images and their vulnerabilities
type View []Data

// Data contains data about image vulnerabilities and metadata about the Resources running those images
type Data struct {
	Name                    string                        // name of the image
	Digest                  string                        // sha digest of the image
	OSFamily                string                        // distro name like "debian" or "alpine"
	OSVersion               string                        // distro version like "12.6"
	OSEndOfServiceLife      string                        // end of service life data
	Resources               map[ResourceMetadata]struct{} // data about resources using this image
	CriticalVulnerabilities []Vulnerability
	HighVulnerabilities     []Vulnerability
	MediumVulnerabilities   []Vulnerability
	LowVulnerabilities      []Vulnerability

	// Data counters for charts in the index page
	FixAvailableCount   int
	NoFixAvailableCount int
}

// ResourceMetadata data related to a k8s resource using a vulnerable image
type ResourceMetadata struct {
	Kind      string
	Name      string
	Namespace string
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
}
