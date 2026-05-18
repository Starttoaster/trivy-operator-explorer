package images

// View a list of data about images and their vulnerabilities
type View []Data

// Data contains data about image vulnerabilities and metadata about the Resources running those images
type Data struct {
	Registry                string                        `json:"registry"`               // registry containing the image
	Name                    string                        `json:"name"`                   // name of the image
	Tag                     string                        `json:"tag"`                    // tag of the image
	Digest                  string                        `json:"digest"`                 // sha digest of the image
	OSFamily                string                        `json:"os_family"`              // distro name like "debian" or "alpine"
	OSVersion               string                        `json:"os_version"`             // distro version like "12.6"
	OSEndOfServiceLife      string                        `json:"os_end_of_service_life"` // end of service life data
	Resources               map[ResourceMetadata]struct{} `json:"-"`                      // data about resources using this image (serialized via custom MarshalJSON)
	CriticalVulnerabilities []Vulnerability               `json:"critical_vulnerabilities"`
	HighVulnerabilities     []Vulnerability               `json:"high_vulnerabilities"`
	MediumVulnerabilities   []Vulnerability               `json:"medium_vulnerabilities"`
	LowVulnerabilities      []Vulnerability               `json:"low_vulnerabilities"`

	// Data counters for charts in the index page
	FixAvailableCount   int `json:"fix_available_count"`
	NoFixAvailableCount int `json:"no_fix_available_count"`

	Unscanned bool `json:"unscanned"`
}

// ResourceMetadata data related to a k8s resource using a vulnerable image
type ResourceMetadata struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
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
}
