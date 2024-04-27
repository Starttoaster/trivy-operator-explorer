package views

// ImagesView contains data about images running in a kubernetes cluster with vulnerabilities
type ImagesView struct {
	Images       map[Image]ImageData
	SortedImages []ImageData
}

// Image contains data about an image
type Image struct {
	Name   string
	Digest string
}

// ImageData contains data about image vulnerabilities and metadata about the Pods running those images
type ImageData struct {
	Name                    string                   // name of the image
	Digest                  string                   // sha digest of the image
	OSFamily                string                   // distro name like "debian" or "alpine"
	OSVersion               string                   // distro version like "12.6"
	OSEndOfServiceLife      string                   // end of service life data
	Pods                    map[PodMetadata]struct{} // data about Pods using this image
	Vulnerabilities         map[string]Vulnerability // keys of CVE IDs with vulnerability data values
	CriticalVulnerabilities int
	HighVulnerabilities     int
	MediumVulnerabilities   int
	LowVulnerabilities      int
}

// PodMetadata data related to a k8s Pod
type PodMetadata struct {
	Pod       string
	Namespace string
}

// Vulnerability data related to a CVE
type Vulnerability struct {
	// CVE severity level (eg. Critical/High/Medium/Low)
	Severity string
	// CVE score from 0-10 with with one decimal place
	Score float32
	// CVE vulnerable resource (eg. curl, libcurl)
	Resource string
	// CVE title (eg. libcarlsjr: remote code execution)
	Title string
	// The vulnerable installed resource version
	VulnerableVersion string
	// The version this vulnerability is fixed in
	FixedVersion string
}

// ImageVulnerabilityView contains the view data for the `/image` server path
type ImageVulnerabilityView struct {
	// Name is the name of the image containing vulnerabilities
	Name string
	// Digest is the string image hash
	Digest             string
	OSFamily           string // distro name like "debian" or "alpine"
	OSVersion          string // distro version like "12.6"
	OSEndOfServiceLife string // end of service life data

	// Data contains a slice of all the vulnerabilities for the given image
	Data []ImageVulnerabilityData
}

// ImageVulnerabilityData contains data on the vulnerabilities in a given image
type ImageVulnerabilityData struct {
	// ID is the CVE's ID
	ID string

	Vulnerability // inherits fields from the Vulnerability struct
}
