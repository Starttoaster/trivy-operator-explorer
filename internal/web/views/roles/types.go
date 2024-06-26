package roles

// View a list of data about role vulnerabilities
type View []Data

// Data data about a role and its vulnerabilities
type Data struct {
	Name                    string
	Namespace               string
	Kind                    string
	CriticalVulnerabilities []Vulnerability
	HighVulnerabilities     []Vulnerability
	MediumVulnerabilities   []Vulnerability
	LowVulnerabilities      []Vulnerability
}

// Vulnerability data related to a role
type Vulnerability struct {
	ID          string
	Title       string
	Description string
}
