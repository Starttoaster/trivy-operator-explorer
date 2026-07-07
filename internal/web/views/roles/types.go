package roles

// View a list of data about role vulnerabilities
type View []Data

// Data data about a role and its vulnerabilities
type Data struct {
	Cluster                 string          `json:"cluster"`
	Name                    string          `json:"name"`
	Namespace               string          `json:"namespace"`
	Kind                    string          `json:"kind"`
	CriticalVulnerabilities []Vulnerability `json:"critical_vulnerabilities"`
	HighVulnerabilities     []Vulnerability `json:"high_vulnerabilities"`
	MediumVulnerabilities   []Vulnerability `json:"medium_vulnerabilities"`
	LowVulnerabilities      []Vulnerability `json:"low_vulnerabilities"`
}

// Vulnerability data related to a role
type Vulnerability struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}
