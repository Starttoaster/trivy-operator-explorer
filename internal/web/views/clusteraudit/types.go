package clusteraudit

// View a list of data about a cluster controller report
type View Data

// Data data about a cluster controller and its checks
type Data struct {
	Name   string
	Kind   string
	Checks []Check
}

// Check data related to a cluster controller audit
type Check struct {
	ID          string
	URL         string
	Severity    string
	Title       string
	Description string
	Remediation string
}
