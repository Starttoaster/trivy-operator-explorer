package clusteraudit

// View a list of data about a cluster controller report
type View Data

// Data data about a cluster controller and its checks
type Data struct {
	Name   string  `json:"name"`
	Kind   string  `json:"kind"`
	Checks []Check `json:"checks"`
}

// Check data related to a cluster controller audit
type Check struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}
