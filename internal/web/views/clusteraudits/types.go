package clusteraudits

// View a list of data about clusteraudits vulnerabilities
type View []Data

// Data data about a cluster controllers and their vulnerabilities
type Data struct {
	Cluster        string  `json:"cluster"`
	Name           string  `json:"name"`
	Kind           string  `json:"kind"`
	CriticalChecks []Check `json:"critical_checks"`
	HighChecks     []Check `json:"high_checks"`
	MediumChecks   []Check `json:"medium_checks"`
	LowChecks      []Check `json:"low_checks"`
}

// Check data related to a cluster controller audit
type Check struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}
