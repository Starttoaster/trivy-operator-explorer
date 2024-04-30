package clusteraudits

// View a list of data about clusteraudits vulnerabilities
type View []Data

// Data data about a cluster controllers and their vulnerabilities
type Data struct {
	Name           string
	Kind           string
	CriticalChecks []Check
	HighChecks     []Check
	MediumChecks   []Check
	LowChecks      []Check
}

// Check data related to a cluster controller audit
type Check struct {
	ID          string
	Title       string
	Description string
}
