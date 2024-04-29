package role

// View a list of data about role vulnerabilities
type View Data

// Data data about a role and its vulnerabilities
type Data struct {
	Name            string
	Namespace       string
	Kind            string
	Vulnerabilities []Vulnerability
}

// Vulnerability data related to a role
type Vulnerability struct {
	ID          string
	URL         string
	Severity    string
	Title       string
	Description string
	Message     string
}
