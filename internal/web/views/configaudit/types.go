package role

// View a list of data about role vulnerabilities
type View Data

// Data data about a role and its vulnerabilities
type Data struct {
	Name            string          `json:"name"`
	Namespace       string          `json:"namespace"`
	Kind            string          `json:"kind"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability data related to a role
type Vulnerability struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Message     string `json:"message"`
}
